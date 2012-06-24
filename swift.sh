#!/usr/bin/env bash

if [[ $EUID -ne 0 ]]; then
	echo "Please re-run the script as root: sudo ./swift.sh"
	exit 1
fi

if [ "$(lsb_release -is)" != "Ubuntu" -o "$(lsb_release -s -r)" != "12.04" ] ; then
	echo "This script is only intended to run on Ubuntu 12.04"
	exit 255
fi

USER=$(who -m | awk '{print $1;}')

echo "
====================================================
[1] Updating system and installing dependencies
===================================================="
sleep 2

apt-get update
apt-get upgrade --yes

apt-get install python-software-properties --yes
add-apt-repository ppa:swift-core/release --yes
apt-get install curl gcc git-core memcached swift python-configobj python-coverage python-dev python-nose python-setuptools python-simplejson python-xattr sqlite3 xfsprogs python-webob python-eventlet python-greenlet python-pastedeploy python-netifaces --yes

echo "
============================================
[2] Using a loopback device for storage
============================================"
sleep 2

if [ ! -f "/srv/swift-disk" ]; then
	echo "Creating partition..."
	dd if=/dev/zero of=/srv/swift-disk bs=1024 count=0 seek=1000000
	mkfs.xfs -i size=1024 /srv/swift-disk
fi

grep -q "^/srv/swift-disk*" /etc/fstab || echo "/srv/swift-disk /mnt/sdb1 xfs loop,noatime,nodiratime,nobarrier,logbufs=8 0 0" | tee -a /etc/fstab

if [ ! -d "/mnt/sdb1" ]; then
	mkdir /mnt/sdb1
	mount /mnt/sdb1
	chown $USER:$USER /mnt/sdb1/*

	for y in {1..4}
	do
		mkdir /mnt/sdb1/$y
	done

	for x in {1..4}
	do 
		ln -s /mnt/sdb1/$x /srv/$x
	done
fi

if [ ! -d "/etc/swift/*-server" ]; then
	mkdir -p /etc/swift/object-server /etc/swift/container-server /etc/swift/account-server /srv/1/node/sdb1 /srv/2/node/sdb2 /srv/3/node/sdb3 /srv/4/node/sdb4 /var/run/swift
	chown -R $USER:$USER /etc/swift /srv/[1-4]/ /var/run/swift
fi


#s=`grep -n ^"exit 0" /etc/rc.local`
#IFS=":"
#set $s
#echo $1

#sed -i "$1 i\mkdir /var/run/swift\nchown $USER:$USER /var/run/swift" /etc/rc.local

grep -q "^mkdir*" /etc/rc.local || sed -i "/^exit 0/i mkdir /var/run/swift\nchown $USER:$USER /var/run/swift" /etc/rc.local

echo "
=============================
[3] Setting up rsync
============================="
sleep 2

if [ ! -f "/etc/rsyncd.conf" ]; then
echo "
uid = $USER
gid = $USER
log file = /var/log/rsyncd.log
pid file = /var/run/rsyncd.pid
address = 127.0.0.1

[account6012]
max connections = 25
path = /srv/1/node/
read only = false
lock file = /var/lock/account6012.lock

[account6022]
max connections = 25
path = /srv/2/node/
read only = false
lock file = /var/lock/account6022.lock

[account6032]
max connections = 25
path = /srv/3/node/
read only = false
lock file = /var/lock/account6032.lock

[account6042]
max connections = 25
path = /srv/4/node/
read only = false
lock file = /var/lock/account6042.lock


[container6011]
max connections = 25
path = /srv/1/node/
read only = false
lock file = /var/lock/container6011.lock

[container6021]
max connections = 25
path = /srv/2/node/
read only = false
lock file = /var/lock/container6021.lock

[container6031]
max connections = 25
path = /srv/3/node/
read only = false
lock file = /var/lock/container6031.lock

[container6041]
max connections = 25
path = /srv/4/node/
read only = false
lock file = /var/lock/container6041.lock

[object6010]
max connections = 25
path = /srv/1/node/
read only = false
lock file = /var/lock/object6010.lock

[object6020]
max connections = 25
path = /srv/2/node/
read only = false
lock file = /var/lock/object6020.lock

[object6030]
max connections = 25
path = /srv/3/node/
read only = false
lock file = /var/lock/object6030.lock

[object6040]
max connections = 25
path = /srv/4/node/
read only = false
lock file = /var/lock/object6040.lock
" > /etc/rsyncd.conf
fi

sed -i "s/RSYNC_ENABLE=false/RSYNC_ENABLE=true/" /etc/default/rsync
service rsync restart

echo "
==================================================
[4] Setting up rsyslog for individual logging
=================================================="
sleep 2

if [ ! -f "/etc/rsyslog.d/10-swift.conf" ]; then
echo "
# Uncomment the following to have a log containing all logs together
#local1,local2,local3,local4,local5.*   /var/log/swift/all.log

# Uncomment the following to have hourly proxy logs for stats processing
#$template HourlyProxyLog,"/var/log/swift/hourly/%$YEAR%%$MONTH%%$DAY%%$HOUR%"
#local1.*;local1.!notice ?HourlyProxyLog

local1.*;local1.!notice /var/log/swift/proxy.log
local1.notice           /var/log/swift/proxy.error
local1.*                ~

local2.*;local2.!notice /var/log/swift/storage1.log
local2.notice           /var/log/swift/storage1.error
local2.*                ~

local3.*;local3.!notice /var/log/swift/storage2.log
local3.notice           /var/log/swift/storage2.error
local3.*                ~

local4.*;local4.!notice /var/log/swift/storage3.log
local4.notice           /var/log/swift/storage3.error
local4.*                ~

local5.*;local5.!notice /var/log/swift/storage4.log
local5.notice           /var/log/swift/storage4.error
local5.*                ~
" > /etc/rsyslog.d/10-swift.conf
fi

s=`grep -n ^'$PrivDropToGroup' /etc/rsyslog.conf`
IFS=":"
set $s

sed -i $1d /etc/rsyslog.conf
sed -i "$1 i\$PrivDropToGroup adm" /etc/rsyslog.conf

if [ ! -d "/var/log/swift/hourly" ]; then
	mkdir -p /var/log/swift/hourly
	chown -R syslog.adm /var/log/swift
fi

service rsyslog restart

echo "
=========================================================
[5] Getting the code and setting up test environment
========================================================="
sleep 2

if [ ! -d "$HOME/swift" ]; then
	git clone https://github.com/openstack/swift.git
	chown $USER:$USER $HOME/swift/*
	cd $HOME/swift; sudo python setup.py develop
fi

echo "
===================================
[6] Configuring each node
==================================="
sleep 2

if [ ! -f "/etc/swift/swift.conf" ]; then
	hash=`od -t x8 -N 8 -A n < /dev/random`
	echo [swift-hash] > /etc/swift/swift.conf
	echo swift_hash_path_suffix =$hash >> /etc/swift/swift.conf
fi

echo "
===================================
[7] Creating proxy-server.conf
==================================="
sleep 2

if [ ! -f "/etc/swift/proxy-server.conf" ]; then
echo "
[DEFAULT]
bind_port = 8080
user = $USER
log_facility = LOG_LOCAL1

cert_file = /etc/swift/cert.crt
key_file = /etc/swift/cert.key

[pipeline:main]
#pipeline = healthcheck cache tempauth proxy-logging proxy-server
pipeline = catch_errors healthcheck cache authtoken keystone proxy-server

[app:proxy-server]
use = egg:swift#proxy
#allow_account_management = true
account_autocreate = true

[filter:keystone]
paste.filter_factory = keystone.middleware.swift_auth:filter_factory
operator_roles = admin, swift

[filter:authtoken]
paste.filter_factory = keystone.middleware.auth_token:filter_factory
# Delaying the auth decision is required to support token-less
# usage for anonymous referrers ('.r:*').
delay_auth_decision = 1
service_protocol = http
service_host = 127.0.0.1
service_port = 5000
auth_protocol = http
auth_port = 35357
auth_host = 127.0.0.1
auth_token = ADMIN
admin_token = ADMIN

[filter:tempauth]
use = egg:swift#tempauth
user_admin_admin = admin .admin .reseller_admin
user_test_tester = testing .admin
user_test2_tester2 = testing2 .admin
user_test_tester3 = testing3

[filter:healthcheck]
use = egg:swift#healthcheck

[filter:cache]
use = egg:swift#memcache 

[filter:catch_errors]
use = egg:swift#catch_errors

[filter:proxy-logging]
use = egg:swift#proxy_logging
" > /etc/swift/proxy-server.conf
fi

echo "
===========================
[8] Creating nodes
==========================="
sleep 1

if [ ! -f "/etc/swift/account-server/1.conf" ]; then
echo "
[DEFAULT]
devices = /srv/1/node
mount_check = false
bind_port = 6012
user = $USER
log_facility = LOG_LOCAL2

[pipeline:main]
pipeline = account-server

[app:account-server]
use = egg:swift#account

[account-replicator]
vm_test_mode = yes

[account-auditor]

[account-reaper]
" > /etc/swift/account-server/1.conf
fi

if [ ! -f "/etc/swift/account-server/2.conf" ]; then
echo "
[DEFAULT]
devices = /srv/2/node
mount_check = false
bind_port = 6022
user = $USER
log_facility = LOG_LOCAL3

[pipeline:main]
pipeline = account-server

[app:account-server]
use = egg:swift#account

[account-replicator]
vm_test_mode = yes

[account-auditor]

[account-reaper]
" > /etc/swift/account-server/2.conf
fi

if [ ! -f "/etc/swift/account-server/3.conf" ]; then
echo "
[DEFAULT]
devices = /srv/3/node
mount_check = false
bind_port = 6032
user = $USER
log_facility = LOG_LOCAL4

[pipeline:main]
pipeline = account-server

[app:account-server]
use = egg:swift#account

[account-replicator]
vm_test_mode = yes

[account-auditor]

[account-reaper]
" > /etc/swift/account-server/3.conf
fi

if [ ! -f "/etc/swift/account-server/4.conf" ]; then
echo "
[DEFAULT]
devices = /srv/4/node
mount_check = false
bind_port = 6042
user = $USER
log_facility = LOG_LOCAL5

[pipeline:main]
pipeline = account-server

[app:account-server]
use = egg:swift#account

[account-replicator]
vm_test_mode = yes

[account-auditor]

[account-reaper]
" > /etc/swift/account-server/4.conf
fi

if [ ! -f "/etc/swift/container-server/1.conf" ]; then
echo "
[DEFAULT]
devices = /srv/1/node
mount_check = false
bind_port = 6011
user = $USER
log_facility = LOG_LOCAL2

[pipeline:main]
pipeline = container-server

[app:container-server]
use = egg:swift#container

[container-replicator]
vm_test_mode = yes

[container-updater]

[container-auditor]

[container-sync]
" > /etc/swift/container-server/1.conf
fi

if [ ! -f "/etc/swift/container-server/2.conf" ]; then
echo "
[DEFAULT]
devices = /srv/2/node
mount_check = false
bind_port = 6021
user = $USER
log_facility = LOG_LOCAL3

[pipeline:main]
pipeline = container-server

[app:container-server]
use = egg:swift#container

[container-replicator]
vm_test_mode = yes

[container-updater]

[container-auditor]

[container-sync]
" > /etc/swift/container-server/2.conf
fi

if [ ! -f "/etc/swift/container-server/3.conf" ]; then
echo "
[DEFAULT]
devices = /srv/3/node
mount_check = false
bind_port = 6031
user = $USER
log_facility = LOG_LOCAL4

[pipeline:main]
pipeline = container-server

[app:container-server]
use = egg:swift#container

[container-replicator]
vm_test_mode = yes

[container-updater]

[container-auditor]

[container-sync]
" > /etc/swift/container-server/3.conf
fi

if [ ! -f "/etc/swift/container-server/4.conf" ]; then
echo "
[DEFAULT]
devices = /srv/4/node
mount_check = false
bind_port = 6041
user = $USER
log_facility = LOG_LOCAL5

[pipeline:main]
pipeline = container-server

[app:container-server]
use = egg:swift#container

[container-replicator]
vm_test_mode = yes

[container-updater]

[container-auditor]

[container-sync]
" > /etc/swift/container-server/4.conf
fi

if [ ! -f "/etc/swift/object-server/1.conf" ]; then
echo "
[DEFAULT]
devices = /srv/1/node
mount_check = false
bind_port = 6010
user = $USER
log_facility = LOG_LOCAL2

[pipeline:main]
pipeline = object-server

[app:object-server]
use = egg:swift#object

[object-replicator]
vm_test_mode = yes

[object-updater]

[object-auditor]
" > /etc/swift/object-server/1.conf
fi

if [ ! -f "/etc/swift/object-server/2.conf" ]; then
echo "
[DEFAULT]
devices = /srv/2/node
mount_check = false
bind_port = 6020
user = $USER
log_facility = LOG_LOCAL3

[pipeline:main]
pipeline = object-server

[app:object-server]
use = egg:swift#object

[object-replicator]
vm_test_mode = yes

[object-updater]

[object-auditor]
" > /etc/swift/object-server/2.conf
fi

if [ ! -f "/etc/swift/object-server/3.conf" ]; then
echo "
[DEFAULT]
devices = /srv/3/node
mount_check = false
bind_port = 6030
user = $USER
log_facility = LOG_LOCAL4

[pipeline:main]
pipeline = object-server

[app:object-server]
use = egg:swift#object

[object-replicator]
vm_test_mode = yes

[object-updater]

[object-auditor]
" > /etc/swift/object-server/3.conf
fi

if [ ! -f "/etc/swift/object-server/4.conf" ]; then
echo "
[DEFAULT]
devices = /srv/4/node
mount_check = false
bind_port = 6040
user = $USER
log_facility = LOG_LOCAL5

[pipeline:main]
pipeline = object-server

[app:object-server]
use = egg:swift#object

[object-replicator]
vm_test_mode = yes

[object-updater]

[object-auditor]
" > /etc/swift/object-server/4.conf
fi

echo "
=============================
[9] Generating SSL keys
============================="
sleep 2

cd /etc/swift

if [ ! -f "cert.crt" ]; then
	openssl req -new -x509 -nodes -out cert.crt -keyout cert.key
fi

echo "
===============================
[10] Building rings
==============================="
sleep 2

if [ ! -f "account.ring.gz" ]; then

rm -f *.builder *.ring.gz backups/*.builder backups/*.ring.gz

swift-ring-builder object.builder create 18 3 1
swift-ring-builder object.builder add z1-127.0.0.1:6010/sdb1 1
swift-ring-builder object.builder add z2-127.0.0.1:6020/sdb2 1
swift-ring-builder object.builder add z3-127.0.0.1:6030/sdb3 1
swift-ring-builder object.builder add z4-127.0.0.1:6040/sdb4 1
swift-ring-builder object.builder rebalance
swift-ring-builder container.builder create 18 3 1
swift-ring-builder container.builder add z1-127.0.0.1:6011/sdb1 1
swift-ring-builder container.builder add z2-127.0.0.1:6021/sdb2 1
swift-ring-builder container.builder add z3-127.0.0.1:6031/sdb3 1
swift-ring-builder container.builder add z4-127.0.0.1:6041/sdb4 1
swift-ring-builder container.builder rebalance
swift-ring-builder account.builder create 18 3 1
swift-ring-builder account.builder add z1-127.0.0.1:6012/sdb1 1
swift-ring-builder account.builder add z2-127.0.0.1:6022/sdb2 1
swift-ring-builder account.builder add z3-127.0.0.1:6032/sdb3 1
swift-ring-builder account.builder add z4-127.0.0.1:6042/sdb4 1
swift-ring-builder account.builder rebalance
fi

echo "
=============================
[11] Installing Keystone
============================="
sleep 2

if dpkg -s "keystone" 2>/dev/null 1>/dev/null; then 
	echo "Keystone is already installed."
else
	apt-get install keystone --yes
	
	export SERVICE_ENDPOINT=http://localhost:35357/v2.0
	export SERVICE_TOKEN=ADMIN

	function get_id () {
	    echo `"$@" | grep ' id ' | awk '{print $4}'`
	}

	#VALID=false

	echo "
===================================================================
Please setup ADMIN and SWIFT user passwords below.
	
Password must have a minimum of 6 characters and contiain at least 
one digit, uppercase, lowercase and punctuation.
===================================================================

	"

	for (( ;; )); do
	        read -s -p "Please enter admin password: " PASS1
	        echo
	        read -s -p "Please re-enter admin password: " PASS2
	        echo

	        if [[ $PASS1 != $PASS2 ]]; then
	                echo "Passwords do not match. Please try again."
	        elif L=${#PASS1}; [[ L -lt 6 || L -gt 15 ]]; then
	                echo "Password must have a minimum of 6 characters and a maximum of 15."
	        elif [[ $PASS1 != *[[:digit:]]* ]]; then
	                echo "Password should contain at least two digits."
	        elif [[ $PASS1 != *[[:upper:]]* ]]; then
	                echo "Password should contain at least two uppercase letters."
	        elif [[ $PASS1 != *[[:lower:]]* ]]; then
	                echo "Password should contain at least one lowercase letters."
	        elif [[ $PASS1 != *[[:punct:]]* ]]; then
	                echo "Password should contain at least one punctuation characters."
	#       elif [[ $PASS1 == *[[:blank:]]* ]]; then
	#               echo "Password cannot contain spaces."
	        else
	                # valid password; break out of the loop
	                #VALID=true
	                break
	        fi

	        echo
	done

	DEFAULT_TENANT=$(get_id keystone tenant-create --name openstack --description "Default Tenant" --enabled true)
	#[+] DEFAULT_TENANT: $DEFAULT_TENANT"
	#sleep 1

	USER_ADMIN=$(get_id keystone user-create --tenant_id $DEFAULT_TENANT --name admin --pass $PASS1 --enabled true)
	#echo "[+] USER_ADMIN: $USER_ADMIN"
	#sleep 1

	ROLE_ADMIN=$(get_id keystone role-create --name admin)
	#echo "[+] ROLE_ADMIN: $ROLE_ADMIN"
	#sleep 1

	ROLE_MEMBER=$(get_id keystone role-create --name member)
	#echo "[+] ROLE_MEMBER: $ROLE_MEMBER"
	#sleep 1

	keystone user-role-add --user $USER_ADMIN --tenant_id $DEFAULT_TENANT --role $ROLE_ADMIN
	#echo "[=] $USER_ADMIN added to TENANT: $DEFAULT_TENANT with ROLE: $ROLE_ADMIN"
	#sleep 1

	echo "[+] Default Tenant and User ADMIN Created."
	sleep 1

	SERVICE_TENANT=$(get_id keystone tenant-create --name service --description "Service Tenant" --enabled true)
	#echo "[+] SERVICE_TENANT: $SERVICE_TENANT"
	#sleep 1

	for (( ;; )); do
        read -s -p "Please enter swift password: " PASS3
        echo
        read -s -p "Please re-enter swift password: " PASS4
        echo

        if [[ $PASS3 != $PASS4 ]]; then
                echo "Passwords do not match. Please try again."
        elif L=${#PASS3}; [[ L -lt 6 || L -gt 15 ]]; then
                echo "Password must have a minimum of 6 characters and a maximum of 15."
        elif [[ $PASS3 != *[[:digit:]]* ]]; then
                echo "Password should contain at least two digits."
        elif [[ $PASS3 != *[[:upper:]]* ]]; then
                echo "Password should contain at least two uppercase letters."
        elif [[ $PASS3 != *[[:lower:]]* ]]; then
                echo "Password should contain at least one lowercase letters."
        elif [[ $PASS3 != *[[:punct:]]* ]]; then
                echo "Password should contain at least one punctuation characters."
#       elif [[ $PASS1 == *[[:blank:]]* ]]; then
#               echo "Password cannot contain spaces."
        else
                # valid password; break out of the loop
                #VALID=true
                break
        fi

        echo
	done

	USER_SWIFT=$(get_id keystone user-create --tenant_id $SERVICE_TENANT --name swift --pass $PASS3 --enabled true)
	#echo "[+] USER_SWIFT: $USER_SWIFT"
	#sleep 1

	keystone user-role-add --user $USER_SWIFT --tenant_id $SERVICE_TENANT --role $ROLE_ADMIN
	#echo "[=] $USER_SWIFT added to TENANT: $SERVICE_TENANT with ROLE: $ROLE_ADMIN"
	#sleep 1

	echo "[+] Service Tenant and User SWIFT Created."
	sleep 1

	SERVICE_KEYSTONE=$(get_id keystone service-create --name=keystone --type=identity --description="Keystone Identity Service")
	#echo "[+] SERVICE_KEYSTONE: $SERVICE_KEYSTONE"
	#sleep 1

	keystone endpoint-create \
	 --region RegionOne \
	 --service_id=$SERVICE_KEYSTONE \
	 --publicurl=http://127.0.0.1:5000/v2.0 \
	 --internalurl=http://127.0.0.1:5000/v2.0 \
	 --adminurl=http://127.0.0.1:35357/v2.0
	#echo "[=] Endpoint for SERVICE_KEYSTONE: $SERVICE_KEYSTONE created"
	#sleep 1

	SERVICE_SWIFT=$(get_id keystone service-create --name=swift --type=object-store --description="Object Storage Service")
	#echo "[+] SERVICE_SWIFT: $SERVICE_SWIFT"
	#sleep 1

	keystone endpoint-create \
	 --region RegionOne \
	 --service_id=$SERVICE_SWIFT \
	 --publicurl 'https://127.0.0.1:8080/v1/AUTH_%(tenant_id)s' \
	 --adminurl 'https://127.0.0.1:8080/' \
	 --internalurl 'https://127.0.0.1:8080/v1/AUTH_%(tenant_id)s'
	#echo "[=] Endpoint for SERVICE_SWIFT: $SERVICE_SWIFT created"
fi

echo "
=================================
[12] Starting SWIFT serivce
================================="
sleep 1

swift-init main start

echo "
===================================
[13] Finished
==================================="
sleep 2

echo "
> Test if swift + keystone is working:

swift -V 2.0 -A http://127.0.0.1:5000/v2.0 -U openstack:admin -K $PASS1 stat
swift -V 2.0 -A http://127.0.0.1:5000/v2.0 -U service:swift -K $PASS3 stat

> Verify user settings:

curl -d '{\"auth\": {\"tenantName\": \"openstack\", \"passwordCredentials\":{\"username\": \"admin\", \"password\": \"$PASS1\"}}}' -H \"Content-type: application/json\" http://localhost:35357/v2.0/tokens | python -mjson.tool
curl -d '{\"auth\": {\"tenantName\": \"service\", \"passwordCredentials\":{\"username\": \"swift\", \"password\": \"$PASS3\"}}}' -H \"Content-type: application/json\" http://localhost:35357/v2.0/tokens | python -mjson.tool

"
