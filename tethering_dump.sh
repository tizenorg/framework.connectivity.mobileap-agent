#!/bin/sh
#
# Tethering module log dump (tethering_dump.sh)
#

# Variables
TETH_DEBUG=$1/tethering
mkdir -p ${TETH_DEBUG}

# copy files
#/bin/cp -a /tmp/hostapd.log ${TETH_DEBUG}
/bin/cp -rf /tmp/dnsmasq.conf /opt/var/lib/misc/* ${TETH_DEBUG}

#vconftool get db/mobile_hotspot > ${TETH_DEBUG}/vconf_db.log
#vconftool get memory/mobile_hotspot > ${TETH_DEBUG}/vconf_memory.log
/usr/sbin/iptables -t nat -L -vv > ${TETH_DEBUG}/iptables_nat.log
/usr/sbin/iptables -L -vv > ${TETH_DEBUG}/iptables_filter.log
