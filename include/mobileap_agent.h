/*
 * mobileap-agent
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __MOBILEAP_AGENT_H__
#define __MOBILEAP_AGENT_H__

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dlog.h>
#include <vconf.h>
#include <netinet/in.h>

#include "mobileap.h"

#define MH_MID	"mh_agent"
#define DBG(fmt, args...) LOG(LOG_DEBUG, MH_MID, "[%s()][Ln:%d] "fmt, \
					__func__, __LINE__, ##args)
#define ERR(fmt, args...) LOG(LOG_ERROR, MH_MID, "[%s()][Ln:%d] "fmt, \
						__func__, __LINE__, ##args)

#define DRIVER_DELAY		250000	/* micro seconds */

#define IF_BUF_LEN		32
#define NET_BUF_LEN		12
#define INTERFACE_NAME_LEN	12
#define SECURITY_TYPE_LEN	32

/* Network Interface */
#define IP_SUBNET_MASK		"255.255.255.0"

#define WIFI_IF			"wlan0"
#define IP_ADDRESS_WIFI		0xC0A83D02	/* 192.168.61.2 */

#define SOFTAP_IF		"wl0.1"
#define IP_ADDRESS_SOFTAP	0xC0A83D01	/* 192.168.61.1 */

#define USB_IF			"usb0"
#define IP_ADDRESS_USB		0xC0A88103	/* 192.168.129.3 */

#define BT_IF_PREFIX		"bnep"
#define BT_IF_ALL		BT_IF_PREFIX"+"
#define IP_ADDRESS_BT_1		0xC0A88201	/* 192.168.130.1 */
#define IP_ADDRESS_BT_2		0xC0A88301	/* 192.168.131.1 */
#define IP_ADDRESS_BT_3		0xC0A88401	/* 192.168.132.1 */
#define IP_ADDRESS_BT_4		0xC0A88501	/* 192.168.133.1 */
#define IP_ADDRESS_BT_5		0xC0A88601	/* 192.168.134.1 */
#define IP_ADDRESS_BT_6		0xC0A88701	/* 192.168.135.1 */
#define IP_ADDRESS_BT_7		0xC0A88801	/* 192.168.136.1 */

#define RET_FAILURE		(-1)
#define RET_SUCCESS		(0)
#define MAX_BUF_SIZE		(256u)

#define DNSMASQ_CONF_LEN	1024
#define DNSMASQ_CONF	"dhcp-range=192.168.61.3,192.168.61.150,255.255.255.0\n" \
			"dhcp-range=192.168.130.2,192.168.130.150,255.255.255.0\n" \
			"dhcp-range=192.168.131.2,192.168.131.150,255.255.255.0\n" \
			"dhcp-range=192.168.132.2,192.168.132.150,255.255.255.0\n" \
			"dhcp-range=192.168.133.2,192.168.133.150,255.255.255.0\n" \
			"dhcp-range=192.168.134.2,192.168.134.150,255.255.255.0\n" \
			"dhcp-range=192.168.135.2,192.168.135.150,255.255.255.0\n" \
			"dhcp-range=192.168.136.2,192.168.136.150,255.255.255.0\n" \
			"dhcp-range=192.168.137.2,192.168.137.150,255.255.255.0\n" \
			"dhcp-range=set:blue,192.168.129.4,192.168.129.150,255.255.255.0\n"\
			"enable-dbus\n" \
			"dhcp-option=tag:blue,option:router,192.168.129.3\n"
#define DNSMASQ_CONF_FILE	"/tmp/dnsmasq.conf"

/* Start of hostapd configuration */
#define MH_CTRL_INTF		"/tmp/mh_wpa_ctrl"
#define MH_MONITOR_INTF		"/tmp/mh_wpa_monitor"

#define HOSTAPD_BIN		"/usr/sbin/hostapd"
#define HOSTAPD_ENTROPY_FILE	"/opt/var/lib/misc/hostapd.bin"
#define HOSTAPD_CONF_FILE	"/opt/var/lib/misc/hostapd.conf"
#define HOSTAPD_CTRL_INTF_DIR	"/opt/var/lib/misc/hostapd"
#define HOSTAPD_CONF_LEN	1024
#define HOSTAPD_CONF		"interface=%s\n" \
				"driver=nl80211\n" \
				"ctrl_interface=%s\n" \
				"ssid=%s\n" \
				"channel=%d\n" \
				"ignore_broadcast_ssid=%d\n" \
				"max_num_sta=%d\n" \
				"ieee80211n=1\n" \
				"%s\n"
#define HOSTAPD_DEBUG_FILE	"/tmp/hostapd.log"
#define HOSTAPD_REQ_MAX_LEN	128
#define HOSTAPD_RETRY_MAX	5
#define HOSTAPD_RETRY_DELAY	500000	/* us */
#define HOSTAPD_STA_DISCONN	"AP-STA-DISCONNECTED "	/* from wpa_ctrl.h */
#define HOSTAPD_MONITOR_ATTACH	"ATTACH"
#define HOSTAPD_MONITOR_DETACH	"DETACH"
/* End of hostapd configuration */

#define WLAN_SCRIPT	"/usr/bin/wlan.sh"

#define IP_FORWARD	"/proc/sys/net/ipv4/ip_forward"
#define IPTABLES	"/usr/sbin/iptables"
#define GREP		"/bin/grep"
#define AWK		"/usr/bin/awk"
#define DATA_USAGE_FILE	"/tmp/tethering_data_usage.txt"
#define MASQUERADE_RULE		"-o %s -j MASQUERADE"
#define DNS_ORDER		1
#define TCP_DNS_FORWARD_RULE	"-i %s -p tcp --dport 53 -j DNAT --to %s:53"
#define UDP_DNS_FORWARD_RULE	"-i %s -p udp --dport 53 -j DNAT --to %s:53"
#define FORWARD_RULE		"-i %s -o %s"

#define MOBILE_AP_STATE_NONE	0
#define MOBILE_AP_STATE_WIFI	1
#define MOBILE_AP_STATE_USB	2
#define MOBILE_AP_STATE_BT	4
#define MOBILE_AP_STATE_ALL	7

#define DNSMASQ_DBUS_INTERFACE "uk.org.thekelleys.dnsmasq"

#define PROC_NET_DEV			"/proc/net/dev"
#define TETHERING_CONN_TIMEOUT		(1200000)	/* 20 Mins */
#define CHECK_NET_STATE_RETRY_COUNT	5
#define PSK_ITERATION_COUNT		4096

typedef struct {
	/* The parent class object state. */
	GObject parent;

	/* instance member */
	DBusGMethodInvocation *bt_context;
	DBusGMethodInvocation *usb_context;
	guint source_id;
	GSList *bt_device;

	int init_count;
	int hide_mode;
	int transfer_check_count;
	unsigned long long rx_bytes;
	unsigned long long tx_bytes;

	char ssid[MOBILE_AP_WIFI_SSID_MAX_LEN + 1];
	char key[MOBILE_AP_WIFI_KEY_MAX_LEN + 1];
	char security_type[SECURITY_TYPE_LEN];
} TetheringObject;

typedef struct {
	/* The parent class state. */
	GObjectClass parent;

	/* class member */
	guint signals[E_SIGNAL_MAX];
} TetheringObjectClass;

typedef struct {
	unsigned int number;	/* Number of connected device */
				/* BSSID list of connected device */
	char bssid[MOBILE_AP_MAX_WIFI_STA][MOBILE_AP_STR_INFO_LEN];
} softap_device_info_t;

typedef struct {
	const char *key;
	vconf_callback_fn cb;
	int *value;
} vconf_reg_t;


typedef enum {
	MOBILE_AP_DRV_INTERFACE_NONE,
	MOBILE_AP_WEXT,
	MOBILE_AP_NL80211,
} mobile_ap_drv_interface_e;

/* ssid : 32  key : 64 */
int _mh_core_enable_softap(const char *ssid, const char *security,
		const char *key, int hide_mode);
int _mh_core_disable_softap(void);
int _mh_core_get_device_info(softap_device_info_t *di);
int _mh_core_execute_dhcp_server(void);
int _mh_core_terminate_dhcp_server(void);
int _mh_core_enable_masquerade(const char *ext_if);
int _mh_core_disable_masquerade(const char *ext_if);
void _mh_core_add_data_to_array(GPtrArray *array, guint type, gchar *dev_name);
int _mh_core_set_ip_address(const char *if_name, const in_addr_t ip);


gboolean _init_tethering(TetheringObject *obj);
gboolean _deinit_tethering(TetheringObject *obj);
gboolean _mobileap_clear_state(int state);


gboolean _mobileap_is_disabled(void);
gboolean _mobileap_is_enabled(int state);
gboolean _mobileap_is_enabled_by_type(mobile_ap_type_e type);
gboolean _mobileap_set_state(int state);

#endif
