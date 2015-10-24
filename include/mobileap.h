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

#ifndef __MOBILEAP_INTERNAL_H__
#define __MOBILEAP_INTERNAL_H__

#ifdef __cplusplus
extern "C" {
#endif

#define TETHERING_SERVICE_OBJECT_PATH	"/Tethering"
#define TETHERING_SERVICE_NAME		"org.tizen.tethering"
#define TETHERING_SERVICE_INTERFACE	"org.tizen.tethering"

#define SIGNAL_NAME_NET_CLOSED		"net_closed"
#define SIGNAL_NAME_STA_CONNECT		"sta_connected"
#define SIGNAL_NAME_STA_DISCONNECT	"sta_disconnected"
#define SIGNAL_NAME_WIFI_TETHER_ON	"wifi_on"
#define SIGNAL_NAME_WIFI_TETHER_OFF	"wifi_off"
#define SIGNAL_NAME_USB_TETHER_ON	"usb_on"
#define SIGNAL_NAME_USB_TETHER_OFF	"usb_off"
#define SIGNAL_NAME_BT_TETHER_ON	"bluetooth_on"
#define SIGNAL_NAME_BT_TETHER_OFF	"bluetooth_off"
#define SIGNAL_NAME_WIFI_AP_ON		"wifi_ap_on"
#define SIGNAL_NAME_WIFI_AP_OFF		"wifi_ap_off"
#define SIGNAL_NAME_NO_DATA_TIMEOUT	"no_data_timeout"
#define SIGNAL_NAME_LOW_BATTERY_MODE	"low_batt_mode"
#define SIGNAL_NAME_FLIGHT_MODE		"flight_mode"
#define SIGNAL_NAME_POWER_SAVE_MODE		"power_save_mode"
#define SIGNAL_NAME_SECURITY_TYPE_CHANGED	"security_type_changed"
#define SIGNAL_NAME_SSID_VISIBILITY_CHANGED	"ssid_visibility_changed"
#define SIGNAL_NAME_PASSPHRASE_CHANGED		"passphrase_changed"
#define SIGNAL_NAME_DHCP_STATUS		"dhcp_status"
#define SIGNAL_MSG_NOT_AVAIL_INTERFACE	"Interface is not available"
#define SIGNAL_MSG_TIMEOUT		"There is no connection for a while"
#define SIGNAL_MSG_SSID_VISIBLE		"ssid_visible"
#define SIGNAL_MSG_SSID_HIDE		"ssid_hide"

#define DNSMASQ_LEASES_FILE		"/var/lib/misc/dnsmasq.leases"
#define IP_USB_SUBNET			"192.168.129"

typedef enum {
	E_SIGNAL_NET_CLOSED,
	E_SIGNAL_STA_CONNECT,
	E_SIGNAL_STA_DISCONNECT,
	E_SIGNAL_WIFI_TETHER_ON,
	E_SIGNAL_WIFI_TETHER_OFF,
	E_SIGNAL_USB_TETHER_ON,
	E_SIGNAL_USB_TETHER_OFF,
	E_SIGNAL_BT_TETHER_ON,
	E_SIGNAL_BT_TETHER_OFF,
	E_SIGNAL_WIFI_AP_ON,
	E_SIGNAL_WIFI_AP_OFF,
	E_SIGNAL_NO_DATA_TIMEOUT,
	E_SIGNAL_LOW_BATTERY_MODE,
	E_SIGNAL_FLIGHT_MODE,
	E_SIGNAL_POWER_SAVE_MODE,
	E_SIGNAL_SECURITY_TYPE_CHANGED,
	E_SIGNAL_SSID_VISIBILITY_CHANGED,
	E_SIGNAL_PASSPHRASE_CHANGED,
	E_SIGNAL_MAX
} mobile_ap_sig_e;

/**
* WiFi tethering configuration
*/
#define MOBILE_AP_WIFI_CHANNEL		6	/**< Channel number */
#define MOBILE_AP_WIFI_BSSID_LEN	6	/**< BSSID Length */
#define MOBILE_AP_WIFI_SSID_MAX_LEN	32	/**< Maximum length of ssid */
#define MOBILE_AP_WIFI_KEY_MIN_LEN	8	/**< Minimum length of wifi key */
#define MOBILE_AP_WIFI_PLAIN_TEXT_KEY_MAX_LEN	63	/**< Maximum length of wifi plain text key */
#define MOBILE_AP_WIFI_KEY_MAX_LEN	64	/**< Maximum length of wifi hash key */

/**
* Common configuration
*/
#define MOBILE_AP_MAX_WIFI_STA		10	/**< Firmware limitation (BCM4339) */
#define MOBILE_AP_MAX_BT_STA		4	/**< Bluetooth specification (1 Master and 4 Slaves) */
#define MOBILE_AP_MAX_USB_STA		1	/**< Only one usb connection is possible */
#define MOBILE_AP_MAX_CONNECTED_STA	15	/**< Maximum connected station. 10(Wi-Fi) + 4(BT) + 1(USB) */

#define MOBILE_AP_STR_INFO_LEN		20	/**< length of the ip or mac address*/
#define MOBILE_AP_STR_HOSTNAME_LEN	33	/**< length of the hostname */
#define MOBILE_AP_NAME_UNKNOWN		"UNKNOWN"
/**
* Mobile AP error code
*/
typedef enum {
	MOBILE_AP_ERROR_NONE,			/**< No error */
	MOBILE_AP_ERROR_RESOURCE,		/**< Socket creation error, file open error */
	MOBILE_AP_ERROR_INTERNAL,		/**< Driver related error */
	MOBILE_AP_ERROR_INVALID_PARAM,		/**< Invalid parameter */
	MOBILE_AP_ERROR_ALREADY_ENABLED,	/**< Mobile AP is already ON */
	MOBILE_AP_ERROR_NOT_ENABLED,		/**< Mobile AP is not ON, so cannot be disabled */
	MOBILE_AP_ERROR_NET_OPEN,		/**< PDP network open error */
	MOBILE_AP_ERROR_NET_CLOSE,		/**< PDP network close error */
	MOBILE_AP_ERROR_DHCP,			/**< DHCP error */
	MOBILE_AP_ERROR_IN_PROGRESS,		/**< Request is in progress */
	MOBILE_AP_ERROR_NOT_PERMITTED,		/**< Operation is not permitted */
	MOBILE_AP_ERROR_PERMISSION_DENIED,	/**< Permission Denied */

	MOBILE_AP_ERROR_MAX
} mobile_ap_error_code_e;

/**
* Event type on callback
*/
typedef enum {
	MOBILE_AP_ENABLE_CFM,			/* mobile_ap_enable() */
	MOBILE_AP_DISABLE_CFM,			/* mobile_ap_disable() */

	MOBILE_AP_ENABLE_WIFI_TETHERING_CFM,	/* mobile_ap_enable_wifi_tethering() */
	MOBILE_AP_DISABLE_WIFI_TETHERING_CFM,	/* mobile_ap_disable_wifi_tethering() */
	MOBILE_AP_CHANGE_WIFI_CONFIG_CFM,	/* mobile_ap_change_wifi_config() */

	MOBILE_AP_ENABLE_USB_TETHERING_CFM,	/* mobile_ap_enable_usb_tethering() */
	MOBILE_AP_DISABLE_USB_TETHERING_CFM,	/* mobile_ap_disable_usb_tethering() */

	MOBILE_AP_ENABLE_BT_TETHERING_CFM,	/* mobile_ap_enable_bt_tethering() */
	MOBILE_AP_DISABLE_BT_TETHERING_CFM,	/* mobile_ap_disable_bt_tethering() */

	MOBILE_AP_ENABLE_WIFI_AP_CFM,		/* mobile_ap_enable_wifi_ap() */
	MOBILE_AP_DISABLE_WIFI_AP_CFM,		/* mobile_ap_disable_wifi_ap() */

	MOBILE_AP_GET_STATION_INFO_CFM,		/* mobile_ap_get_station_info() */
	MOBILE_AP_GET_DATA_PACKET_USAGE_CFM,	/* mobile_ap_get_data_packet_usage() */

	MOBILE_AP_DISABLED_IND,			/* Turning off tethering service indication */

	MOBILE_AP_ENABLED_WIFI_TETHERING_IND,	/* Turning on WiFi tethering indication */
	MOBILE_AP_DISABLED_WIFI_TETHERING_IND,	/* Turning off WiFi tethering indication */

	MOBILE_AP_ENABLED_USB_TETHERING_IND,	/* Turning on USB tethering indication */
	MOBILE_AP_DISABLED_USB_TETHERING_IND,	/* Turning off USB tethering indication */

	MOBILE_AP_ENABLED_BT_TETHERING_IND,	/* Turning on BT tethering indication */
	MOBILE_AP_DISABLED_BT_TETHERING_IND,	/* Turning off BT tethering indication */

	MOBILE_AP_ENABLED_WIFI_AP_IND,		/* Turning on WiFi AP indication */
	MOBILE_AP_DISABLED_WIFI_AP_IND,		/* Turning off WiFi AP indication */

	MOBILE_AP_STATION_CONNECT_IND,		/* Station connection indication */
	MOBILE_AP_STATION_DISCONNECT_IND,	/* Station disconnection indication */
	MOBILE_AP_USB_STATION_CONNECT_IND,

	MOBILE_AP_MAX_EVENT,
} mobile_ap_event_e;

typedef enum {
	MOBILE_AP_TYPE_WIFI,
	MOBILE_AP_TYPE_USB,
	MOBILE_AP_TYPE_BT,
	MOBILE_AP_TYPE_WIFI_AP,
	MOBILE_AP_TYPE_MAX,
} mobile_ap_type_e;

typedef struct {
	unsigned long long pdp_tx_bytes;        /**< packet data transmitted */
	unsigned long long pdp_rx_bytes;        /**< packet data received */
} mobile_ap_data_packet_usage_t;

typedef struct {
	mobile_ap_type_e interface;                     /**< interface type */
	char ip[MOBILE_AP_STR_INFO_LEN];                /**< assigned IP address */
	char mac[MOBILE_AP_STR_INFO_LEN];               /**< MAC Address */
	char *hostname;
	time_t tm;	/**< connection time*/
} mobile_ap_station_info_t;

typedef struct {
	mobile_ap_type_e interface;                     /**< interface type */
	char interface_name[MOBILE_AP_STR_INFO_LEN];            /**< interface alphanumeric name */
	char ip_address[MOBILE_AP_STR_INFO_LEN];                /**< assigned ip addresss to interface */
	char gateway_address[MOBILE_AP_STR_INFO_LEN];   /**< gateway address of interface */
	char subnet_mask[MOBILE_AP_STR_INFO_LEN];       /**< subnet mask of interface */
} mobile_ap_interface_info_t;

typedef struct {
	unsigned short number;                  /**< Number of connected device */
	mobile_ap_station_info_t sta_info[MOBILE_AP_MAX_CONNECTED_STA];
} mobile_ap_device_info_t;

#ifdef __cplusplus
}
#endif

#endif	/* __MOBILEAP_INTERNAL_H__ */
