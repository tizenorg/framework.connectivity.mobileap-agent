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

#include <fcntl.h>
#include <unistd.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <dd-display.h>
#include <vconf.h>
#include <net_connection.h>
#include <appcore-common.h>
#include <wifi.h>
#include <alarm.h>

#include "mobileap_softap.h"
#include "mobileap_handler.h"
#include "mobileap_common.h"
#include "mobileap_bluetooth.h"
#include "mobileap_wifi.h"
#include "mobileap_usb.h"
#include "mobileap_network.h"
#include "mobileap_notification.h"
#include "mobileap_iptables.h"

GMainLoop *mainloop = NULL;
int mobileap_state = MOBILE_AP_STATE_NONE;

GDBusObjectManagerServer *manager_server = NULL;
guint owner_id = 0;
GDBusConnection *teth_gdbus_conn = NULL;
Tethering *tethering_obj = NULL;
static int init_count = 0;
guint conn_sig_id = 0;
guint deleted_sig_id = 0;
gboolean tethering_disable(Tethering *obj, GDBusMethodInvocation *context);
gboolean tethering_get_station_info(Tethering *obj,
		GDBusMethodInvocation *context);
gboolean tethering_get_data_packet_usage(Tethering *obj,
		GDBusMethodInvocation *context);

Tethering *_get_tethering_obj(void)
{
	return tethering_obj;
}

gboolean _mobileap_set_state(int state)
{
	int vconf_ret = 0;

	mobileap_state |= state;

	vconf_ret = vconf_set_int(VCONFKEY_MOBILE_HOTSPOT_MODE, mobileap_state);
	if (vconf_ret != 0) {
		ERR("vconf_set_int is failed : %d\n", vconf_ret);
		return FALSE;
	}

	return TRUE;
}

gboolean _mobileap_is_disabled(void)
{
	return mobileap_state ? FALSE : TRUE;
}

gboolean _mobileap_is_enabled(int state)
{
	return (mobileap_state & state) ? TRUE : FALSE;
}

gboolean _mobileap_is_enabled_by_type(mobile_ap_type_e type)
{
	switch (type) {
	case MOBILE_AP_TYPE_WIFI:
		if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI))
			return TRUE;
		break;

	case MOBILE_AP_TYPE_BT:
		if (_mobileap_is_enabled(MOBILE_AP_STATE_BT))
			return TRUE;
		break;

	case MOBILE_AP_TYPE_USB:
		if (_mobileap_is_enabled(MOBILE_AP_STATE_USB))
			return TRUE;
		break;

	case MOBILE_AP_TYPE_WIFI_AP:
		if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI_AP))
			return TRUE;
		break;

	default:
		ERR("Unknow type : %d\n", type);
		break;
	}

	return FALSE;
}

gboolean _mobileap_clear_state(int state)
{
	int vconf_ret = 0;

	mobileap_state &= (~state);

	vconf_ret = vconf_set_int(VCONFKEY_MOBILE_HOTSPOT_MODE, mobileap_state);
	if (vconf_ret != 0) {
		ERR("vconf_set_int is failed : %d\n", vconf_ret);
		return FALSE;
	}

	return TRUE;
}

gboolean _terminate_mobileap_agent(gpointer user_data)
{
	if (mainloop == NULL) {
		return FALSE;
	}

	if (!_mobileap_is_disabled()) {
		DBG("Tethering is enabled\n");
		return FALSE;
	}

	if (_is_trying_network_operation()) {
		DBG("Network operation is going on\n");
		return FALSE;
	}

	if (_is_trying_wifi_operation()) {
		DBG("Wi-Fi operation is going on\n");
		return FALSE;
	}

	if (_is_trying_bt_operation()) {
		DBG("BT operation is going on\n");
		return FALSE;
	}

	if (_is_trying_usb_operation()) {
		DBG("USB operation is going on\n");
		return FALSE;
	}

	DBG("All tethering / AP's are turned off\n");
	g_main_loop_quit(mainloop);
	mainloop = NULL;

	return FALSE;
}

void _block_device_sleep(void)
{
	int ret = 0;

	ret = display_lock_state(LCD_OFF, STAY_CUR_STATE, 0);
	if (ret < 0)
		ERR("PM control [ERROR] result = %d\n", ret);
	else
		DBG("PM control [SUCCESS]\n");
}

void _unblock_device_sleep(void)
{
	int ret = 0;

	ret = display_unlock_state(LCD_OFF, PM_SLEEP_MARGIN);
	if (ret < 0)
		ERR("PM control [ERROR] result = %d\n", ret);
	else
		DBG("PM control [SUCCESS]\n");
}

int _init_tethering(void)
{
	int ret = MOBILE_AP_ERROR_NONE;

	DBG("init_count: %d\n", init_count);

	if (init_count > 0) {
		init_count++;
		return MOBILE_AP_ERROR_NONE;
	}

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_WIFI_AP)) {
		ret = _open_network();
	}
	_mh_core_execute_dhcp_server();

	init_count++;

	return ret;
}

gboolean _deinit_tethering(void)
{
	DBG("obj->init_count: %d\n", init_count);

	guint idle_id;

	if (init_count > 1) {
		init_count--;
		return TRUE;
	} else if (init_count <= 0) {
		ERR("Already deinitialized\n");
		init_count = 0;
		return TRUE;
	}

	init_count = 0;

	_mh_core_terminate_dhcp_server();

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_WIFI_AP)) {
		_close_network();
	}

	idle_id = g_idle_add(_terminate_mobileap_agent, NULL);
	if (idle_id == 0) {
		ERR("g_idle_add is failed\n");
	}

	return TRUE;
}

gboolean tethering_disable(Tethering *obj, GDBusMethodInvocation *context)
{
	int ret = MOBILE_AP_ERROR_NONE;

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	if (_mobileap_is_disabled()) {
		ERR("Mobile hotspot has not been enabled\n");
		ret = MOBILE_AP_ERROR_NOT_ENABLED;
		tethering_complete_disable(obj, context, MOBILE_AP_DISABLE_CFM, ret);
		return FALSE;
	}

	_disable_wifi_tethering(obj);
	_disable_bt_tethering(obj);
	_disable_usb_tethering(obj);

	tethering_complete_disable(obj, context, MOBILE_AP_DISABLE_CFM, ret);

	return TRUE;
}

gboolean tethering_get_station_info(Tethering *obj,
			GDBusMethodInvocation *context)
{
	DBG("+\n");

	GVariant *var = NULL;

	g_assert(obj != NULL);
	g_assert(context != NULL);

	var = _station_info_foreach();

	g_dbus_method_invocation_return_value(context, var);
	g_variant_unref(var);

	DBG("-\n");
	return TRUE;
}

gboolean tethering_get_data_packet_usage(Tethering *obj,
				GDBusMethodInvocation *context)
{
	char *if_name = NULL;
	unsigned long long wifi_tx_bytes = 0;
	unsigned long long wifi_rx_bytes = 0;
	unsigned long long bt_tx_bytes = 0;
	unsigned long long bt_rx_bytes = 0;
	unsigned long long usb_tx_bytes = 0;
	unsigned long long usb_rx_bytes = 0;
	unsigned long long tx_bytes = 0;
	unsigned long long rx_bytes = 0;

	if (_get_network_interface_name(&if_name) == FALSE) {
		tethering_complete_get_data_packet_usage(obj, context,
				MOBILE_AP_GET_DATA_PACKET_USAGE_CFM,
				0ULL, 0ULL);
		return FALSE;
	}

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI))
		_get_data_usage(WIFI_IF, if_name,
				&wifi_tx_bytes, &wifi_rx_bytes);

	if (_mobileap_is_enabled(MOBILE_AP_STATE_BT))
		_get_data_usage(BT_IF_ALL, if_name,
				&bt_tx_bytes, &bt_rx_bytes);

	if (_mobileap_is_enabled(MOBILE_AP_STATE_USB))
		_get_data_usage(USB_IF, if_name,
				&usb_tx_bytes, &usb_rx_bytes);
	free(if_name);

	tx_bytes = wifi_tx_bytes + bt_tx_bytes + usb_tx_bytes;
	rx_bytes = wifi_rx_bytes + bt_rx_bytes + usb_rx_bytes;

	tethering_complete_get_data_packet_usage(obj, context, MOBILE_AP_GET_DATA_PACKET_USAGE_CFM,
			tx_bytes, rx_bytes);

	return TRUE;
}

void static __handle_dnsmasq_dhcp_status_changed_cb(GDBusConnection *connection,
			const gchar *sender_name, const gchar *object_path,
			const gchar *interface_name, const gchar *signal_name,
			GVariant *parameters, gpointer user_data)
{
	DBG("+\n");
	char *ip_addr = NULL;
	char *mac = NULL;
	char *name = NULL;
	char *bt_remote_device_name = NULL;
	mobile_ap_type_e type = MOBILE_AP_TYPE_MAX;
	mobile_ap_station_info_t *info = NULL;
	int n_station = 0;
	time_t tm;

	if (signal_name == NULL) {
		ERR("singal name is NULL\n");
		return;
	}
	g_variant_get(parameters, "(sss)",  &ip_addr, &mac, &name);
	if (!g_strcmp0(signal_name, "DhcpConnected")) {
		SDBG("DhcpConnected signal : %s  %s %s\n", ip_addr, mac, name);
		/*
		 * DHCP ACK received, destroy timeout if exists
		 */
		if (ip_addr == NULL || mac == NULL) {
			goto EXIT;
		}
		_destroy_dhcp_ack_timer(mac);

		if (_get_tethering_type_from_ip(ip_addr, &type) != MOBILE_AP_ERROR_NONE)
			goto EXIT;

		if (_mobileap_is_enabled_by_type(type) == FALSE) {
			goto EXIT;
		}

		info = (mobile_ap_station_info_t *)g_malloc(sizeof(mobile_ap_station_info_t));
		if (info == NULL) {
			ERR("malloc failed\n");
			goto EXIT;
		}

		info->interface = type;
		g_strlcpy(info->ip, ip_addr, sizeof(info->ip));
		g_strlcpy(info->mac, mac, sizeof(info->mac));
		if (type == MOBILE_AP_TYPE_WIFI || type == MOBILE_AP_TYPE_USB ||
				type == MOBILE_AP_TYPE_WIFI_AP) {
			if (name[0] == '\0')
				info->hostname = g_strdup(MOBILE_AP_NAME_UNKNOWN);
			else
				info->hostname = g_strdup(name);
		} else if (type == MOBILE_AP_TYPE_BT) {
			_bt_get_remote_device_name(mac, &bt_remote_device_name);
			if (bt_remote_device_name == NULL)
				info->hostname = g_strdup(MOBILE_AP_NAME_UNKNOWN);
			else
				info->hostname = bt_remote_device_name;
		}
		time(&tm);
		info->tm = tm;
		if (_add_station_info(info) != MOBILE_AP_ERROR_NONE) {
			ERR("_add_station_info is failed\n");
			g_free(info->hostname);
			g_free(info);
			goto EXIT;
		}

		_get_station_count((gconstpointer)type,
				_slist_find_station_by_interface, &n_station);
		if (n_station == 1)
			_stop_timeout_cb(type);

		_send_dbus_station_info("DhcpConnected", info);
	} else if (!g_strcmp0(signal_name, "DhcpLeaseDeleted")) {
		SDBG("DhcpLeaseDeleted signal : %s %s %s\n", ip_addr, mac, name);
		_remove_station_info(ip_addr, _slist_find_station_by_ip_addr);
	} else {
		SDBG("UNKNOWN member signal\n");
	}
EXIT :
	g_free(ip_addr);
	g_free(mac);
	g_free(name);
	DBG("-\n");
}

static void on_bus_acquired_cb (GDBusConnection *connection, const gchar *name,
				gpointer user_data)
{
	DBG("+\n");
	GDBusInterfaceSkeleton *intf = NULL;
	teth_gdbus_conn = connection;

	manager_server = g_dbus_object_manager_server_new(TETHERING_SERVICE_OBJECT_PATH);
	if(manager_server == NULL) {
		DBG("Manager server not created.");
		return;
	}
	tethering_obj = tethering_skeleton_new();
	intf = G_DBUS_INTERFACE_SKELETON(tethering_obj);
	if (!g_dbus_interface_skeleton_export(intf, connection,
			TETHERING_SERVICE_OBJECT_PATH, NULL)) {
		ERR("Export with path failed");
	} else {
		DBG("Export sucessss");
	}

	g_signal_connect(tethering_obj, "handle-enable-wifi-tethering",
			G_CALLBACK(tethering_enable_wifi_tethering), NULL);
	g_signal_connect(tethering_obj, "handle-enable-bt-tethering",
			G_CALLBACK(tethering_enable_bt_tethering), NULL);
	g_signal_connect(tethering_obj, "handle-enable-usb-tethering",
			G_CALLBACK(tethering_enable_usb_tethering), NULL);
	g_signal_connect(tethering_obj, "handle-disable-wifi-tethering",
			G_CALLBACK(tethering_disable_wifi_tethering), NULL);
	g_signal_connect(tethering_obj, "handle-disable-bt-tethering",
			G_CALLBACK(tethering_disable_bt_tethering), NULL);
	g_signal_connect(tethering_obj, "handle-disable-usb-tethering",
			G_CALLBACK(tethering_disable_usb_tethering), NULL);
	g_signal_connect(tethering_obj, "handle-enable-wifi-ap",
			G_CALLBACK(tethering_enable_wifi_ap), NULL);

	g_signal_connect(tethering_obj, "handle-disable-wifi-ap",
			G_CALLBACK(tethering_disable_wifi_ap), NULL);
	g_signal_connect(tethering_obj, "handle-reload-wifi-settings",
			G_CALLBACK(tethering_reload_wifi_settings), NULL);
	g_signal_connect(tethering_obj, "handle-reload-wifi-ap-settings",
			G_CALLBACK(tethering_reload_wifi_ap_settings), NULL);
	g_signal_connect(tethering_obj, "handle-get-station-info",
			G_CALLBACK(tethering_get_station_info), NULL);
	g_signal_connect(tethering_obj, "handle-get-data-packet-usage",
			G_CALLBACK(tethering_get_data_packet_usage), NULL);
#ifdef __PRIVATE_CODE__
	g_signal_connect(tethering_obj, "handle-cont-enable-wifi-tethering",
			G_CALLBACK(tethering_cont_enable_wifi_tethering), NULL);
	g_signal_connect(tethering_obj, "handle-cont-enable-bt-tethering",
			G_CALLBACK(tethering_cont_enable_bt_tethering), NULL);
	g_signal_connect(tethering_obj, "handle-cont-enable-usb-tethering",
			G_CALLBACK(tethering_cont_enable_usb_tethering), NULL);

	g_signal_connect(tethering_obj, "handle-cancel-wifi-tethering",
			G_CALLBACK(tethering_cancel_enable_wifi_tethering), NULL);
	g_signal_connect(tethering_obj, "handle-cancel-bt-tethering",
			G_CALLBACK(tethering_cancel_enable_bt_tethering), NULL);
	g_signal_connect(tethering_obj, "handle-cancel-usb-tethering",
			G_CALLBACK(tethering_cancel_enable_usb_tethering), NULL);
#endif

#ifdef __PRIVATE_CODE__
#if defined TIZEN_MDM_ENABLE
	_register_mdm_policy_cb((void *)tethering_obj);
#endif /* TIZEN_MDM_ENABLE */
#endif /* __PRIVATE_CODE__ */

	_init_network((void *)tethering_obj);
	_register_vconf_cb((void *)tethering_obj);

	conn_sig_id = g_dbus_connection_signal_subscribe(connection, NULL, DNSMASQ_DBUS_INTERFACE,
			"DhcpConnected", NULL, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
			__handle_dnsmasq_dhcp_status_changed_cb, NULL, NULL);
	deleted_sig_id = g_dbus_connection_signal_subscribe(connection, NULL, DNSMASQ_DBUS_INTERFACE,
			"DhcpLeaseDeleted", NULL, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
			__handle_dnsmasq_dhcp_status_changed_cb, NULL, NULL);

	g_dbus_object_manager_server_set_connection(manager_server, connection);
	DBG("-\n");
}

static void on_name_acquired_cb(GDBusConnection *connection, const gchar *name,
		gpointer user_data)
{
	DBG("+\n");

	DBG("-\n");
}

static void on_name_lost_db(GDBusConnection *conn, const gchar *name,
		gpointer user_data)
{
	DBG("+\n");
	/* May service name is already in use */
	ERR("Service name is already in use");

	/* The result of DBus name request is only permitted,
	 *  such as DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER.
	 */
	exit(2);

	DBG("-\n");
}

static int __tethering_setup_gdbus(void)
{
	DBG("+\n");

	owner_id = g_bus_own_name(DBUS_BUS_SYSTEM, TETHERING_SERVICE_NAME,
				G_BUS_NAME_OWNER_FLAGS_NONE, on_bus_acquired_cb,
				on_name_acquired_cb, on_name_lost_db, NULL, NULL);

	if (!owner_id) {
		ERR("g_bus_own_name is failed\n");
		return -1;
	}
	return 0;
}
int main(int argc, char **argv)
{
	int ret = 0;

	DBG("+\n");

#if !GLIB_CHECK_VERSION(2,36,0)
	g_type_init();
#endif

	mainloop = g_main_loop_new(NULL, FALSE);
	if (mainloop == NULL) {
		ERR("Couldn't create GMainLoop\n");
		return 0;
	}

	ret = __tethering_setup_gdbus();
	if (ret < 0) {
		ERR("tethering_setup_gdbus is failed\n");
		return 0;
	}
	/* Platform modules */
	if (appcore_set_i18n(MOBILEAP_LOCALE_COMMON_PKG, MOBILEAP_LOCALE_COMMON_RES) < 0) {
		ERR("appcore_set_i18n is failed\n");
	}

	if (vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_MODE, &mobileap_state) < 0) {
		ERR("vconf_get_int is failed\n");
		mobileap_state = MOBILE_AP_STATE_NONE;
	}

	_register_wifi_station_handler();

	ret = wifi_initialize();
	if (ret != WIFI_ERROR_NONE) {
		ERR("wifi_initialize() is failed : %d\n", ret);
	}

	ret = alarmmgr_init(APPNAME);
	if (ret != ALARMMGR_RESULT_SUCCESS) {
		ERR("alarmmgr_init(%s) is failed : %d\n", APPNAME, ret);
	} else {
		ret = alarmmgr_set_cb(_sp_timeout_handler, NULL);
		if (ret != ALARMMGR_RESULT_SUCCESS) {
			ERR("alarmmgr_set_cb is failed : %d\n", ret);
		}
	}

	g_main_loop_run(mainloop);

	alarmmgr_fini();

	ret = wifi_deinitialize();
	if (ret != WIFI_ERROR_NONE) {
		ERR("wifi_deinitialize() is failed : %d\n", ret);
	}

	_unregister_vconf_cb();
	_unregister_wifi_station_handler();
	_deinit_network();

	g_dbus_connection_signal_unsubscribe(teth_gdbus_conn, conn_sig_id);
	g_dbus_connection_signal_unsubscribe(teth_gdbus_conn, deleted_sig_id);

	g_object_unref(tethering_obj);
	g_bus_unown_name(owner_id);
	g_object_unref(manager_server);
	DBG("-\n");
	return 0;
}
