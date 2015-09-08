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
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
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

GType tethering_object_get_type(void);
#define TETHERING_TYPE_OBJECT (tethering_object_get_type())
G_DEFINE_TYPE(TetheringObject, tethering_object, G_TYPE_OBJECT)

GMainLoop *mainloop = NULL;
int mobileap_state = MOBILE_AP_STATE_NONE;
DBusConnection *tethering_conn = NULL;

gboolean tethering_disable(TetheringObject *obj, DBusGMethodInvocation *context);
gboolean tethering_get_station_info(TetheringObject *obj,
		DBusGMethodInvocation *context);
gboolean tethering_get_data_packet_usage(TetheringObject *obj,
		DBusGMethodInvocation *context);

#include "tethering-server-stub.h"

static void tethering_object_init(TetheringObject *obj)
{
	DBG("+\n");
	g_assert(obj != NULL);

	obj->init_count = 0;
	memset(&obj->softap_settings, 0x00, sizeof(obj->softap_settings));
}

static void tethering_object_finalize(GObject *obj)
{
	DBG("+\n");

	G_OBJECT_CLASS(tethering_object_parent_class)->finalize(obj);
}

static void tethering_object_class_init(TetheringObjectClass *klass)
{
	GObjectClass *object_class = (GObjectClass *)klass;
	const gchar *signalNames[E_SIGNAL_MAX] = {
		SIGNAL_NAME_NET_CLOSED,
		SIGNAL_NAME_STA_CONNECT,
		SIGNAL_NAME_STA_DISCONNECT,
		SIGNAL_NAME_WIFI_TETHER_ON,
		SIGNAL_NAME_WIFI_TETHER_OFF,
		SIGNAL_NAME_USB_TETHER_ON,
		SIGNAL_NAME_USB_TETHER_OFF,
		SIGNAL_NAME_BT_TETHER_ON,
		SIGNAL_NAME_BT_TETHER_OFF,
		SIGNAL_NAME_WIFI_AP_ON,
		SIGNAL_NAME_WIFI_AP_OFF,
		SIGNAL_NAME_NO_DATA_TIMEOUT,
		SIGNAL_NAME_LOW_BATTERY_MODE,
		SIGNAL_NAME_FLIGHT_MODE,
		SIGNAL_NAME_POWER_SAVE_MODE,
		SIGNAL_NAME_SECURITY_TYPE_CHANGED,
		SIGNAL_NAME_SSID_VISIBILITY_CHANGED,
		SIGNAL_NAME_PASSPHRASE_CHANGED
	};

	int i = 0;

	g_assert(klass != NULL);

	object_class->finalize = tethering_object_finalize;

	DBG("Creating signals\n");

	for (i = 0; i < E_SIGNAL_MAX; i++) {
		guint signalId;

		signalId = g_signal_new(signalNames[i],
					G_OBJECT_CLASS_TYPE(klass),
					G_SIGNAL_RUN_LAST,
					0, NULL, NULL,
					g_cclosure_marshal_VOID__STRING,
					G_TYPE_NONE, 1, G_TYPE_STRING);
		klass->signals[i] = signalId;
	}

	DBG("Binding to GLib/D-Bus\n");

	dbus_g_object_type_install_info(TETHERING_TYPE_OBJECT,
					&dbus_glib_tethering_object_info);
}

static void __add_station_info_to_array(gpointer data, gpointer user_data)
{
	mobile_ap_station_info_t *si = (mobile_ap_station_info_t *)data;
	GPtrArray *array = (GPtrArray *)user_data;
	GValue value = {0, {{0}}};

	g_value_init(&value, DBUS_STRUCT_STATIONS);
	g_value_take_boxed(&value,
			dbus_g_type_specialized_construct(DBUS_STRUCT_STATIONS));
	dbus_g_type_struct_set(&value, 0, si->interface, 1, si->ip,
			2, si->mac, 3, si->hostname, 4, (guint)(si->tm), G_MAXUINT);
	g_ptr_array_add(array, g_value_get_boxed(&value));
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

int _init_tethering(TetheringObject *obj)
{
	int ret = MOBILE_AP_ERROR_NONE;

	DBG("obj->init_count: %d\n", obj->init_count);

	if (obj->init_count > 0) {
		obj->init_count++;
		return MOBILE_AP_ERROR_NONE;
	}

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_WIFI_AP)) {
		ret = _open_network();
	}
	_mh_core_execute_dhcp_server();

	obj->init_count++;

	return ret;
}

gboolean _deinit_tethering(TetheringObject *obj)
{
	DBG("obj->init_count: %d\n", obj->init_count);

	guint idle_id;

	if (obj->init_count > 1) {
		obj->init_count--;
		return TRUE;
	} else if (obj->init_count <= 0) {
		ERR("Already deinitialized\n");
		obj->init_count = 0;
		return TRUE;
	}

	obj->init_count = 0;

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

gboolean tethering_disable(TetheringObject *obj, DBusGMethodInvocation *context)
{
	int ret = MOBILE_AP_ERROR_NONE;

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	if (_mobileap_is_disabled()) {
		ERR("Mobile hotspot has not been enabled\n");
		ret = MOBILE_AP_ERROR_NOT_ENABLED;
		dbus_g_method_return(context, MOBILE_AP_DISABLE_CFM, ret);
		return FALSE;
	}

	_disable_wifi_tethering(obj);
	_disable_bt_tethering(obj);
	_disable_usb_tethering(obj);

	dbus_g_method_return(context, MOBILE_AP_DISABLE_CFM, ret);

	return TRUE;
}

gboolean tethering_get_station_info(TetheringObject *obj,
						DBusGMethodInvocation *context)
{
	DBG("+\n");

	GPtrArray *array = g_ptr_array_new();

	g_assert(obj != NULL);
	g_assert(context != NULL);

	_station_info_foreach(__add_station_info_to_array, array);

	dbus_g_method_return(context, MOBILE_AP_GET_STATION_INFO_CFM, array);
	g_ptr_array_free(array, TRUE);

	DBG("-\n");

	return TRUE;
}

gboolean tethering_get_data_packet_usage(TetheringObject *obj,
						DBusGMethodInvocation *context)
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
		dbus_g_method_return(context, MOBILE_AP_GET_DATA_PACKET_USAGE_CFM,
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

	dbus_g_method_return(context, MOBILE_AP_GET_DATA_PACKET_USAGE_CFM,
			tx_bytes, rx_bytes);

	return TRUE;
}

static DBusHandlerResult __dnsmasq_signal_filter(DBusConnection *conn,
		DBusMessage *msg, void *user_data)
{
	if (!user_data) {
		ERR("Invalid param\n");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	char *ip_addr = NULL;
	char *mac = NULL;
	char *name = NULL;
	char *bt_remote_device_name = NULL;
	DBusError error;
	mobile_ap_type_e type = MOBILE_AP_TYPE_MAX;
	TetheringObject *obj = (TetheringObject *)user_data;
	mobile_ap_station_info_t *info = NULL;
	int n_station = 0;
	time_t tm;

	dbus_error_init(&error);
	if (dbus_message_is_signal(msg, DNSMASQ_DBUS_INTERFACE,
				"DhcpConnected")) {
		if (!dbus_message_get_args(msg, &error,
					DBUS_TYPE_STRING, &ip_addr,
					DBUS_TYPE_STRING, &mac,
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INVALID)) {
			ERR("Cannot read message, cause: %s\n", error.message);
			dbus_error_free(&error);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		SDBG("DhcpConnected signal : %s  %s %s\n", ip_addr, mac, name);
		/*
		 * DHCP ACK received, destroy timeout if exists
		 */
		_destroy_dhcp_ack_timer(mac);

		if (_get_tethering_type_from_ip(ip_addr, &type) != MOBILE_AP_ERROR_NONE)
			return DBUS_HANDLER_RESULT_HANDLED;

		if (_mobileap_is_enabled_by_type(type) == FALSE) {
			return DBUS_HANDLER_RESULT_HANDLED;
		}

		info = (mobile_ap_station_info_t *)malloc(sizeof(mobile_ap_station_info_t));
		if (info == NULL) {
			ERR("malloc failed\n");
			return DBUS_HANDLER_RESULT_HANDLED;
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
			_bt_get_remote_device_name(obj, mac, &bt_remote_device_name);
			if (bt_remote_device_name == NULL)
				info->hostname = g_strdup(MOBILE_AP_NAME_UNKNOWN);
			else
				info->hostname = bt_remote_device_name;
		}
		time(&tm);
		info->tm = tm;

		if (_add_station_info(info) != MOBILE_AP_ERROR_NONE) {
			g_free(info->hostname);
			free(info);
			return DBUS_HANDLER_RESULT_HANDLED;
		}

		_get_station_count((gconstpointer)type,
				_slist_find_station_by_interface, &n_station);
		if (n_station == 1)
			_stop_timeout_cb(type);

		_send_dbus_station_info("DhcpConnected", info);

		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, DNSMASQ_DBUS_INTERFACE,
				"DhcpLeaseDeleted")) {
		if (!dbus_message_get_args(msg, &error,
					DBUS_TYPE_STRING, &ip_addr,
					DBUS_TYPE_STRING, &mac,
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INVALID)) {
			ERR("Cannot read message, cause: %s\n", error.message);
			dbus_error_free(&error);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		SDBG("DhcpLeaseDeleted signal : %s %s %s\n", ip_addr, mac, name);

		_remove_station_info(ip_addr, _slist_find_station_by_ip_addr);

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

int main(int argc, char **argv)
{
	const char *rule = "type='signal',interface='"DNSMASQ_DBUS_INTERFACE"'";

	TetheringObject *tethering_obj = NULL;
	DBusGConnection *tethering_bus = NULL;
	DBusGProxy *tethering_bus_proxy = NULL;
	DBusError dbus_error;
	GError *error = NULL;
	guint result = 0;
	int ret;

	DBG("+\n");

#if !GLIB_CHECK_VERSION(2,36,0)
	g_type_init();
#endif

	mainloop = g_main_loop_new(NULL, FALSE);
	if (mainloop == NULL) {
		ERR("Couldn't create GMainLoop\n");
		return 0;
	}

	/* D-Bus init */
	tethering_bus = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (error != NULL) {
		ERR("Couldn't connect to system bus[%s]\n", error->message);
		g_error_free(error);
		goto failure;
	}

	tethering_bus_proxy = dbus_g_proxy_new_for_name(tethering_bus,
			DBUS_SERVICE_DBUS, DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS);
	if (tethering_bus_proxy == NULL) {
		ERR("Failed to get a proxy for D-Bus\n");
		goto failure;
	}
	if (!dbus_g_proxy_call(tethering_bus_proxy, "RequestName", &error,
			       G_TYPE_STRING, TETHERING_SERVICE_NAME,
			       G_TYPE_UINT, 0, G_TYPE_INVALID,
			       G_TYPE_UINT, &result, G_TYPE_INVALID)) {
		ERR("dbus_g_proxy_call is failed\n");
		if (error) {
			ERR("D-Bus.RequestName RPC failed[%s]\n",
					error->message);
			g_error_free(error);
		}
		goto failure;
	}
	if (result != 1) {
		ERR("Failed to get the primary well-known name.\n");
		goto failure;
	}
	g_object_unref(tethering_bus_proxy);
	tethering_bus_proxy = NULL;

	tethering_obj = g_object_new(TETHERING_TYPE_OBJECT, NULL);
	if (tethering_obj == NULL) {
		ERR("Failed to create one Tethering instance.\n");
		goto failure;
	}
	dbus_g_connection_register_g_object(tethering_bus,
			TETHERING_SERVICE_OBJECT_PATH, G_OBJECT(tethering_obj));

	tethering_conn = dbus_g_connection_get_connection(tethering_bus);
	dbus_error_init(&dbus_error);
	dbus_bus_add_match(tethering_conn, rule, &dbus_error);
	if (dbus_error_is_set(&dbus_error)) {
		ERR("Cannot add D-BUS match rule, cause: %s", dbus_error.message);
		dbus_error_free(&dbus_error);
		goto failure;
	}
	dbus_connection_add_filter(tethering_conn, __dnsmasq_signal_filter, tethering_obj, NULL);

	/* Platform modules */
	if (appcore_set_i18n(MOBILEAP_LOCALE_COMMON_PKG, MOBILEAP_LOCALE_COMMON_RES) < 0) {
		ERR("appcore_set_i18n is failed\n");
	}

	if (vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_MODE, &mobileap_state) < 0) {
		ERR("vconf_get_int is failed\n");
		mobileap_state = MOBILE_AP_STATE_NONE;
	}

	_init_network((void *)tethering_obj);
	_register_wifi_station_handler();
	_register_vconf_cb((void *)tethering_obj);

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

	_unregister_vconf_cb((void *)tethering_obj);
	_unregister_wifi_station_handler();
	_deinit_network();

	dbus_connection_remove_filter(tethering_conn, __dnsmasq_signal_filter, tethering_obj);
	dbus_bus_remove_match(tethering_conn, rule, NULL);

	g_object_unref(tethering_obj);
	dbus_g_connection_unref(tethering_bus);

	DBG("-\n");
	return 0;

 failure:
	if (tethering_obj)
		g_object_unref(tethering_obj);
	if (tethering_bus_proxy)
		g_object_unref(tethering_bus_proxy);
	if (tethering_bus)
		dbus_g_connection_unref(tethering_bus);

	DBG("-\n");
	return 0;
}
