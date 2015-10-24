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

#include <glib.h>
#include <dbus/dbus.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <gio/gio.h>

#include "mobileap_softap.h"
#include "mobileap_common.h"
#include "mobileap_usb.h"

static GDBusMethodInvocation *g_context = NULL;
static gboolean in_progress = FALSE;
static GDBusConnection *conn = NULL;
static guint subscription_id = 0;
static int usb_client_state = 0;

#define USB_SYSTEM_DEVICE_PATH	"/Org/Tizen/System/DeviceD/Usb"
#define USB_SYSTEM_DEVICE_IFACE	"org.tizen.system.deviced.Usb"
#define USB_STATE_CHANGE_SIGNAL	"StateChanged"

enum usbclient_state {
	USBCLIENT_STATE_DISCONNECTED = 0x00, /* usb cable is detached */
	USBCLIENT_STATE_CONNECTED    = 0x01, /* usb cable is attached */
	/* usb cable is attached and available (ready to use) */
	USBCLIENT_STATE_AVAILABLE    = 0x02,
};

/* GDbus Signal Handler for USB Device State Changes */
static void __usb_device_state_change_cb(GDBusConnection *connection,
	const gchar *sender_name, const gchar *object_path,
	const gchar *interface_name, const gchar *signal_name,
	GVariant *parameters, gpointer user_data)
{
	unsigned int value = 0;
	Tethering *obj = (Tethering *)user_data;

	if (NULL == parameters || NULL == obj) {
		ERR("Paramters Invalid \n");
		return;
	}

	if (strcmp(object_path, USB_SYSTEM_DEVICE_PATH) ||
		strcmp(interface_name, USB_SYSTEM_DEVICE_IFACE) ||
		strcmp(signal_name, USB_STATE_CHANGE_SIGNAL)) {
		ERR("Unknown DBUS Signal\n");
		return;
	}
	g_variant_get(parameters, "(u)", &value);
	DBG("Received signal(%s), value: (%u)", signal_name, value);
	DBG("USB connected ? (%s)", value & USBCLIENT_STATE_CONNECTED? "Yes":"No");
	DBG("USB available ? (%s)", value & USBCLIENT_STATE_AVAILABLE? "Yes":"No");

	if (USBCLIENT_STATE_DISCONNECTED == value) {
		_disable_usb_tethering(obj);

		if (g_context) {
			tethering_complete_enable_usb_tethering(obj, g_context, MOBILE_AP_ERROR_RESOURCE);
			g_context = NULL;
		} else {
			tethering_emit_usb_off(obj, SIGNAL_MSG_NOT_AVAIL_INTERFACE);
		}
	}

	usb_client_state = value;
}

int _dbus_register_usb_state_change_signal(void *data)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	GError *error = NULL;

#if !GLIB_CHECK_VERSION(2,36,0)
	g_type_init();
#endif

	conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (error) {
		ERR("Error occurred (%s)", error->message);
		g_error_free(error);
		ret = MOBILE_AP_ERROR_RESOURCE;
		goto FAIL;
	}
	if (!conn) {
		ERR("Failed to get gdbus connection");
		ret = MOBILE_AP_ERROR_RESOURCE;
		goto FAIL;
	}

	subscription_id = g_dbus_connection_signal_subscribe(
						conn, NULL, USB_SYSTEM_DEVICE_IFACE,
						USB_STATE_CHANGE_SIGNAL, USB_SYSTEM_DEVICE_PATH, NULL,
						G_DBUS_SIGNAL_FLAGS_NONE, __usb_device_state_change_cb,
						data, NULL);

	if (subscription_id == 0) {
		ERR("Failed to subscribe signal (%d)", USB_STATE_CHANGE_SIGNAL);
		ret = MOBILE_AP_ERROR_RESOURCE;
		goto FAIL;
	}

	usb_client_state = -1;
	DBG("Successfully Subscribed USB State Signal Handler");
	return ret;

FAIL:
	if (conn)
		g_object_unref(conn);
	return ret;
}

static void __handle_usb_disconnect_cb(keynode_t *key, void *data)
{
	if (key == NULL || data == NULL) {
		ERR("Parameter is NULL\n");
		return;
	}

	char *vconf_name = NULL;
	int vconf_key;
	Tethering *obj = (Tethering *)data;

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_USB)) {
		ERR("USB tethering is not enabled\n");
		return;
	}

	if (vconf_keynode_get_type(key) != VCONF_TYPE_INT) {
		ERR("Invalid vconf key type\n");
		return;
	}

	vconf_name = vconf_keynode_get_name(key);
	if (vconf_name == NULL) {
		ERR("vconf_keynode_get_name is failed\n");
		return;
	}
	vconf_key = vconf_keynode_get_int(key);
	if (vconf_key < 0) {
		ERR("vconf_keynode_get_int is failed\n");
		return;
	}
	SDBG("key = %s, value = %d(int)\n", vconf_name, vconf_key);

	/*
	 * P140305-02551: Disconnected State is implemented from DBUS instead of
	 * VCONF key.
	 */
	if (usb_client_state == USBCLIENT_STATE_DISCONNECTED)
		DBG("USB is disconnected\n");
	else if (vconf_name && !strcmp(vconf_name, VCONFKEY_SETAPPL_USB_MODE_INT) &&
			vconf_key != SETTING_USB_TETHERING_MODE)
		SDBG("USB Mode is changed [%d]\n", vconf_key);
	else
		return;

	_disable_usb_tethering(obj);

	if (g_context) {
		g_dbus_method_invocation_return_value(g_context,
				g_variant_new("(uu)", MOBILE_AP_ENABLE_USB_TETHERING_CFM,
						MOBILE_AP_ERROR_RESOURCE));
		g_context = NULL;
	} else {
		tethering_emit_usb_off(obj, SIGNAL_MSG_NOT_AVAIL_INTERFACE);
	}

	return;
}

static void __handle_usb_mode_change(keynode_t *key, void *data)
{
	if (key == NULL || data == NULL) {
		ERR("Parameter is NULL\n");
		return;
	}

	Tethering *obj = (Tethering *)data;
	int ret;
	int vconf_key;
	guint idle_id;

	if (vconf_keynode_get_type(key) != VCONF_TYPE_INT) {
		ERR("Invalid vconf key\n");
		return;
	}

	vconf_key = vconf_keynode_get_int(key);
	SDBG("key = %s, value = %d(int)\n",
			vconf_keynode_get_name(key), vconf_key);

	if (_mobileap_is_enabled(MOBILE_AP_STATE_USB)) {
		if (vconf_key != SETTING_USB_TETHERING_MODE) {
			DBG("Is progressing for usb mode change\n");
			return;
		}

		DBG("USB tethering is enabled\n");
		vconf_ignore_key_changed(VCONFKEY_SETAPPL_USB_MODE_INT,
				__handle_usb_mode_change);

		/* USB Mode change is handled while USB tethering is enabled */
		vconf_notify_key_changed(VCONFKEY_SETAPPL_USB_MODE_INT,
				__handle_usb_disconnect_cb, (void *)obj);
		ret = vconf_get_int(VCONFKEY_SETAPPL_USB_MODE_INT, &vconf_key);
		if (ret != 0) {
			ERR("vconf_get_int is failed. but ignored [%d]\n", ret);
		}

		if (vconf_key != SETTING_USB_TETHERING_MODE) {
			ERR("USB Mode is changed suddenly\n");
			_disable_usb_tethering(obj);
			if (g_context) {
				tethering_complete_enable_usb_tethering(obj, g_context, MOBILE_AP_ERROR_RESOURCE);
				g_context = NULL;
			}
			return;
		}
		_add_interface_routing(USB_IF, IP_ADDRESS_USB);
		_add_routing_rule(USB_IF);
		tethering_emit_usb_on(obj);
		_create_tethering_active_noti();
		if (g_context) {
			tethering_complete_enable_usb_tethering(obj, g_context, MOBILE_AP_ERROR_NONE);
			g_context = NULL;
		}
	} else {
		if (vconf_key == SETTING_USB_TETHERING_MODE) {
			DBG("Is progressing for usb mode change\n");
			return;
		}

		DBG("USB tethering is disabled\n");
		vconf_ignore_key_changed(VCONFKEY_SETAPPL_USB_MODE_INT,
				__handle_usb_mode_change);
		tethering_emit_usb_off(obj, NULL);
		if (g_context) {
			tethering_complete_disable_usb_tethering(obj, g_context, MOBILE_AP_DISABLE_USB_TETHERING_CFM, NULL);
			g_context = NULL;
		}

		in_progress = FALSE;
		idle_id = g_idle_add(_terminate_mobileap_agent, NULL);
		if (idle_id == 0)
			ERR("g_idle_add is failed\n");
	}
}

mobile_ap_error_code_e _enable_usb_tethering(Tethering *obj)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	int vconf_ret;
	int usb_mode = SETTING_USB_NONE_MODE;

	if (_mobileap_is_enabled(MOBILE_AP_STATE_USB)) {
		ERR("USB tethering is already enabled\n");
		ret = MOBILE_AP_ERROR_ALREADY_ENABLED;
		return ret;
	}

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI_AP)) {
		ERR("Wi-Fi AP is enabled\n");
		ret = MOBILE_AP_ERROR_RESOURCE;
		return ret;
	}

	/* Register DBus Signal Handler for USB Client State */
	if (_dbus_register_usb_state_change_signal(obj) != MOBILE_AP_ERROR_NONE) {
		ERR("Failed to register dbus signal(%d)", ret);
		ret = MOBILE_AP_ERROR_RESOURCE;
		goto FAIL;
	}

	if (!_mobileap_set_state(MOBILE_AP_STATE_USB)) {
		ret = MOBILE_AP_ERROR_RESOURCE;
		goto FAIL;
	}

	ret = _init_tethering();
	if (ret != MOBILE_AP_ERROR_NONE) {
		goto FAIL;
	}

	vconf_notify_key_changed(VCONFKEY_SETAPPL_USB_MODE_INT,
			__handle_usb_mode_change, (void *)obj);

	vconf_ret = vconf_get_int(VCONFKEY_SETAPPL_USB_MODE_INT, &usb_mode);
	if (vconf_ret != 0) {
		ERR("Error getting vconf\n");
		vconf_ignore_key_changed(VCONFKEY_SETAPPL_USB_MODE_INT,
				__handle_usb_mode_change);
		_deinit_tethering();
		ret = MOBILE_AP_ERROR_RESOURCE;
		goto FAIL;
	}

	if (usb_mode == SETTING_USB_TETHERING_MODE) {
		vconf_ignore_key_changed(VCONFKEY_SETAPPL_USB_MODE_INT,
				__handle_usb_mode_change);
		_add_interface_routing(USB_IF, IP_ADDRESS_USB);
		_add_routing_rule(USB_IF);
	}

	DBG("-\n");
	return MOBILE_AP_ERROR_NONE;

FAIL:
	/* Clear DBus Signal Handler for USB Client State */
	if (conn) {
		if (subscription_id > 0) {
			g_dbus_connection_signal_unsubscribe(conn, subscription_id);
			subscription_id = 0;
		}
		g_object_unref(conn);
		conn = NULL;
	}
	_mobileap_clear_state(MOBILE_AP_STATE_USB);

	return ret;
}

mobile_ap_error_code_e _disable_usb_tethering(Tethering *obj)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_USB)) {
		ERR("USB tethering has not been enabled\n");
		ret = MOBILE_AP_ERROR_NOT_ENABLED;
		return ret;
	}

	_deinit_tethering();

	if (_remove_station_info_all(MOBILE_AP_TYPE_USB) != MOBILE_AP_ERROR_NONE) {
		ERR("_remove_station_info_all is failed. Ignore it\n");
	}

	/* Clear DBus Signal Handler for USB Client State */
	if (conn) {
		if (subscription_id > 0) {
			g_dbus_connection_signal_unsubscribe(conn, subscription_id);
			subscription_id = 0;
		}
		g_object_unref(conn);
		conn = NULL;
	}

	vconf_ignore_key_changed(VCONFKEY_SETAPPL_USB_MODE_INT,
			__handle_usb_disconnect_cb);

	_mobileap_clear_state(MOBILE_AP_STATE_USB);
	_del_routing_rule(USB_IF);
	_del_interface_routing(USB_IF, IP_ADDRESS_USB);

	DBG("_disable_usb_tethering is done\n");

	return ret;
}

gboolean tethering_enable_usb_tethering(Tethering *obj, GDBusMethodInvocation *context)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	gboolean ret_val = FALSE;

	DBG("+\n");

	g_assert(obj != NULL);
	g_assert(context != NULL);

	if (g_context) {
		DBG("It is turnning on\n");
		tethering_complete_enable_usb_tethering(obj, g_context, MOBILE_AP_ERROR_IN_PROGRESS);
		return FALSE;
	}

	g_context = context;

	ret = _enable_usb_tethering(obj);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_enable_usb_tethering() is failed : %d\n", ret);
		goto DONE;
	} else {
		DBG("Don't need to wait for usb-setting\n");
		tethering_emit_usb_on(obj);
		_create_tethering_active_noti();
		ret_val = TRUE;
	}

DONE:
	tethering_complete_enable_usb_tethering(obj, g_context, ret);

	g_context = NULL;

	return ret_val;
}

gboolean tethering_disable_usb_tethering(Tethering *obj,
		GDBusMethodInvocation *context)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	int usb_mode = SETTING_USB_NONE_MODE;
	int vconf_ret = 0;

	DBG("+\n");

	g_assert(obj != NULL);
	g_assert(context != NULL);

	if (g_context) {
		DBG("It is turnning on\n");
		tethering_complete_disable_usb_tethering(obj, context,
				MOBILE_AP_DISABLE_USB_TETHERING_CFM,
				MOBILE_AP_ERROR_IN_PROGRESS);
		return FALSE;
	}

	g_context = context;

	ret = _disable_usb_tethering(obj);
	if (ret != MOBILE_AP_ERROR_NONE) {
		tethering_complete_disable_usb_tethering(obj, g_context,
				MOBILE_AP_DISABLE_USB_TETHERING_CFM, ret);
		g_context = NULL;
		return FALSE;
	}

	vconf_notify_key_changed(VCONFKEY_SETAPPL_USB_MODE_INT,
			__handle_usb_mode_change, (void *)obj);
	vconf_ret = vconf_get_int(VCONFKEY_SETAPPL_USB_MODE_INT, &usb_mode);
	if (vconf_ret != 0) {
		ERR("Error getting vconf : %d. This error is ignored\n", vconf_ret);
		goto DONE;
	}

	if (usb_mode != SETTING_USB_TETHERING_MODE) {
		DBG("Don't need to wait for usb-setting\n");
		goto DONE;
	}

	in_progress = TRUE;

	DBG("-\n");
	return TRUE;

DONE:
	vconf_ignore_key_changed(VCONFKEY_SETAPPL_USB_MODE_INT,
			__handle_usb_mode_change);
	tethering_emit_usb_off(obj, NULL);
	tethering_complete_disable_usb_tethering(obj, g_context,
			MOBILE_AP_DISABLE_USB_TETHERING_CFM, ret);
	g_context = NULL;

	return TRUE;
}

gboolean _is_trying_usb_operation(void)
{
	return (g_context ? TRUE : FALSE || in_progress);
}
