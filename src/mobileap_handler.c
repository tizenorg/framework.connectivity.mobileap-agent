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
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "mobileap_agent.h"
#include "mobileap_common.h"
#include "mobileap_bluetooth.h"
#include "mobileap_wifi.h"
#include "mobileap_usb.h"
#include "mobileap_notification.h"

/* Need translation */
#define MH_NOTI_TIMEOUT_STR	"Tap for setting"
#define MH_NOTI_TIMEOUT_TITLE	"Disable tethering by timeout"

typedef struct {
	guint src_id;
	GSourceFunc func;
	void *user_data;
} sp_timeout_handler_t;

static gboolean __wifi_timeout_cb(gpointer user_data);
static gboolean __bt_timeout_cb(gpointer user_data);

static sp_timeout_handler_t sp_timeout_handler[MOBILE_AP_TYPE_MAX] = {
	{0, __wifi_timeout_cb, NULL},
	{0, NULL, NULL},
	{0, __bt_timeout_cb, NULL}};



static void __handle_flight_mode_changed_cb(keynode_t *key, void *data)
{
	if (key == NULL) {
		ERR("Parameter is NULL\n");
		return;
	}

	TetheringObject *obj = (TetheringObject *)data;
	int vconf_key = 0;

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_WIFI)) {
		DBG("Wi-Fi tethering is not enabled\n");
		return;
	}

	if (vconf_keynode_get_type(key) != VCONF_TYPE_BOOL) {
		ERR("Invalid vconf key type\n");
		return;
	}

	vconf_key = vconf_keynode_get_bool(key);
	DBG("key = %s, value = %d(bool)\n",
			vconf_keynode_get_name(key), vconf_key);

	if (vconf_key == FALSE)
		return;

	DBG("Flight mode\n");
	_disable_wifi_tethering(obj);
	_emit_mobileap_dbus_signal(obj, E_SIGNAL_FLIGHT_MODE, NULL);

	return;
}

static void __handle_device_name_changed_cb(keynode_t *key, void *data)
{
	if (key == NULL || data == NULL) {
		ERR("Parameter is NULL\n");
		return;
	}

	TetheringObject *obj = (TetheringObject *)data;
	char *vconf_key = NULL;

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_WIFI)) {
		DBG("Wi-Fi hotspot is not enabled\n");
		return;
	}

	if (vconf_keynode_get_type(key) != VCONF_TYPE_STRING) {
		ERR("Invalid vconf key type\n");
		return;
	}

	vconf_key = vconf_keynode_get_str(key);
	DBG("key = %s, value = %s(str)\n",
			vconf_keynode_get_name(key), vconf_key);

	if (g_strcmp0(vconf_key, obj->ssid) == 0) {
		DBG("ssid is not changed\n");
	} else {
		DBG("ssid is changed\n");
		_disable_wifi_tethering(obj);
	}

	return;
}

void _register_vconf_cb(void *user_data)
{
	if (user_data == NULL) {
		ERR("Invalid param\n");
		return;
	}

	vconf_reg_t vconf_reg[] = {
		{VCONFKEY_TELEPHONY_FLIGHT_MODE,
			__handle_flight_mode_changed_cb, NULL},
		{VCONFKEY_SETAPPL_DEVICE_NAME_STR,
			__handle_device_name_changed_cb, NULL},
		{NULL, NULL, NULL}
	};

	int i = 0;
	int ret = 0;

	while (vconf_reg[i].key != NULL && vconf_reg[i].cb != NULL) {
		DBG("Register [%d] : %s\n", i, vconf_reg[i].key);
		ret = vconf_notify_key_changed(vconf_reg[i].key,
					vconf_reg[i].cb, user_data);
		if (ret != 0) {
			ERR("vconf_notify_key_changed is failed : %d\n", ret);
		}

		if (vconf_reg[i].value) {
			ret = vconf_get_int(vconf_reg[i].key,
					vconf_reg[i].value);
			if (ret != 0) {
				ERR("vconf_get_int is failed : %d\n", ret);
			}
		}

		i++;
	}

	return;
}

void _unregister_vconf_cb(void *user_data)
{
	if (user_data == NULL) {
		ERR("Invalid param\n");
		return;
	}

	vconf_reg_t vconf_reg[] = {
		{VCONFKEY_TELEPHONY_FLIGHT_MODE,
			__handle_flight_mode_changed_cb, NULL},
		{VCONFKEY_SETAPPL_DEVICE_NAME_STR,
			__handle_device_name_changed_cb, NULL},
		{NULL, NULL, NULL}
	};

	int i = 0;
	int ret = 0;

	while (vconf_reg[i].key != NULL && vconf_reg[i].cb != NULL) {
		DBG("Register [%d] : %s\n", i, vconf_reg[i].key);
		ret = vconf_ignore_key_changed(vconf_reg[i].key,
				vconf_reg[i].cb);
		if (ret != 0) {
			ERR("vconf_notify_key_changed is failed : %d\n", ret);
		}

		i++;
	}

	return;
}

static gboolean __wifi_timeout_cb(gpointer data)
{
	DBG("+\n");
	if (data == NULL) {
		ERR("data is NULL\n");
		return FALSE;
	}

	TetheringObject *obj = (TetheringObject *)data;

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI) == FALSE) {
		ERR("There is no conn. via Wi-Fi tethernig. But nothing to do\n");
		return FALSE;
	}

	_disable_wifi_tethering(obj);
	_emit_mobileap_dbus_signal(obj,
			E_SIGNAL_WIFI_TETHER_OFF, SIGNAL_MSG_TIMEOUT);

	_create_timeout_noti(MH_NOTI_TIMEOUT_STR, MH_NOTI_TIMEOUT_TITLE,
			MH_NOTI_ICON_PATH);

	DBG("-\n");
	return FALSE;
}

static gboolean __bt_timeout_cb(gpointer data)
{
	DBG("+\n");
	if (data == NULL) {
		ERR("data is NULL\n");
		return FALSE;
	}

	TetheringObject *obj = (TetheringObject *)data;

	if (_mobileap_is_enabled(MOBILE_AP_STATE_BT) == FALSE) {
		ERR("There is no conn. via BT tethering. But nothing to do\n");
		return FALSE;
	}

	_disable_bt_tethering(obj);
	_emit_mobileap_dbus_signal(obj,
			E_SIGNAL_BT_TETHER_OFF, SIGNAL_MSG_TIMEOUT);

	_create_timeout_noti(MH_NOTI_TIMEOUT_STR, MH_NOTI_TIMEOUT_TITLE,
			MH_NOTI_ICON_PATH);
	DBG("-\n");
	return FALSE;
}

void _init_timeout_cb(mobile_ap_type_e type, void *user_data)
{
	DBG("+\n");
	if (sp_timeout_handler[type].func == NULL) {
		DBG("Not supported timeout : type[%d]\n", type);
		return;
	}

	if (user_data == NULL) {
		ERR("Invalid param\n");
		return;
	}

	if (sp_timeout_handler[type].src_id > 0) {
		DBG("There is already registered timeout source\n");
		g_source_remove(sp_timeout_handler[type].src_id);
		sp_timeout_handler[type].src_id = 0;
	}

	sp_timeout_handler[type].user_data = user_data;

	DBG("-\n");
	return;
}

void _start_timeout_cb(mobile_ap_type_e type)
{
	DBG("+\n");
	if (sp_timeout_handler[type].func == NULL) {
		DBG("Not supported timeout : type[%d]\n", type);
		return;
	}

	if (sp_timeout_handler[type].src_id > 0) {
		ERR("It is not registered or stopped\n");
		return;
	}

	sp_timeout_handler[type].src_id = g_timeout_add(TETHERING_CONN_TIMEOUT,
			sp_timeout_handler[type].func,
			sp_timeout_handler[type].user_data);

	DBG("-\n");
	return;
}

void _stop_timeout_cb(mobile_ap_type_e type)
{
	DBG("+\n");
	if (sp_timeout_handler[type].func == NULL) {
		DBG("Not supported timeout : type[%d]\n", type);
		return;
	}

	if (sp_timeout_handler[type].src_id == 0) {
		ERR("It is not started yet\n");
		return;
	}

	g_source_remove(sp_timeout_handler[type].src_id);
	sp_timeout_handler[type].src_id = 0;

	DBG("-\n");
	return;
}

void _deinit_timeout_cb(mobile_ap_type_e type) {
	DBG("+\n");
	if (sp_timeout_handler[type].func == NULL) {
		DBG("Not supported timeout : type[%d]\n", type);
		return;
	}

	if (sp_timeout_handler[type].src_id > 0) {
		g_source_remove(sp_timeout_handler[type].src_id);
		sp_timeout_handler[type].src_id = 0;
	}

	sp_timeout_handler[type].user_data = NULL;

	DBG("-\n");
	return;
}

