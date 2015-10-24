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
#include <stdlib.h>

#include "mobileap_softap.h"
#include "mobileap_common.h"
#include "mobileap_bluetooth.h"
#include "mobileap_wifi.h"
#include "mobileap_usb.h"
#include "mobileap_notification.h"
#include "mobileap_handler.h"

#define VCONF_IS_DEVICE_RENAMED_IN_UG "file/private/libug-setting-mobileap-efl/is_device_rename_local"

typedef struct {
	alarm_id_t alarm_id;
	time_t end_time;
	GSourceFunc func;
	void *user_data;
} sp_timeout_handler_t;

static gboolean __wifi_timeout_cb(gpointer user_data);
static gboolean __bt_timeout_cb(gpointer user_data);

static sp_timeout_handler_t sp_timeout_handler[MOBILE_AP_TYPE_MAX] = {
	{0, 0, __wifi_timeout_cb, NULL},
	{0, 0, NULL, NULL},
	{0, 0, __bt_timeout_cb, NULL},
	{0, 0, NULL, NULL}};

static void __handle_network_cellular_state_changed_cb(keynode_t *key, void *data)
{
	if (key == NULL) {
		ERR("Parameter is NULL\n");
		return;
	}

	Tethering *obj = (Tethering *)data;
	int vconf_key = 0;

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_WIFI | MOBILE_AP_STATE_WIFI_AP)) {
		return;
	}

	if (vconf_keynode_get_type(key) != VCONF_TYPE_INT) {
		ERR("Invalid vconf key type\n");
		return;
	}

	vconf_key = vconf_keynode_get_int(key);
	SDBG("key = %s, value = %d(int)\n",
			vconf_keynode_get_name(key), vconf_key);

	if (vconf_key != VCONFKEY_NETWORK_CELLULAR_FLIGHT_MODE)
		return;

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI))
		_disable_wifi_tethering(obj);
	else if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI_AP))
		_disable_wifi_ap(obj);
	if (_mobileap_is_enabled(MOBILE_AP_STATE_USB))
		_disable_usb_tethering(obj);

	tethering_emit_flight_mode(obj);

	return;
}

static void __handle_device_name_changed_cb(keynode_t *key, void *data)
{
	if (key == NULL || data == NULL) {
		ERR("Parameter is NULL\n");
		return;
	}

	Tethering *obj = (Tethering *)data;
	char *vconf_key = NULL;
	softap_settings_t *new_settings = _get_softap_settings();
	softap_security_type_e sec_type;

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_WIFI | MOBILE_AP_STATE_WIFI_AP)) {
		return;
	}

	if (vconf_keynode_get_type(key) != VCONF_TYPE_STRING) {
		ERR("Invalid vconf key type\n");
		return;
	}
	vconf_key = vconf_keynode_get_str(key);

	if (g_strcmp0(vconf_key, new_settings->ssid) != 0) {
		DBG("Device name is changed\n");
		if (!g_strcmp0(new_settings->security_type, SOFTAP_SECURITY_TYPE_WPA2_PSK_STR)) {
			sec_type = SOFTAP_SECURITY_TYPE_WPA2_PSK;
		} else {
			sec_type = SOFTAP_SECURITY_TYPE_OPEN;
		}
		if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI)) {
			_reload_softap_settings(obj, vconf_key, new_settings->key,
					new_settings->hide_mode, sec_type);
		} else if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI_AP)) {
			_reload_softap_settings_for_ap(obj, vconf_key, new_settings->key,
					new_settings->hide_mode, sec_type);
		}
	}
	return;
}

static void __handle_language_changed_cb(keynode_t *key, void *data)
{
	if (key == NULL || data == NULL) {
		ERR("Parameter is NULL\n");
		return;
	}

	char *language = NULL;

	if (vconf_keynode_get_type(key) != VCONF_TYPE_STRING) {
		ERR("Invalid vconf key type\n");
		return;
	}

	language = vconf_get_str(VCONFKEY_LANGSET);
	if (language) {
		setenv("LANG", language, 1);
		setenv("LC_MESSAGES",  language, 1);
		setlocale(LC_ALL, language);
		free(language);
	}

	return;
}

gboolean _is_power_save_survival_mode(void)
{
	int ret;
	int status;

	ret = vconf_get_int(VCONFKEY_SETAPPL_PSMODE, &status);
	if (ret != 0) {
		ERR("vconf_get_int is failed : %d\n", ret);
		return FALSE;
	}

	DBG(" PS mode status : %d", status);
	if (status == SETTING_PSMODE_SURVIVAL)
		return TRUE;
	else
		return FALSE;
}

void _register_vconf_cb(void *user_data)
{
	if (user_data == NULL) {
		ERR("Invalid param\n");
		return;
	}

	vconf_reg_t vconf_reg[] = {
		{VCONFKEY_NETWORK_CELLULAR_STATE,
			__handle_network_cellular_state_changed_cb, NULL},
		{VCONFKEY_SETAPPL_DEVICE_NAME_STR,
			__handle_device_name_changed_cb, NULL},
		{VCONFKEY_LANGSET,
			__handle_language_changed_cb, NULL},
		{NULL, NULL, NULL}
	};

	int i = 0;
	int ret = 0;

	while (vconf_reg[i].key != NULL && vconf_reg[i].cb != NULL) {
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

void _unregister_vconf_cb(void)
{
	vconf_reg_t vconf_reg[] = {
		{VCONFKEY_NETWORK_CELLULAR_STATE,
			__handle_network_cellular_state_changed_cb, NULL},
		{VCONFKEY_SETAPPL_DEVICE_NAME_STR,
			__handle_device_name_changed_cb, NULL},
		{VCONFKEY_LANGSET,
			__handle_language_changed_cb, NULL},
		{NULL, NULL, NULL}
	};

	int i = 0;
	int ret = 0;

	while (vconf_reg[i].key != NULL && vconf_reg[i].cb != NULL) {
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

	Tethering *obj = (Tethering *)data;

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI) == FALSE) {
		ERR("There is no conn. via Wi-Fi tethernig. But nothing to do\n");
		return FALSE;
	}

	_disable_wifi_tethering(obj);
	tethering_emit_wifi_off(obj, SIGNAL_MSG_TIMEOUT);
	//_launch_toast_popup(MOBILE_AP_TETHERING_TIMEOUT_TOAST_POPUP);
	_create_timeout_noti(MH_NOTI_ICON_WIFI);
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

	Tethering *obj = (Tethering *)data;

	if (_mobileap_is_enabled(MOBILE_AP_STATE_BT) == FALSE) {
		ERR("There is no conn. via BT tethering. But nothing to do\n");
		return FALSE;
	}

	_disable_bt_tethering(obj);
	tethering_emit_bluetooth_off(obj, SIGNAL_MSG_TIMEOUT);
	//_launch_toast_popup(MOBILE_AP_TETHERING_TIMEOUT_TOAST_POPUP);
	_create_timeout_noti(MH_NOTI_ICON_BT);
	DBG("-\n");
	return FALSE;
}

static sp_timeout_handler_t *__find_next_timeout(void)
{
	sp_timeout_handler_t *next_timeout = &sp_timeout_handler[MOBILE_AP_TYPE_WIFI];
	mobile_ap_type_e i;

	for (i = MOBILE_AP_TYPE_USB; i < MOBILE_AP_TYPE_MAX; i++) {
		if (sp_timeout_handler[i].end_time == 0)
			continue;

		if (sp_timeout_handler[i].end_time < next_timeout->end_time ||
				next_timeout->end_time == 0)
			next_timeout = &sp_timeout_handler[i];
	}

	return next_timeout;
}

static void __expire_timeout(sp_timeout_handler_t *sp)
{
	if (sp->alarm_id > 0) {
		alarmmgr_remove_alarm(sp->alarm_id);
		sp->alarm_id = 0;
	}

	sp->end_time = 0;

	if (sp->func)
		sp->func(sp->user_data);
}

static void __reset_timeout(sp_timeout_handler_t *sp)
{
	if (sp->alarm_id > 0) {
		alarmmgr_remove_alarm(sp->alarm_id);
		sp->alarm_id = 0;
	}

	sp->end_time = 0;
}

int _sp_timeout_handler(alarm_id_t alarm_id, void *user_param)
{
	DBG("+\n");

	int ret;
	time_t now;
	time_t interval;
	mobile_ap_type_e i;
	sp_timeout_handler_t *next_timeout;

	now = time(NULL);
	for (i = MOBILE_AP_TYPE_WIFI; i < MOBILE_AP_TYPE_MAX; i++) {
		if (sp_timeout_handler[i].end_time == 0)
			continue;

		if (sp_timeout_handler[i].alarm_id == alarm_id) {
			sp_timeout_handler[i].alarm_id = 0;
			__expire_timeout(&sp_timeout_handler[i]);
			continue;
		}

		interval = (time_t)difftime(sp_timeout_handler[i].end_time, now);
		if (interval > 0)
			continue;

		__expire_timeout(&sp_timeout_handler[i]);
	}

	next_timeout = __find_next_timeout();
	if (next_timeout->end_time == 0)
		return 0;

	interval = (time_t)difftime(next_timeout->end_time, now);
	ret = alarmmgr_add_alarm(ALARM_TYPE_VOLATILE, interval, 0, NULL,
			&next_timeout->alarm_id);
	if (ret != ALARMMGR_RESULT_SUCCESS) {
		ERR("alarmmgr_add_alarm is failed. end_time : %d\n",
				next_timeout->end_time);
		return 0;
	}

	DBG("-\n");
	return 0;
}

void _init_timeout_cb(mobile_ap_type_e type, void *user_data)
{
	DBG("+\n");

	if (sp_timeout_handler[type].func == NULL) {
		return;
	}

	if (user_data == NULL) {
		ERR("Invalid param\n");
		return;
	}

	sp_timeout_handler[type].alarm_id = 0;
	sp_timeout_handler[type].end_time = 0;
	sp_timeout_handler[type].user_data = user_data;

	DBG("-\n");
	return;
}

void _start_timeout_cb(mobile_ap_type_e type, time_t end_time)
{
	int ret;
	time_t interval;
	mobile_ap_type_e i;
	sp_timeout_handler_t *next_timeout;

	if (sp_timeout_handler[type].func == NULL) {
		return;
	}

	__reset_timeout(&sp_timeout_handler[type]);
	sp_timeout_handler[type].end_time = end_time;

	next_timeout = __find_next_timeout();
	if (next_timeout->alarm_id > 0) {
		return;
	}

	for (i = MOBILE_AP_TYPE_WIFI; i < MOBILE_AP_TYPE_MAX; i++) {
		if (sp_timeout_handler[i].alarm_id == 0)
			continue;

		__reset_timeout(&sp_timeout_handler[i]);
	}

	interval = (time_t)difftime(next_timeout->end_time, time(NULL));
	if (interval <= 0) {
		__expire_timeout(next_timeout);
		return;
	}

	ret = alarmmgr_add_alarm(ALARM_TYPE_VOLATILE, interval, 0, NULL,
			&next_timeout->alarm_id);
	if (ret != ALARMMGR_RESULT_SUCCESS) {
		ERR("alarmmgr_add_alarm is failed. type : %d, end_time : %d\n",
				type, end_time);
		return;
	}

	return;
}

void _stop_timeout_cb(mobile_ap_type_e type)
{
	DBG("+\n");

	int ret;
	time_t interval;
	mobile_ap_type_e i;
	sp_timeout_handler_t *next_timeout;

	if (sp_timeout_handler[type].func == NULL) {
		return;
	}

	if (sp_timeout_handler[type].alarm_id == 0) {
		sp_timeout_handler[type].end_time = 0;
		return;
	}

	for (i = MOBILE_AP_TYPE_WIFI; i < MOBILE_AP_TYPE_MAX; i++) {
		if (sp_timeout_handler[i].end_time != sp_timeout_handler[type].end_time ||
				type == i)
			continue;

		sp_timeout_handler[i].alarm_id = sp_timeout_handler[type].alarm_id;
		sp_timeout_handler[type].alarm_id = 0;
		sp_timeout_handler[type].end_time = 0;
		return;
	}
	__reset_timeout(&sp_timeout_handler[type]);

	next_timeout = __find_next_timeout();
	if (next_timeout->end_time == 0)
		return;

	interval = (time_t)difftime(next_timeout->end_time, time(NULL));
	if (interval <= 0) {
		__expire_timeout(next_timeout);
		return;
	}

	ret = alarmmgr_add_alarm(ALARM_TYPE_VOLATILE, interval, 0, NULL,
			&next_timeout->alarm_id);
	if (ret != ALARMMGR_RESULT_SUCCESS) {
		ERR("alarmmgr_add_alarm is failed. type : %d, end_time : %d\n",
				type, next_timeout->end_time);
	}

	DBG("-\n");
	return;
}

void _deinit_timeout_cb(mobile_ap_type_e type) {
	DBG("+\n");

	if (sp_timeout_handler[type].func == NULL) {
		return;
	}

	if (sp_timeout_handler[type].alarm_id > 0) {
		_stop_timeout_cb(type);
	}

	sp_timeout_handler[type].user_data = NULL;
	sp_timeout_handler[type].end_time = 0;

	DBG("-\n");
	return;
}
