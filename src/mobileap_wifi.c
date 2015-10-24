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
#include <stdlib.h>
#include <wifi.h>
#include <wifi-direct.h>

#include "mobileap_softap.h"
#include "mobileap_common.h"
#include "mobileap_wifi.h"
#include "mobileap_handler.h"
#include "mobileap_notification.h"

#define WIFI_RECOVERY_GUARD_TIME	1000	/* ms */

static mobile_ap_error_code_e __update_softap_settings(softap_settings_t *st,
	gchar *ssid, gchar *passphrase, int hide_mode, softap_security_type_e security_type);
static int __turn_off_wifi(Tethering *obj);

static GDBusMethodInvocation *g_context = NULL;
static guint wifi_recovery_timeout_id = 0;
static gboolean prev_wifi_on = FALSE;
static wifi_saved_settings wifi_settings = {0, NULL, NULL, 0};
static softap_settings_t obj_softap_settings = {0, "", "", ""};

softap_settings_t *_get_softap_settings()
{
	return &obj_softap_settings;
}
static void _wifi_direct_state_cb(int error_code, wifi_direct_device_state_e state, void *user_data)
{
	bool wifi_state = false;

	DBG("+\n");

	if (user_data == NULL) {
		ERR("The param is NULL\n");
		return;
	}

	Tethering *obj = (Tethering *)user_data;
	int ret = 0;

	if (state != WIFI_DIRECT_DEVICE_STATE_DEACTIVATED) {
		ERR("Unknown state : %d\n", state);
		return;
	}

	wifi_direct_unset_device_state_changed_cb();
	wifi_direct_deinitialize();

	if (error_code != 0) {
		ERR("wifi_direct_deactivate fail in cb : %d\n", error_code);
		ret = MOBILE_AP_ERROR_INTERNAL;
		goto DONE;
	}
	DBG("Wi-Fi direct is turned off\n");

	wifi_is_activated(&wifi_state);
	if (wifi_state) {
		DBG("Wi-Fi is turned on. Turn off Wi-Fi");
		if (__turn_off_wifi(obj) != MOBILE_AP_ERROR_NONE) {
			ERR("_turn_off_wifi is failed\n");
			ret = MOBILE_AP_ERROR_INTERNAL;
			goto DONE;
		}
		return;
	}

	ret = _enable_wifi_tethering(obj, wifi_settings.ssid, wifi_settings.key,
			wifi_settings.hide_mode, wifi_settings.security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_enable_wifi_tethering is failed\n");
	} else {
		tethering_emit_wifi_on(obj);
		_create_tethering_active_noti();
	}

DONE:
	tethering_complete_enable_wifi_tethering(obj, g_context, ret);
	g_context = NULL;

	g_free(wifi_settings.ssid);
	g_free(wifi_settings.key);
	memset(&wifi_settings, 0, sizeof(wifi_settings));

	DBG("-\n");
	return;
}

static void __wifi_activated_cb(wifi_error_e result, void *user_data)
{
	DBG("Wi-Fi on is done\n");

	return;
}

static void __wifi_deactivated_cb(wifi_error_e result, void *user_data)
{
	DBG("+\n");

	if (user_data == NULL) {
		ERR("The param is NULL\n");
		return;
	}

	Tethering *obj = (Tethering *)user_data;
	int ret;

	if (result != WIFI_ERROR_NONE) {
		ERR("__wifi_deactivated_cb error : %d\n", result);
		ret = MOBILE_AP_ERROR_INTERNAL;
		goto DONE;
	}

	DBG("Wi-Fi is turned off\n");

	ret = _enable_wifi_tethering(obj, wifi_settings.ssid, wifi_settings.key,
			wifi_settings.hide_mode, wifi_settings.security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_enable_wifi_tethering is failed\n");
	} else {
		prev_wifi_on = TRUE;
		tethering_emit_wifi_on(obj);
		_create_tethering_active_noti();
	}

DONE:
	tethering_complete_enable_wifi_tethering(obj, g_context, ret);

	g_context = NULL;

	g_free(wifi_settings.ssid);
	g_free(wifi_settings.key);
	memset(&wifi_settings, 0, sizeof(wifi_settings));

	DBG("-\n");
	return;
}

static int __turn_off_wifi(Tethering *obj)
{
	int ret;

	ret = wifi_deactivate(__wifi_deactivated_cb, (void *)obj);
	if (ret != WIFI_ERROR_NONE) {
		ERR("wifi_deactivate() is failed : %d\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	return MOBILE_AP_ERROR_NONE;
}

static gboolean __turn_on_wifi_timeout_cb(gpointer user_data)
{
	int ret;
	guint idle_id;

	wifi_recovery_timeout_id = 0;

	ret = wifi_activate(__wifi_activated_cb, NULL);
	if (ret != WIFI_ERROR_NONE) {
		ERR("wifi_activate() is failed : %d\n", ret);
	}

	idle_id = g_idle_add(_terminate_mobileap_agent, NULL);
	if (idle_id == 0) {
		ERR("g_idle_add is failed\n");
	}

	return FALSE;
}

static int __turn_on_wifi(void)
{
	if (wifi_recovery_timeout_id > 0) {
		g_source_remove(wifi_recovery_timeout_id);
		wifi_recovery_timeout_id = 0;
	}

	wifi_recovery_timeout_id = g_timeout_add(WIFI_RECOVERY_GUARD_TIME,
			__turn_on_wifi_timeout_cb, NULL);
	if (wifi_recovery_timeout_id == 0) {
		ERR("g_timeout_add is failed\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	return MOBILE_AP_ERROR_NONE;
}

static gboolean __is_wifi_direct_on(void)
{
	int wifi_direct_state = 0;
	int ret;

	ret = vconf_get_int(VCONFKEY_WIFI_DIRECT_STATE, &wifi_direct_state);
	if (ret < 0) {
		ERR("vconf_get_int() is failed : %d\n", ret);
		return FALSE;
	}

	return wifi_direct_state != 0 ? TRUE : FALSE;
}

static int __turn_off_wifi_direct(Tethering *obj)
{
	int ret;

	ret = wifi_direct_initialize();
	if (ret < 0) {
		ERR("wifi_direct_initialize() is failed : %d\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	ret = wifi_direct_set_device_state_changed_cb(_wifi_direct_state_cb, (void *)obj);
	if (ret < 0) {
		ERR("wifi_direct_set_device_state_changed_cb() is failed : %d\n", ret);
		ret = wifi_direct_deinitialize();
		DBG("wifi_direct_deinitialize() ret : %d\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	ret = wifi_direct_deactivate();
	if (ret < 0) {
		ERR("wifi_direct_deactivate() is failed : %d\n", ret);
		ret = wifi_direct_unset_device_state_changed_cb();
		DBG("wifi_direct_unset_device_state_changed_cb() ret : %d\n", ret);
		ret = wifi_direct_deinitialize();
		DBG("wifi_direct_deinitialize() ret : %d\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	return MOBILE_AP_ERROR_NONE;
}

static mobile_ap_error_code_e __update_softap_settings(softap_settings_t *st,
	gchar *ssid, gchar *passphrase, int hide_mode, softap_security_type_e security_type)
{
	if (st == NULL) {
		ERR("Invalid param\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	g_strlcpy(st->ssid, ssid, sizeof(st->ssid));

	if (security_type == SOFTAP_SECURITY_TYPE_WPA2_PSK) {
		g_strlcpy(st->security_type, SOFTAP_SECURITY_TYPE_WPA2_PSK_STR,
			sizeof(st->security_type));
		g_strlcpy(st->key, passphrase, sizeof(st->key));
	} else if (security_type == SOFTAP_SECURITY_TYPE_OPEN) {
		g_strlcpy(st->security_type, SOFTAP_SECURITY_TYPE_OPEN_STR,
			sizeof(st->security_type));
		g_strlcpy(st->key, "00000000", sizeof(st->key));
	} else {
		ERR("Unknown security type\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	st->hide_mode = hide_mode;

	SDBG("ssid : %s security type : %s hide mode : %d\n",
			st->ssid, st->security_type, st->hide_mode);

	return MOBILE_AP_ERROR_NONE;
}

static gboolean __is_equal_softap_settings(softap_settings_t *a, softap_settings_t *b)
{
	if (a->hide_mode != b->hide_mode)
		return FALSE;

	if (strcmp(a->ssid, b->ssid) != 0)
		return FALSE;

	if (strcmp(a->key, b->key) != 0)
		return FALSE;

	if (strcmp(a->security_type, b->security_type) != 0)
		return FALSE;

	return TRUE;
}

mobile_ap_error_code_e _reload_softap_settings(Tethering *obj,
		gchar *ssid, gchar *key, gint hide_mode, gint security_type)
{
	gboolean backup_prev_wifi_on = prev_wifi_on;
	mobile_ap_error_code_e ret;
	softap_settings_t *old_settings = _get_softap_settings();
	softap_settings_t new_settings;

	if (obj == NULL || ssid == NULL || !strlen(ssid)) {
		ERR("invalid parameters\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_WIFI))
		return MOBILE_AP_ERROR_NONE;

	ret = __update_softap_settings(&new_settings, ssid, key, hide_mode,
			(softap_security_type_e)security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("__update_softap_settings is failed\n");
		return ret;
	}

	if (__is_equal_softap_settings(&new_settings, old_settings) == TRUE) {
		DBG("No need to reload settings\n");
		return MOBILE_AP_ERROR_NONE;
	}

	prev_wifi_on = FALSE;
	ret = _disable_wifi_tethering(obj);

	prev_wifi_on = backup_prev_wifi_on;
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_disable_wifi_tethering is failed : %d\n", ret);
		return ret;
	}

	ret = _enable_wifi_tethering(obj, ssid, key, hide_mode,
			(softap_security_type_e)security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_enable_wifi_tethering is failed : %d\n", ret);
		return ret;
	}
	tethering_emit_wifi_on(obj);
	_create_tethering_active_noti();

	return MOBILE_AP_ERROR_NONE;
}

mobile_ap_error_code_e _reload_softap_settings_for_ap(Tethering *obj,
	gchar *ssid, gchar *key, gint hide_mode, gint security_type)
{
	gboolean backup_prev_wifi_on = prev_wifi_on;
	mobile_ap_error_code_e ret;
	softap_settings_t *old_settings = _get_softap_settings();
	softap_settings_t new_settings;

	if (obj == NULL || ssid == NULL || !strlen(ssid)) {
		ERR("invalid parameters\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	ret = __update_softap_settings(&new_settings, ssid, key, hide_mode,
			(softap_security_type_e)security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("__update_softap_settings is failed\n");
		return ret;
	}

	if (__is_equal_softap_settings(&new_settings, old_settings) == TRUE) {
		DBG("No need to reload settings\n");
		return MOBILE_AP_ERROR_NONE;
	}

	prev_wifi_on = FALSE;

	ret = _disable_wifi_ap(obj);
	prev_wifi_on = backup_prev_wifi_on;
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_disable_wifi_ap is failed : %d\n", ret);
		return ret;
	}

	ret = _enable_wifi_ap(obj, ssid, key, hide_mode,
			(softap_security_type_e)security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_enable_wifi_ap is failed : %d\n", ret);
		return ret;
	}

	return MOBILE_AP_ERROR_NONE;
}

int _get_wifi_name_from_lease_info(const char *mac, char **name_buf)
{
	if (mac == NULL || name_buf == NULL) {
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	GIOChannel *io = NULL;
	char *line = NULL;
	char *device_name = MOBILE_AP_NAME_UNKNOWN;
	char ip_addr[MOBILE_AP_STR_INFO_LEN] = {0, };
	char mac_addr[MOBILE_AP_STR_INFO_LEN] = {0, };
	char name[MOBILE_AP_STR_HOSTNAME_LEN] = {0, };
	char expire[MOBILE_AP_STR_INFO_LEN] = {0, };
	char extra[MOBILE_AP_STR_INFO_LEN] = {0, };

	io = g_io_channel_new_file(DNSMASQ_LEASES_FILE, "r", NULL);
	if (io == NULL) {
		return MOBILE_AP_ERROR_RESOURCE;
	}

	while (g_io_channel_read_line(io, &line, NULL, NULL, NULL) ==
			G_IO_STATUS_NORMAL) {
		sscanf(line, "%19s %19s %19s %19s %19s",
				expire, mac_addr, ip_addr, name, extra);
		g_free(line);

		if (g_ascii_strcasecmp(mac_addr, mac) == 0) {
			if (g_strcmp0(name, "*") != 0)
				device_name = name;
			break;
		}
	}
	g_io_channel_unref(io);

	*name_buf = g_strdup(device_name);

	return MOBILE_AP_ERROR_NONE;
}

mobile_ap_error_code_e _enable_wifi_tethering(Tethering *obj, gchar *ssid,
	gchar *passphrase, int hide_mode, softap_security_type_e security_type)
{
	mobile_ap_error_code_e ret;

	if (obj == NULL || ssid == NULL || !strlen(ssid)) {
		ERR("invalid parameters\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	if (security_type == SOFTAP_SECURITY_TYPE_WPA2_PSK && passphrase == NULL) {
		ERR("passphrase is null\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI_AP)) {
		ERR("Wi-Fi AP is already enabled\n");
		ret = MOBILE_AP_ERROR_RESOURCE;
		return ret;
	}

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI)) {
		ERR("Wi-Fi tethering is already enabled\n");
		ret = MOBILE_AP_ERROR_ALREADY_ENABLED;
		return ret;
	}

	/* Update global state */
	if (!_mobileap_set_state(MOBILE_AP_STATE_WIFI)) {
		ret = MOBILE_AP_ERROR_RESOURCE;
		return ret;
	}

	/* Update Wi-Fi hotspot data to global settings pointer */
	ret = __update_softap_settings(&obj_softap_settings, ssid, passphrase,
			hide_mode, security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		_mobileap_clear_state(MOBILE_AP_STATE_WIFI);
		return ret;
	}

	if (vconf_set_str(VCONFKEY_MOBILE_HOTSPOT_SSID,
			obj_softap_settings.ssid) < 0) {
		ERR("vconf_set_str is failed\n");
	}

	/* Initialize tethering */
	_block_device_sleep();
	ret = _init_tethering();
	if (ret != MOBILE_AP_ERROR_NONE) {
		_mobileap_clear_state(MOBILE_AP_STATE_WIFI);
		goto DONE;
	}

	/* Upload driver */
	ret = _mh_core_enable_softap(MOBILE_AP_TYPE_WIFI,
			obj_softap_settings.ssid,
			obj_softap_settings.security_type,
			obj_softap_settings.key,
			obj_softap_settings.hide_mode);
	if (ret != MOBILE_AP_ERROR_NONE) {
		_deinit_tethering();
		_mobileap_clear_state(MOBILE_AP_STATE_WIFI);
		goto DONE;
	}
	_delete_timeout_noti();

	_init_timeout_cb(MOBILE_AP_TYPE_WIFI, (void *)obj);
	_start_timeout_cb(MOBILE_AP_TYPE_WIFI, time(NULL) + TETHERING_CONN_TIMEOUT);

	_add_interface_routing(WIFI_IF, IP_ADDRESS_SOFTAP);
	_add_routing_rule(WIFI_IF);

DONE:
	_unblock_device_sleep();
	return ret;
}

mobile_ap_error_code_e _enable_wifi_ap(Tethering *obj,
					gchar *ssid, gchar *passphrase, int hide_mode,
					softap_security_type_e security_type)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	if (obj == NULL || ssid == NULL || !strlen(ssid)) {
		ERR("invalid parameters\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	if (security_type == SOFTAP_SECURITY_TYPE_WPA2_PSK &&
		(passphrase == NULL || strlen(passphrase) >= MOBILE_AP_WIFI_KEY_MAX_LEN)) {
		ERR("hex key length is not correct\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI | MOBILE_AP_STATE_BT
			| MOBILE_AP_STATE_USB)) {
		ERR("Tethering is already enabled\n");
		return MOBILE_AP_ERROR_RESOURCE;
	}

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI_AP)) {
		ERR("Wi-Fi AP is already enabled\n");
		return MOBILE_AP_ERROR_ALREADY_ENABLED;
	}

	if (!_mobileap_set_state(MOBILE_AP_STATE_WIFI_AP)) {
		return MOBILE_AP_ERROR_RESOURCE;
	}
	ret = __update_softap_settings(&obj_softap_settings, ssid, passphrase,
			hide_mode, security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		_mobileap_clear_state(MOBILE_AP_STATE_WIFI_AP);
		return ret;
	}

	_block_device_sleep();

	if (_init_tethering() != MOBILE_AP_ERROR_NONE) {
		_mobileap_clear_state(MOBILE_AP_STATE_WIFI_AP);
		ret = MOBILE_AP_ERROR_RESOURCE;
		goto DONE;
	}

	/* Upload driver */
	ret = _mh_core_enable_softap(MOBILE_AP_TYPE_WIFI_AP,
			obj_softap_settings.ssid,
			obj_softap_settings.security_type,
			obj_softap_settings.key,
			obj_softap_settings.hide_mode);
	if (ret != MOBILE_AP_ERROR_NONE) {
		_deinit_tethering();
		_mobileap_clear_state(MOBILE_AP_STATE_WIFI_AP);
		goto DONE;
	}

	_delete_timeout_noti();
	_init_timeout_cb(MOBILE_AP_TYPE_WIFI_AP, (void *)obj);
	_start_timeout_cb(MOBILE_AP_TYPE_WIFI_AP, time(NULL) + WIFI_AP_CONN_TIMEOUT);
	_add_interface_routing(WIFI_IF, IP_ADDRESS_SOFTAP);
	_add_routing_rule(WIFI_IF);

DONE:
	_unblock_device_sleep();
	return ret;
}

mobile_ap_error_code_e _disable_wifi_tethering(Tethering *obj)
{
	int ret;
	int state;
	mobile_ap_type_e type;

	type = MOBILE_AP_TYPE_WIFI;
	state = MOBILE_AP_STATE_WIFI;

	if (!_mobileap_is_enabled(state)) {
		ERR("Wi-Fi tethering ap has not been activated\n");
		ret = MOBILE_AP_ERROR_NOT_ENABLED;
		return ret;
	}

	_block_device_sleep();
	_del_routing_rule(WIFI_IF);
	_del_interface_routing(WIFI_IF, IP_ADDRESS_SOFTAP);
	_flush_ip_address(WIFI_IF);
	_deinit_timeout_cb(type);

	if (_remove_station_info_all(type) != MOBILE_AP_ERROR_NONE) {
		ERR("_remove_station_info_all is failed. Ignore it.\n");
	}

	ret = _mh_core_disable_softap();
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_mh_core_disable_softap is failed : %d\n", ret);
		goto DONE;
	}

	_deinit_tethering();
	_mobileap_clear_state(state);

	if (prev_wifi_on == TRUE) {
		DBG("Previous Wi-Fi was turned on. Recover it\n");
		if (__turn_on_wifi() != MOBILE_AP_ERROR_NONE) {
			ERR("__turn_on_wifi() is failed\n");
		}
		prev_wifi_on = FALSE;
	}
	DBG("_disable_wifi_tethering is done\n");

DONE:
	_unblock_device_sleep();
	return ret;
}

mobile_ap_error_code_e _disable_wifi_ap(Tethering *obj)
{
	int ret;
	int state;
	mobile_ap_type_e type;

	type = MOBILE_AP_TYPE_WIFI_AP;
	state = MOBILE_AP_STATE_WIFI_AP;

	if (!_mobileap_is_enabled(state)) {
		ERR("Wi-Fi ap tethering has not been activated\n");
		ret = MOBILE_AP_ERROR_NOT_ENABLED;
		return ret;
	}

	_block_device_sleep();
	_del_routing_rule(WIFI_IF);
	_del_interface_routing(WIFI_IF, IP_ADDRESS_SOFTAP);
	_flush_ip_address(WIFI_IF);
	_deinit_timeout_cb(type);

	if (_remove_station_info_all(type) != MOBILE_AP_ERROR_NONE) {
		ERR("_remove_station_info_all is failed. Ignore it.\n");
	}

	ret = _mh_core_disable_softap();
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_mh_core_disable_softap is failed : %d\n", ret);
		goto DONE;
	}

	_deinit_tethering();
	_mobileap_clear_state(state);

	DBG("_disable_wifi_ap is done\n");

DONE:
	_unblock_device_sleep();
	return ret;
}

gboolean tethering_enable_wifi_tethering(Tethering *obj,
		GDBusMethodInvocation *context, gchar *ssid,
		gchar *key, gint visibility, gint security_type)
{
	DBG("+\n");
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	gboolean ret_val = FALSE;
	bool wifi_state = false;
	g_assert(obj != NULL);
	g_assert(context != NULL);

	if (g_context) {
		DBG("It is turnning on\n");
		tethering_complete_enable_wifi_tethering(obj, g_context,
				MOBILE_AP_ERROR_IN_PROGRESS);
		return FALSE;
	}
	g_context = context;

	wifi_settings.ssid = g_strdup(ssid);
	if (security_type == SOFTAP_SECURITY_TYPE_WPA2_PSK) {
		wifi_settings.key = g_strdup(key);
		wifi_settings.security_type = SOFTAP_SECURITY_TYPE_WPA2_PSK;
	} else {
		wifi_settings.security_type = SOFTAP_SECURITY_TYPE_OPEN;
	}
	wifi_settings.hide_mode = (!visibility);

	if (wifi_recovery_timeout_id) {
		DBG("Wi-Fi recovery is cancelled\n");
		g_source_remove(wifi_recovery_timeout_id);
		wifi_recovery_timeout_id = 0;
		prev_wifi_on = TRUE;
	}

	if (__is_wifi_direct_on() == TRUE) {
		DBG("Wi-Fi and Wi-Fi direct are turned on\n");
		if (__turn_off_wifi_direct(obj) != MOBILE_AP_ERROR_NONE) {
			ERR("_turn_off_wifi_direct is failed\n");
			ret = MOBILE_AP_ERROR_INTERNAL;
			goto DONE;
		}

		return TRUE;
	}

	wifi_is_activated(&wifi_state);
	if (wifi_state == true) {
		DBG("Wi-Fi is turned on\n");
		if (__turn_off_wifi(obj) != MOBILE_AP_ERROR_NONE) {
			ERR("_turn_off_wifi is failed\n");
			ret = MOBILE_AP_ERROR_INTERNAL;
			goto DONE;
		}

		return TRUE;
	}

	ret = _enable_wifi_tethering(obj, ssid, key, !visibility,
			(softap_security_type_e)security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_enable_wifi_tethering is failed\n");
	} else {
		tethering_emit_wifi_on(obj);
		_create_tethering_active_noti();
		ret_val = TRUE;
	}

DONE:
	tethering_complete_enable_wifi_tethering(obj, g_context, ret);
	g_context = NULL;

	g_free(wifi_settings.ssid);
	g_free(wifi_settings.key);
	memset(&wifi_settings, 0, sizeof(wifi_settings));

	return ret_val;
}

gboolean tethering_disable_wifi_tethering(Tethering *obj,
		GDBusMethodInvocation *context)
{
	int ret = MOBILE_AP_ERROR_NONE;

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	ret = _disable_wifi_tethering(obj);

	tethering_emit_wifi_off(obj, NULL);
	tethering_complete_disable_wifi_tethering(obj, context,
			MOBILE_AP_DISABLE_WIFI_TETHERING_CFM, ret);


	if (ret != MOBILE_AP_ERROR_NONE)
		return FALSE;

	return TRUE;
}

gboolean tethering_enable_wifi_ap(Tethering *obj, GDBusMethodInvocation *context,
		gchar *ssid, gchar *key, gint visibility, gint security_type)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	gboolean ret_val = FALSE;

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	if (wifi_recovery_timeout_id) {
		DBG("Wi-Fi recovery is cancelled\n");
		g_source_remove(wifi_recovery_timeout_id);
		wifi_recovery_timeout_id = 0;
	}

	ret = _enable_wifi_ap(obj, ssid, key, !visibility,
	                (softap_security_type_e)security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_enable_wifi_tethering is failed\n");
	} else {
		tethering_emit_wifi_ap_on(obj);
		ret_val = TRUE;
	}
	tethering_complete_enable_wifi_ap(obj, context, ret);
	return ret_val;
}

gboolean tethering_disable_wifi_ap(Tethering *obj,
		GDBusMethodInvocation *context)
{
	int ret = MOBILE_AP_ERROR_NONE;

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	ret = _disable_wifi_ap(obj);
	tethering_emit_wifi_ap_off(obj, NULL);
	tethering_complete_disable_wifi_ap(obj, g_context,
			MOBILE_AP_ENABLE_WIFI_AP_CFM, ret);

	if (ret != MOBILE_AP_ERROR_NONE)
		return FALSE;

	return TRUE;
}

gboolean tethering_reload_wifi_settings(Tethering *obj,
		GDBusMethodInvocation *context, gchar *ssid,
		gchar *key, gint visibility, gint security_type)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	gboolean ret_val = TRUE;

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	ret = _reload_softap_settings(obj, ssid, key, !visibility, security_type);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_reload_softap_settings is failed\n");
		ret_val = FALSE;
	}

	tethering_complete_reload_wifi_settings(obj, context, ret);

	return ret_val;
}

gboolean tethering_reload_wifi_ap_settings(Tethering *obj,
		GDBusMethodInvocation *context, gchar *ssid,
	gchar *key, gint visibility, gint security)
{

	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	gboolean ret_val = TRUE;

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	ret = _reload_softap_settings_for_ap(obj, ssid, key, !visibility, security);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_reload_softap_settings_for_ap is failed\n");
		ret_val = FALSE;
	}

	tethering_complete_reload_wifi_ap_settings(obj, context, ret);
	return ret_val;
}

gboolean _is_trying_wifi_operation(void)
{
	return (g_context || wifi_recovery_timeout_id ? TRUE : FALSE);
}
