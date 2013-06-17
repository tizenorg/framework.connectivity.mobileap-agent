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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ss_manager.h>

#include "mobileap_agent.h"
#include "mobileap_common.h"
#include "mobileap_wifi.h"
#include "mobileap_handler.h"
#include "mobileap_notification.h"

static int __generate_initial_passphrase(char *passphrase_buf);
static mobile_ap_error_code_e __get_hide_mode(int *hide_mode);
static mobile_ap_error_code_e __set_hide_mode(const int hide_mode);
static mobile_ap_error_code_e __get_common_ssid(char *ssid, unsigned int size);
static mobile_ap_error_code_e __get_security_type(char *security_type, unsigned int len);
static mobile_ap_error_code_e __set_security_type(const char *security_type);
static mobile_ap_error_code_e __get_passphrase(char *passphrase, unsigned int size, unsigned int *passphrase_len);
static mobile_ap_error_code_e __set_passphrase(const char *passphrase, const unsigned int size);
static gboolean __send_station_event_cb(gpointer data);
static void __handle_station_signal(int sig);
static mobile_ap_error_code_e __update_wifi_data(TetheringObject *obj);

static int __generate_initial_passphrase(char *passphrase_buf)
{
	DBG("+\n");

	guint32 rand_int;
	int index;

	for (index = 0; index < MOBILE_AP_WIFI_KEY_MIN_LEN; index++) {
		rand_int = g_random_int_range('a', 'z');
		passphrase_buf[index] = rand_int;
	}
	passphrase_buf[index] = '\0';

	return index;
}

static mobile_ap_error_code_e __get_hide_mode(int *hide_mode)
{
	if (hide_mode == NULL) {
		ERR("Invalid param\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	if (vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_HIDE, hide_mode) < 0) {
		ERR("vconf_get_int is failed\n");
		return MOBILE_AP_ERROR_RESOURCE;
	}

	return MOBILE_AP_ERROR_NONE;
}

static mobile_ap_error_code_e __set_hide_mode(const int hide_mode)
{
	if (vconf_set_int(VCONFKEY_MOBILE_HOTSPOT_HIDE, hide_mode) < 0) {
		ERR("vconf_set_int is failed\n");
		return MOBILE_AP_ERROR_RESOURCE;
	}

	return MOBILE_AP_ERROR_NONE;
}

static mobile_ap_error_code_e __get_common_ssid(char *ssid, unsigned int size)
{
	if (ssid == NULL)
		return MOBILE_AP_ERROR_INVALID_PARAM;

	char *ptr = NULL;
	char *ptr_tmp = NULL;

	ptr = vconf_get_str(VCONFKEY_SETAPPL_DEVICE_NAME_STR);
	if (ptr == NULL)
		return MOBILE_AP_ERROR_RESOURCE;

	if (!g_utf8_validate(ptr, -1, (const char **)&ptr_tmp))
		*ptr_tmp = '\0';

	g_strlcpy(ssid, ptr, size);
	free(ptr);

	return MOBILE_AP_ERROR_NONE;
}

static mobile_ap_error_code_e __get_security_type(char *security_type, unsigned int len)
{
	if (security_type == NULL)
		return MOBILE_AP_ERROR_INVALID_PARAM;

	char *type_str = NULL;
	softap_security_type_e type;

	if (vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_SECURITY, (int *)&type) < 0) {
		ERR("vconf_get_int is failed\n");
		return MOBILE_AP_ERROR_RESOURCE;
	}

	switch (type) {
	case SOFTAP_SECURITY_TYPE_OPEN:
		type_str = SOFTAP_SECURITY_TYPE_OPEN_STR;
		break;

	case SOFTAP_SECURITY_TYPE_WPA2_PSK:
		type_str = SOFTAP_SECURITY_TYPE_WPA2_PSK_STR;
		break;

	default:
		ERR("Invalid data\n");
		return MOBILE_AP_ERROR_RESOURCE;
	}

	g_strlcpy(security_type, type_str, len);

	return MOBILE_AP_ERROR_NONE;
}

static mobile_ap_error_code_e __set_security_type(const char *security_type)
{
	if (security_type == NULL) {
		ERR("Invalid param\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	softap_security_type_e type;

	if (!strcmp(security_type, SOFTAP_SECURITY_TYPE_OPEN_STR)) {
		type = SOFTAP_SECURITY_TYPE_OPEN;
	} else if (!strcmp(security_type, SOFTAP_SECURITY_TYPE_WPA2_PSK_STR)) {
		type = SOFTAP_SECURITY_TYPE_WPA2_PSK;
	} else {
		ERR("Invalid param\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	if (vconf_set_int(VCONFKEY_MOBILE_HOTSPOT_SECURITY, type) < 0) {
		ERR("vconf_set_int is failed\n");
		return MOBILE_AP_ERROR_RESOURCE;
	}

	return MOBILE_AP_ERROR_NONE;
}

static mobile_ap_error_code_e __get_passphrase(char *passphrase,
		unsigned int size, unsigned int *passphrase_len)
{
	if (passphrase == NULL || passphrase_len == NULL) {
		ERR("Invalid parameter\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	int ret = 0;
	ssm_file_info_t sfi;

	ret = ssm_getinfo(SOFTAP_PASSPHRASE_PATH, &sfi,
			SSM_FLAG_SECRET_OPERATION, NULL);
	if (ret == -SS_FILE_OPEN_ERROR) {
		*passphrase_len = __generate_initial_passphrase(passphrase);

		ret = __set_passphrase(passphrase, *passphrase_len);
		if (ret != MOBILE_AP_ERROR_NONE) {
			memset(passphrase, 0x00, size);
			*passphrase_len = 0;
			return ret;
		}

		ret = ssm_getinfo(SOFTAP_PASSPHRASE_PATH, &sfi,
				SSM_FLAG_SECRET_OPERATION, NULL);
		if (ret < 0) {
			ERR("ssm_getinfo is failed : %d\n", ret);
			memset(passphrase, 0x00, size);
			*passphrase_len = 0;
			return MOBILE_AP_ERROR_RESOURCE;
		}
	} else if (ret < 0) {
		ERR("ssm_getinfo is failed : %d\n", ret);
		return MOBILE_AP_ERROR_RESOURCE;
	}

	memset(passphrase, 0x00, size);
	ret = ssm_read(SOFTAP_PASSPHRASE_PATH, passphrase, sfi.originSize,
			passphrase_len, SSM_FLAG_SECRET_OPERATION, NULL);
	if (ret < 0) {
		ERR("ssm_read is failed : %d\n", ret);
		return MOBILE_AP_ERROR_RESOURCE;
	}

	return MOBILE_AP_ERROR_NONE;
}

static mobile_ap_error_code_e __set_passphrase(const char *passphrase, const unsigned int size)
{
	if (size < MOBILE_AP_WIFI_KEY_MIN_LEN || size > MOBILE_AP_WIFI_KEY_MAX_LEN ||
			passphrase == NULL) {
		ERR("Invalid parameter\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	int ret = 0;

	ret = ssm_write_buffer((char *)passphrase, size, SOFTAP_PASSPHRASE_PATH,
			SSM_FLAG_SECRET_OPERATION, NULL);
	if (ret < 0) {
		ERR("ssm_write_buffer is failed : %d\n", ret);
		return MOBILE_AP_ERROR_RESOURCE;
	}

	return MOBILE_AP_ERROR_NONE;
}

static gboolean __send_station_event_cb(gpointer data)
{
	int sig = GPOINTER_TO_INT(data);
	int n_station = 0;
	mobile_ap_station_info_t *si = NULL;

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_WIFI)) {
		return FALSE;
	}

	if (sig == SIGUSR1) {
		DBG("STA connected(%d)\n", sig);
		/* STA connection is handled in the dnsmasq signal handler */
	} else if (sig == SIGUSR2) {
		DBG("STA disconnected(%d)\n", sig);

		/* Temporarily care only one station.
		 * Driver team should be support detail information */
		if (_get_station_info(MOBILE_AP_TYPE_WIFI,
				_slist_find_station_by_interface,
				&si) != MOBILE_AP_ERROR_NONE) {
			return FALSE;
		}
		_remove_station_info(si->mac, _slist_find_station_by_mac);

		_get_station_count((gconstpointer)MOBILE_AP_TYPE_WIFI,
				_slist_find_station_by_interface, &n_station);
		if (n_station == 0)
			_start_timeout_cb(MOBILE_AP_TYPE_WIFI);
	}

	return FALSE;
}

static void __handle_station_signal(int sig)
{
	g_idle_add(__send_station_event_cb, GINT_TO_POINTER(sig));
	return;
}

void _register_wifi_station_handler(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = __handle_station_signal;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
}

void _add_wifi_device_to_array(softap_device_info_t *di, GPtrArray *array)
{
	int i = 0;
	GIOChannel *io = NULL;
	gchar *line = NULL;
	gchar *device_name = NULL;
	gchar ip_addr[MOBILE_AP_STR_INFO_LEN] = {0, };
	gchar mac_addr[MOBILE_AP_STR_INFO_LEN] = {0, };
	gchar name[MOBILE_AP_STR_HOSTNAME_LEN] = {0, };
	gchar expire[MOBILE_AP_STR_INFO_LEN] = {0, };
	gchar extra[MOBILE_AP_STR_INFO_LEN] = {0, };

	int found = 0;

	for (i = 0; i < di->number; i++)
		DBG("bssid[%d]:%s\n", i, di->bssid[i]);

	DBG("Number of connected device:%d\n", di->number);

	io = g_io_channel_new_file(DNSMASQ_LEASES_FILE, "r", NULL);

	while (g_io_channel_read_line(io, &line, NULL, NULL, NULL) ==
							G_IO_STATUS_NORMAL) {
		sscanf(line, "%19s %19s %19s %19s %19s", expire, mac_addr,
							ip_addr, name, extra);
		DBG("mac_addr:%s ip_addr:%s name:%s expire:%s\n", mac_addr,
							ip_addr, name, expire);

		for (i = 0; i < di->number; i++) {
			if (g_ascii_strcasecmp(di->bssid[i], mac_addr) == 0) {
				if (!strcmp(name, "*"))
					device_name = MOBILE_AP_NAME_UNKNOWN;
				else
					device_name = name;

				_mh_core_add_data_to_array(array, MOBILE_AP_TYPE_WIFI,
								device_name);

				found++;

				break;
			}
		}

		g_free(line);
	}
	g_io_channel_unref(io);

	/* Set the name UNKNOWN unless we got the name. */
	for (i = found; i < di->number; i++) {
		_mh_core_add_data_to_array(array, MOBILE_AP_TYPE_WIFI,
							MOBILE_AP_NAME_UNKNOWN);
	}
}

mobile_ap_error_code_e _enable_wifi_tethering(TetheringObject *obj, gchar *ssid)
{
	mobile_ap_error_code_e ret;

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

	/* Update Wi-Fi hotspot data to common object */
	ret = __update_wifi_data(obj);
	if (ret != MOBILE_AP_ERROR_NONE) {
		_mobileap_clear_state(MOBILE_AP_STATE_WIFI);
		return ret;
	}

	if (ssid != NULL && strlen(ssid) > 0) {
		DBG("Private(Passed) SSID is used : %s\n", ssid);
		g_strlcpy(obj->ssid, ssid, sizeof(obj->ssid));
	}

	/* Initialize tethering */
	if (!_init_tethering(obj)) {
		_mobileap_clear_state(MOBILE_AP_STATE_WIFI);
		ret = MOBILE_AP_ERROR_RESOURCE;
		return ret;
	}

	/* Upload driver */
	ret = _mh_core_enable_softap(obj->ssid, obj->security_type,
			obj->key, obj->hide_mode);
	if (ret != MOBILE_AP_ERROR_NONE) {
		_deinit_tethering(obj);
		_mobileap_clear_state(MOBILE_AP_STATE_WIFI);
		return ret;
	}

	_delete_timeout_noti();
	_init_timeout_cb(MOBILE_AP_TYPE_WIFI, (void *)obj);
	_start_timeout_cb(MOBILE_AP_TYPE_WIFI);

	return MOBILE_AP_ERROR_NONE;
}

mobile_ap_error_code_e _disable_wifi_tethering(TetheringObject *obj)
{
	int ret = MOBILE_AP_ERROR_NONE;

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_WIFI)) {
		ERR("Wi-Fi tethering has not been activated\n");
		ret = MOBILE_AP_ERROR_NOT_ENABLED;
		return ret;
	}

	_deinit_timeout_cb(MOBILE_AP_TYPE_WIFI);

	if (_remove_station_info_all(MOBILE_AP_TYPE_WIFI) !=
			MOBILE_AP_ERROR_NONE) {
		ERR("_remove_station_info_all is failed. Ignore it.\n");
	}

	ret = _mh_core_disable_softap();
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_mh_core_disable_softap is failed : %d\n", ret);
		return ret;
	}

	_deinit_tethering(obj);
	_mobileap_clear_state(MOBILE_AP_STATE_WIFI);

	DBG("_disable_wifi_tethering is done\n");

	return ret;
}

static mobile_ap_error_code_e __update_wifi_data(TetheringObject *obj)
{
	if (obj == NULL) {
		ERR("Invalid param\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	unsigned int read_len = 0;

	ret = __get_common_ssid(obj->ssid, sizeof(obj->ssid));
	if (ret != MOBILE_AP_ERROR_NONE)
		return ret;

	ret = __get_security_type(obj->security_type, sizeof(obj->security_type));
	if (ret != MOBILE_AP_ERROR_NONE)
		return ret;

	ret = __get_hide_mode(&obj->hide_mode);
	if (ret != MOBILE_AP_ERROR_NONE)
		return ret;

	if (strcmp(obj->security_type, SOFTAP_SECURITY_TYPE_OPEN_STR) == 0) {
		g_strlcpy(obj->key, "00000000", sizeof(obj->key));
	} else if (strcmp(obj->security_type, SOFTAP_SECURITY_TYPE_WPA2_PSK_STR) == 0) {
		ret = __get_passphrase(obj->key, sizeof(obj->key), &read_len);
		if (ret != MOBILE_AP_ERROR_NONE)
			return ret;
	} else {
		ERR("Unknown security type\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	DBG("ssid : %s security type : %s hide mode : %d\n",
			obj->ssid, obj->security_type, obj->hide_mode);

	return MOBILE_AP_ERROR_NONE;
}

gboolean tethering_enable_wifi_tethering(TetheringObject *obj, gchar *ssid,
		gchar *key, gint hide_mode, DBusGMethodInvocation *context)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	gboolean ret_val = FALSE;

	g_assert(obj != NULL);
	g_assert(context != NULL);


	ret = _enable_wifi_tethering(obj, ssid);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_enable_wifi_tethering is failed\n");
	} else {
		_emit_mobileap_dbus_signal(obj, E_SIGNAL_WIFI_TETHER_ON, NULL);
		ret_val = TRUE;
	}

	dbus_g_method_return(context, MOBILE_AP_ENABLE_WIFI_TETHERING_CFM, ret);

	return ret_val;
}


gboolean tethering_disable_wifi_tethering(TetheringObject *obj,
		DBusGMethodInvocation *context)
{
	int ret = MOBILE_AP_ERROR_NONE;

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	ret = _disable_wifi_tethering(obj);

	_emit_mobileap_dbus_signal(obj, E_SIGNAL_WIFI_TETHER_OFF, NULL);
	dbus_g_method_return(context, MOBILE_AP_DISABLE_WIFI_TETHERING_CFM, ret);

	if (ret != MOBILE_AP_ERROR_NONE)
		return FALSE;

	return TRUE;
}

gboolean tethering_get_wifi_tethering_hide_mode(TetheringObject *obj,
		DBusGMethodInvocation *context)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	int hide_mode = 0;

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	ret = __get_hide_mode(&hide_mode);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("__get_hide_mode is failed : %d\n", ret);
	}

	dbus_g_method_return(context, hide_mode);

	return TRUE;
}

gboolean tethering_set_wifi_tethering_hide_mode(TetheringObject *obj,
		gint hide_mode, DBusGMethodInvocation *context)
{
	int ret = 0;

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	int old_hide_mode;

	ret = __get_hide_mode(&old_hide_mode);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("__get_hide_mode is failed : %d\n", ret);
	} else if (old_hide_mode == hide_mode) {
		DBG("old_hide_mode == hide_mode\n");
		dbus_g_method_return(context);
		return TRUE;
	}

	ret = __set_hide_mode(hide_mode);
	if (ret < 0) {
		ERR("__set_hide_mode is failed : %d\n", ret);
	}

	_emit_mobileap_dbus_signal(obj, E_SIGNAL_SSID_VISIBILITY_CHANGED,
			hide_mode == VCONFKEY_MOBILE_AP_HIDE_OFF ?
			SIGNAL_MSG_SSID_VISIBLE :
			SIGNAL_MSG_SSID_HIDE);
	dbus_g_method_return(context);

	return TRUE;
}

gboolean tethering_get_wifi_tethering_ssid(TetheringObject *obj,
		DBusGMethodInvocation *context)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	char ssid[MOBILE_AP_WIFI_SSID_MAX_LEN + 1] = {0, };

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI)) {
		g_strlcpy(ssid, obj->ssid, sizeof(ssid));
	} else {
		ret = __get_common_ssid(ssid, sizeof(ssid));
		if (ret != MOBILE_AP_ERROR_NONE) {
			ERR("__get_common_ssid is failed : %d\n", ret);
		}
	}

	dbus_g_method_return(context, ssid);

	return TRUE;
}

gboolean tethering_get_wifi_tethering_security_type(TetheringObject *obj,
		DBusGMethodInvocation *context)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	char security_type[SECURITY_TYPE_LEN] = {0, };

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	ret = __get_security_type(security_type, sizeof(security_type));
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("__get_security_type is failed : %d\n", ret);
	}

	dbus_g_method_return(context, security_type);

	return TRUE;
}

gboolean tethering_set_wifi_tethering_security_type(TetheringObject *obj,
		gchar *security_type, DBusGMethodInvocation *context)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	char old_security_type[SECURITY_TYPE_LEN] = {0, };

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	ret = __get_security_type(old_security_type, sizeof(old_security_type));
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("__get_security_type is failed : %d\n", ret);
	} else if (g_strcmp0(old_security_type, security_type) == 0) {
		DBG("old_security_type == security_type\n");
		dbus_g_method_return(context);
		return TRUE;
	}

	ret = __set_security_type(security_type);
	if (ret < 0) {
		ERR("__set_security_type is failed: %d\n", ret);
	}

	_emit_mobileap_dbus_signal(obj, E_SIGNAL_SECURITY_TYPE_CHANGED,
			security_type);
	dbus_g_method_return(context);

	return TRUE;
}

gboolean tethering_get_wifi_tethering_passphrase(TetheringObject *obj,
		DBusGMethodInvocation *context)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	char passphrase[MOBILE_AP_WIFI_KEY_MAX_LEN + 1] = {0, };
	unsigned int len = 0;

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	ret = __get_passphrase(passphrase, sizeof(passphrase), &len);
	if (ret != MOBILE_AP_ERROR_NONE) {
		len = 0;
		ERR("__get_password is failed : %d\n", ret);
	}

	dbus_g_method_return(context, passphrase, len);

	return TRUE;
}

gboolean tethering_set_wifi_tethering_passphrase(TetheringObject *obj,
		gchar *passphrase, guint len, DBusGMethodInvocation *context)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	char old_passphrase[MOBILE_AP_WIFI_KEY_MAX_LEN + 1] = {0, };
	unsigned int old_len = 0;

	DBG("+\n");
	g_assert(obj != NULL);
	g_assert(context != NULL);

	ret = __get_passphrase(old_passphrase, sizeof(old_passphrase), &old_len);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("__get_passphrase is failed : %d\n", ret);
	} else if (old_len == len && !g_strcmp0(old_passphrase, passphrase)) {
		dbus_g_method_return(context);
		return TRUE;
	}

	ret = __set_passphrase(passphrase, len);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("__set_passphrase is failed : %d\n", ret);
	}

	_emit_mobileap_dbus_signal(obj, E_SIGNAL_PASSPHRASE_CHANGED, NULL);
	dbus_g_method_return(context);

	return TRUE;
}
