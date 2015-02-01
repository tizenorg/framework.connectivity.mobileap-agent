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

#ifndef __MOBILEAP_WIFI_H__
#define __MOBILEAP_WIFI_H__

#include "mobileap_softap.h"

#define VCONFKEY_MOBILE_HOTSPOT_SSID		"memory/private/mobileap-agent/ssid"
#define SOFTAP_SECURITY_TYPE_OPEN_STR		"open"
#define SOFTAP_SECURITY_TYPE_WPA2_PSK_STR	"wpa2-psk"
#define SOFTAP_PASSPHRASE_PATH			"wifi_tethering.txt"
#define SOFTAP_PASSPHRASE_GROUP_ID		"secure-storage::tethering"

typedef enum {
	SOFTAP_SECURITY_TYPE_OPEN,
	SOFTAP_SECURITY_TYPE_WPA2_PSK,
} softap_security_type_e;

typedef struct {
	int hide_mode;
	char *ssid;
	char *key;
	softap_security_type_e security_type;
} wifi_saved_settings;

int _get_wifi_name_from_lease_info(const char *mac, char **name_buf);
void _add_wifi_device_to_array(softap_device_info_t *di, GPtrArray *array);
mobile_ap_error_code_e _enable_wifi_tethering(TetheringObject *obj, gchar *ssid,
	gchar *passphrase, int hide_mode, softap_security_type_e security_type);
mobile_ap_error_code_e _disable_wifi_tethering(TetheringObject *obj);
gboolean _is_trying_wifi_operation(void);
mobile_ap_error_code_e _reload_softap_settings(TetheringObject *obj,
		gchar *ssid, gchar *key, gint hide_mode, gint security_type);
mobile_ap_error_code_e _reload_softap_settings_for_ap(TetheringObject *obj,
	gchar *ssid, gchar *key, gint hide_mode, gint security_type);

/* Dbus method */
mobile_ap_error_code_e _enable_wifi_ap(TetheringObject *obj, gchar *ssid,
		gchar *passphrase, int hide_mode,
                softap_security_type_e security_type);
mobile_ap_error_code_e _disable_wifi_ap(TetheringObject *obj);
gboolean tethering_enable_wifi_tethering(TetheringObject *obj, gchar *ssid,
		gchar *key, gint hide_mode, gint security_type,
		DBusGMethodInvocation *context);

gboolean tethering_disable_wifi_tethering(TetheringObject *obj,
		DBusGMethodInvocation *context);

gboolean tethering_reload_wifi_settings(TetheringObject *obj, gchar *ssid,
		gchar *key, gint visibility, gint security_type,
		DBusGMethodInvocation *context);

gboolean tethering_reload_wifi_ap_settings(TetheringObject *obj, gchar *ssid,
                gchar *key, gint hide_mode,
                gint security, DBusGMethodInvocation *context);

gboolean tethering_enable_wifi_ap(TetheringObject *obj, gchar *ssid,
		gchar *key, gint hide_mode, gint security_type,
		DBusGMethodInvocation *context);

gboolean tethering_disable_wifi_ap(TetheringObject *obj,
		DBusGMethodInvocation *context);
#endif /* __MOBILEAP_WIFI_H__ */
