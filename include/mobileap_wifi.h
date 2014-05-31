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

#include "mobileap_agent.h"

#define SOFTAP_SECURITY_TYPE_OPEN_STR		"open"
#define SOFTAP_SECURITY_TYPE_WPA2_PSK_STR	"wpa2-psk"
#define SOFTAP_PASSPHRASE_PATH			"wifi_tethering.txt"

typedef enum {
	SOFTAP_SECURITY_TYPE_OPEN,
	SOFTAP_SECURITY_TYPE_WPA2_PSK,
} softap_security_type_e;

void _register_wifi_station_handler(void);
void _add_wifi_device_to_array(softap_device_info_t *di, GPtrArray *array);
mobile_ap_error_code_e _disable_wifi_tethering(TetheringObject *obj);

/* Dbus method */
gboolean tethering_enable_wifi_tethering(TetheringObject *obj, gchar *ssid,
		gchar *key, gint hide_mode,
		DBusGMethodInvocation *context);

gboolean tethering_disable_wifi_tethering(TetheringObject *obj,
		DBusGMethodInvocation *context);

gboolean tethering_get_wifi_tethering_hide_mode(TetheringObject *obj,
		DBusGMethodInvocation *context);

gboolean tethering_set_wifi_tethering_hide_mode(TetheringObject *obj,
		gint hide_mode, DBusGMethodInvocation *context);

gboolean tethering_get_wifi_tethering_ssid(TetheringObject *obj,
		DBusGMethodInvocation *context);

gboolean tethering_get_wifi_tethering_security_type(TetheringObject *obj,
		DBusGMethodInvocation *context);

gboolean tethering_set_wifi_tethering_security_type(TetheringObject *obj,
		gchar *security_type, DBusGMethodInvocation *context);

gboolean tethering_get_wifi_tethering_passphrase(TetheringObject *obj,
		DBusGMethodInvocation *context);

gboolean tethering_set_wifi_tethering_passphrase(TetheringObject *obj,
		gchar *passphrase, guint len, DBusGMethodInvocation *context);
#endif /* __MOBILEAP_WIFI_H__ */
