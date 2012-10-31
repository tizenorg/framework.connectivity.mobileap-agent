/*
 * mobileap-agent
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Hocheol Seo <hocheol.seo@samsung.com>,
 *          Injun Yang <injun.yang@samsung.com>,
 *          Seungyoun Ju <sy39.ju@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
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
mobile_ap_error_code_e _disable_wifi_tethering(MobileAPObject *obj);

/* Dbus method */
gboolean mobileap_enable_wifi_tethering(MobileAPObject *obj, gchar *ssid,
		gchar *key, gint hide_mode,
		DBusGMethodInvocation *context);

gboolean mobileap_disable_wifi_tethering(MobileAPObject *obj,
		DBusGMethodInvocation *context);

gboolean mobileap_get_wifi_tethering_hide_mode(MobileAPObject *obj,
		DBusGMethodInvocation *context);

gboolean mobileap_set_wifi_tethering_hide_mode(MobileAPObject *obj,
		gint hide_mode, DBusGMethodInvocation *context);

gboolean mobileap_get_wifi_tethering_ssid(MobileAPObject *obj,
		DBusGMethodInvocation *context);

gboolean mobileap_get_wifi_tethering_security_type(MobileAPObject *obj,
		DBusGMethodInvocation *context);

gboolean mobileap_set_wifi_tethering_security_type(MobileAPObject *obj,
		gchar *security_type, DBusGMethodInvocation *context);

gboolean mobileap_get_wifi_tethering_passphrase(MobileAPObject *obj,
		DBusGMethodInvocation *context);

gboolean mobileap_set_wifi_tethering_passphrase(MobileAPObject *obj,
		gchar *passphrase, guint len, DBusGMethodInvocation *context);
#endif /* __MOBILEAP_WIFI_H__ */
