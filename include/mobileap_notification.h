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

#ifndef __MOBILEAP_NOTIFICATION_H__
#define __MOBILEAP_NOTIFICATION_H__

#include <appcore-common.h>
#include <notification.h>

#define MH_NOTI_STR_MAX			50
#define MH_NOTI_PATH_MAX		256

#define MH_NOTI_ICON_PATH		"/usr/ug/res/images/ug-setting-mobileap-efl"
#define MH_NOTI_ICON_BT			MH_NOTI_ICON_PATH"/noti_tethering_bluetooth.png"
#define MH_NOTI_ICON_GENERAL		MH_NOTI_ICON_PATH"/noti_tethering_general.png"
#define MH_NOTI_ICON_USB		MH_NOTI_ICON_PATH"/noti_tethering_usb.png"
#define MH_NOTI_ICON_WIFI		MH_NOTI_ICON_PATH"/noti_tethering_wifi_num.png"
#define MH_NOTI_ICON_WIFI_PD		MH_NOTI_ICON_PATH"/noti_tethering_wifi_num_%02d.png"

#define MOBILEAP_LOCALE_COMMON_PKG	"ug-setting-mobileap-efl"
#define MOBILEAP_LOCALE_COMMON_RES	"/usr/ug/res/locale"

#ifdef _
#undef _
#endif
#define _(str)				dgettext(MOBILEAP_LOCALE_COMMON_PKG, str)

#define MH_STR_TETHERING			"IDS_MOBILEAP_BODY_TETHERING"
#define MH_STR_CONNECTED_DEV		"IDS_MOBILEAP_POP_CONNECTED_DEVICES_C_PD"
#define MH_STR_CONNECTION_TIMEOUT		"IDS_ST_BODY_CONNECTION_TIMEOUT"
#define MH_STR_CONFIGURE_TETHERING	"IDS_MOBILEAP_BODY_TAP_TO_CONFIGURE_TETHERING"
#define MH_STR_TETHERING_ACTIVE	_("IDS_MOBILEAP_BODY_TETHERING_ACTIVE_ABB")
#define MH_STR_BT_VISIBILITY	_("IDS_ST_BODY_BLUETOOTH_VISIBILITY_HAS_TIMED_OUT_YOUR_DEVICE_MIGHT_NOT_BE_FOUND")

int _create_timeout_noti(const char *icon_path);
int _delete_timeout_noti(void);
int _create_connected_noti(int count, const char *icon_path);
int _update_connected_noti(int count, const char *icon_path);
int _delete_connected_noti(void);
void _create_tethering_active_noti(void);
void _create_bt_tethering_active_noti(void);
#endif
