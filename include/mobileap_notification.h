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

#include <notification.h>

#define MH_NOTI_STR_MAX		50
#define MH_NOTI_ICON_PATH	"/usr/apps/org.tizen.tethering/res/images/Q02_Notification_MobileAP.png"

int _create_timeout_noti(const char *content, const char *title,
		const char *icon_path);

int _create_connected_noti(const char *content, const char *title,
		const char *icon_path);
int _update_connected_noti(const char *content);
int _delete_connected_noti(void);

#endif