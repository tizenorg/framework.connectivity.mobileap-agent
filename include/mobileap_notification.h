/*
 *  mobileap-agent
 *
 * Copyright 2012-2013  Samsung Electronics Co., Ltd
 *
 * Licensed under the Flora License, Version 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://floralicense.org/license
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __MOBILEAP_NOTIFICATION_H__
#define __MOBILEAP_NOTIFICATION_H__

#include <notification.h>

#define MH_NOTI_STR_MAX		50
#define MH_NOTI_ICON_PATH	"/usr/ug/res/images/ug-setting-mobileap-efl/tethering.png"

int _create_timeout_noti(const char *content, const char *title,
		const char *icon_path);
int _delete_timeout_noti(void);
int _create_connected_noti(const char *content, const char *title,
		const char *icon_path);
int _update_connected_noti(const char *content);
int _delete_connected_noti(void);
int _create_status_noti(const char *content);
#endif
