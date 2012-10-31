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

#ifndef __MOBILEAP_BLUETOOTH_H__
#define __MOBILEAP_BLUETOOTH_H__

#include "mobileap_agent.h"

void _bt_get_remote_device_name(MobileAPObject *obj, const char *mac, char **name);
mobile_ap_error_code_e _disable_bt_tethering(MobileAPObject *obj);

gboolean mobileap_enable_bt_tethering(MobileAPObject *obj,
		DBusGMethodInvocation *context);
gboolean mobileap_disable_bt_tethering(MobileAPObject *obj,
		DBusGMethodInvocation *context);

#endif
