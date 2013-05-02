/*
 *  mobile-agent
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

#ifndef __MOBILEAP_USB_H__
#define __MOBILEAP_USB_H__

#include "mobileap_agent.h"


mobile_ap_error_code_e _disable_usb_tethering(TetheringObject *obj);

gboolean tethering_enable_usb_tethering(TetheringObject *obj,
						DBusGMethodInvocation *context);
gboolean tethering_disable_usb_tethering(TetheringObject *obj,
						DBusGMethodInvocation *context);
gboolean tethering_get_usb_station_info(TetheringObject *obj,
						DBusGMethodInvocation *context);
gboolean tethering_get_usb_interface_info(TetheringObject *obj,
						DBusGMethodInvocation *context);
#endif /* __MOBILEAP_USB_H__ */
