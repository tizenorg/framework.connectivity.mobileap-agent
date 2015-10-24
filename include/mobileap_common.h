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

#ifndef __MOBILEAP_COMMON_H__
#define __MOBILEAP_COMMON_H__

#include <glib.h>
#include <gio/gio.h>

#include "mobileap_softap.h"
#include <tethering-server-stub.h>

gint _slist_find_station_by_interface(gconstpointer a, gconstpointer b);
gint _slist_find_station_by_mac(gconstpointer a, gconstpointer b);
gint _slist_find_station_by_ip_addr(gconstpointer a, gconstpointer b);

void _send_dbus_station_info(const char *member,
		mobile_ap_station_info_t *info);
void _update_station_count(int count);
int _add_station_info(mobile_ap_station_info_t *info);
int _remove_station_info(gconstpointer data, GCompareFunc func);
int _remove_station_info_all(mobile_ap_type_e type);
int _get_station_info(gconstpointer data, GCompareFunc func,
		mobile_ap_station_info_t **si);
int _get_station_count(gconstpointer data, GCompareFunc func, int *count);
GVariant *_station_info_foreach(void);
int _add_interface_routing(const char *interface, const in_addr_t gateway);
int _del_interface_routing(const char *interface, const in_addr_t gateway);
int _add_routing_rule(const char *interface);
int _del_routing_rule(const char *interface);
int _flush_ip_address(const char *interface);
int _execute_command(const char *cmd);
int _get_tethering_type_from_ip(const char *ip, mobile_ap_type_e *type);
Tethering *_get_tethering_obj(void);
#endif /* __MOBILEAP_COMMON_H__ */
