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

#include "mobileap_agent.h"

/* Need translation */
#define MH_NOTI_STR	"Connected device (%d)"
#define MH_NOTI_TITLE	"Tethering"

gint _slist_find_station_by_interface(gconstpointer a, gconstpointer b);
gint _slist_find_station_by_mac(gconstpointer a, gconstpointer b);
gint _slist_find_station_by_ip_addr(gconstpointer a, gconstpointer b);

void _emit_mobileap_dbus_signal(TetheringObject *obj,
		mobile_ap_sig_e num, const gchar *message);
void _send_dbus_station_info(const char *member,
		mobile_ap_station_info_t *info);
void _update_station_count(int count);
int _add_station_info(mobile_ap_station_info_t *info);
int _remove_station_info(gconstpointer data, GCompareFunc func);
int _remove_station_info_all(mobile_ap_type_e type);
int _get_station_info(gconstpointer data, GCompareFunc func,
		mobile_ap_station_info_t **si);
int _get_station_count(gconstpointer data, GCompareFunc func, int *count);
int _station_info_foreach(GFunc func, void *user_data);
int _add_data_usage_rule(const char *src, const char *dest);
int _del_data_usage_rule(const char *src, const char *dest);
int _get_data_usage(const char *src, const char *dest, unsigned long long *tx, unsigned long long *rx);
int _execute_command(const char *cmd);
int _get_tethering_type_from_ip(const char *ip, mobile_ap_type_e *type);

#endif /* __MOBILEAP_COMMON_H__ */
