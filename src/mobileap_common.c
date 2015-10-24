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

#include <stdio.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <dbus/dbus.h>

#include "mobileap_notification.h"
#include "mobileap_common.h"

static GSList *station_list = NULL;

gint _slist_find_station_by_interface(gconstpointer a, gconstpointer b)
{
	mobile_ap_station_info_t *si = (mobile_ap_station_info_t *)a;
	mobile_ap_type_e interface = (mobile_ap_type_e)b;

	return si->interface - interface;
}

gint _slist_find_station_by_mac(gconstpointer a, gconstpointer b)
{
	mobile_ap_station_info_t *si = (mobile_ap_station_info_t *)a;
	const char *mac = (const char *)b;

	return g_ascii_strcasecmp(si->mac, mac);
}

gint _slist_find_station_by_ip_addr(gconstpointer a, gconstpointer b)
{
	mobile_ap_station_info_t *si = (mobile_ap_station_info_t *)a;
	const char *ip_addr = (const char *)b;

	return g_ascii_strcasecmp(si->ip, ip_addr);
}

void _send_dbus_station_info(const char *member, mobile_ap_station_info_t *info)
{

	DBG("+\n");
	if (member == NULL || info == NULL) {
		ERR("Invalid param\n");
		return;
	}
	Tethering *obj = _get_tethering_obj();
	if (obj == NULL) {
		ERR("tethering object is null\n");
		return;
	}
	DBG("signal is   %s", member);
	tethering_emit_dhcp_status(obj, member, info->interface, info->ip, info->mac,
			info->hostname, info->tm);
	DBG("-\n");
}

void _update_station_count(int count)
{
	static int prev_cnt = 0;
	char icon_path[MH_NOTI_PATH_MAX] = {0, };
	int wifi_count = 0;
	int bt_count = 0;
	int usb_count = 0;

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI_AP)) {
		return;
	}

	if (prev_cnt == count) {
		return;
	}

	if (vconf_set_int(VCONFKEY_MOBILE_HOTSPOT_CONNECTED_DEVICE,
				count) < 0) {
		ERR("Error setting up vconf\n");
		return;
	}

	if (count == 0) {
		prev_cnt = 0;
		_delete_connected_noti();
		return;
	}

	_get_station_count((gconstpointer)MOBILE_AP_TYPE_WIFI, _slist_find_station_by_interface, &wifi_count);
	_get_station_count((gconstpointer)MOBILE_AP_TYPE_BT, _slist_find_station_by_interface, &bt_count);
	_get_station_count((gconstpointer)MOBILE_AP_TYPE_USB, _slist_find_station_by_interface, &usb_count);

	if (wifi_count > 0 && bt_count == 0 && usb_count == 0) {
		g_strlcpy(icon_path, MH_NOTI_ICON_WIFI, sizeof(icon_path));
	} else if (wifi_count == 0 && bt_count > 0 && usb_count == 0) {
		g_strlcpy(icon_path, MH_NOTI_ICON_BT, sizeof(icon_path));
	} else if (wifi_count == 0 && bt_count == 0 && usb_count > 0) {
		g_strlcpy(icon_path, MH_NOTI_ICON_USB, sizeof(icon_path));
	} else if (wifi_count == 0 && bt_count == 0 && usb_count == 0) {
		return;
	} else {
		g_strlcpy(icon_path, MH_NOTI_ICON_GENERAL, sizeof(icon_path));
	}

	if (prev_cnt == 0) {
		_create_connected_noti(count, icon_path);
	} else {
		_update_connected_noti(count, icon_path);
	}

	prev_cnt = count;
	return;
}

int _add_station_info(mobile_ap_station_info_t *info)
{
	if (info == NULL) {
		ERR("Invalid param\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	guint count;
	GSList *l = NULL;
	mobile_ap_station_info_t *si = NULL;
	int i = 0;

	if (_get_station_info(info->mac, _slist_find_station_by_mac, &si) ==
			MOBILE_AP_ERROR_NONE) {
		if (!si) {
			return MOBILE_AP_ERROR_INTERNAL;
		}

		if (g_strcmp0(si->hostname, info->hostname) == 0 &&
				g_strcmp0(si->ip, info->ip) == 0) {
			return MOBILE_AP_ERROR_INTERNAL;
		}

		_remove_station_info(si->mac, _slist_find_station_by_mac);
	}

	station_list = g_slist_append(station_list, info);
	for (l = station_list; l != NULL; l = g_slist_next(l)) {
		si = (mobile_ap_station_info_t *)l->data;
		SDBG("[%d] interface : %d\n", i, si->interface);
		SDBG("[%d] station MAC : %s\n", i, si->mac);
		SDBG("[%d] station Hostname : %s\n", i, si->hostname);
		SDBG("[%d] station IP : %s\n", i, si->ip);
		SDBG("[%d] station connected time : %d\n", i, si->tm);
		i++;
	}

	count = g_slist_length(station_list);
	_update_station_count(count);

	return MOBILE_AP_ERROR_NONE;
}

int _remove_station_info(gconstpointer data, GCompareFunc func)
{
	if (func == NULL) {
		ERR("Invalid param\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	if (station_list == NULL) {
		ERR("There is no station\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	GSList *l = NULL;
	mobile_ap_station_info_t *si = NULL;
	int count;

	l = g_slist_find_custom(station_list, data, func);
	if (!l) {
		ERR("Not found\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	si = (mobile_ap_station_info_t *)l->data;
	SDBG("Remove station MAC : %s\n", si->mac);
	station_list = g_slist_delete_link(station_list, l);
	_send_dbus_station_info("DhcpLeaseDeleted", si);
	g_free(si->hostname);
	g_free(si);

	count = g_slist_length(station_list);
	_update_station_count(count);

	return MOBILE_AP_ERROR_NONE;
}

int _remove_station_info_all(mobile_ap_type_e type)
{
	if (station_list == NULL) {
		return MOBILE_AP_ERROR_NONE;
	}

	GSList *l = station_list;
	GSList *temp_l = NULL;
	mobile_ap_station_info_t *si = NULL;
	int count;

	_flush_dhcp_ack_timer();

	while (l) {
		si = (mobile_ap_station_info_t *)l->data;
		if (si->interface != type) {
			l = g_slist_next(l);
			continue;
		}

		SDBG("Remove station MAC : %s\n", si->mac);
		_send_dbus_station_info("DhcpLeaseDeleted", si);
		g_free(si->hostname);
		g_free(si);

		temp_l = l;
		l = g_slist_next(l);
		station_list = g_slist_delete_link(station_list, temp_l);
	}

	count = g_slist_length(station_list);
	_update_station_count(count);

	return MOBILE_AP_ERROR_NONE;
}

int _get_station_info(gconstpointer data, GCompareFunc func,
		mobile_ap_station_info_t **si)
{
	if (func == NULL || si == NULL) {
		ERR("Invalid param\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	if (station_list == NULL) {
		ERR("There is no station\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	GSList *l = NULL;
	mobile_ap_station_info_t *node = NULL;

	l = g_slist_find_custom(station_list, data, func);
	if (!l) {
		ERR("Not found\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	node = l->data;
	SDBG("Found station : %s\n", node->mac);
	*si = node;

	return MOBILE_AP_ERROR_NONE;
}

int _get_station_count(gconstpointer data, GCompareFunc func, int *count)
{
	if (count == NULL) {
		ERR("Invalid param\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	GSList *l = station_list;
	int _count = 0;

	for (_count = 0; l != NULL; _count++, l = g_slist_next(l)) {
		l = g_slist_find_custom(l, data, func);
		if (l == NULL)
			break;
	}

	*count = _count;

	return MOBILE_AP_ERROR_NONE;
}

GVariant * _station_info_foreach()
{
	GSList *l = NULL;
	GVariant *params = NULL;
	GVariantBuilder *inner_builder;
	GVariantBuilder *outer_builder;
	mobile_ap_station_info_t *st = NULL;

	outer_builder = g_variant_builder_new(G_VARIANT_TYPE ("a(a{sv})"));

	for (l = station_list; l != NULL; l = g_slist_next(l)) {
		st = (mobile_ap_station_info_t *)l->data;

		inner_builder = g_variant_builder_new(G_VARIANT_TYPE ("a{sv}"));
		g_variant_builder_add(inner_builder, "{sv}", "Type",
					g_variant_new_int32(st->interface));
		g_variant_builder_add(inner_builder, "{sv}", "IP",
					g_variant_new_string(st->ip));
		g_variant_builder_add(inner_builder, "{sv}", "MAC",
					g_variant_new_string(st->mac));
		if (st->hostname) {
			g_variant_builder_add(inner_builder, "{sv}", "Name",
						g_variant_new_string(st->hostname));
		}
		g_variant_builder_add(inner_builder, "{sv}", "Time",
					g_variant_new_int32(st->tm));

		g_variant_builder_add(outer_builder, "(@a{sv})", g_variant_builder_end(inner_builder));

		g_variant_builder_unref(inner_builder);
	}

	params = g_variant_new("(@a(a{sv}))", g_variant_builder_end(outer_builder));
	if (params == NULL) {
		ERR("params IS NULL\n");
	} else {
		SDBG("outer builder print  %s", g_variant_print(params, TRUE));
	}
	g_variant_builder_unref(outer_builder);
	return params;
}

int _add_interface_routing(const char *interface, const in_addr_t gateway)
{
	if (interface == NULL || interface[0] == '\0') {
		ERR("Invalid parameter\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	char cmd[MAX_BUF_SIZE] = {0, };
	struct in_addr addr;
	char *interface_gw;
	in_addr_t subnet;

	addr.s_addr = htonl(gateway);

	subnet = inet_netof(addr);
	addr = inet_makeaddr(subnet, 0);
	interface_gw = inet_ntoa(addr);

	snprintf(cmd, sizeof(cmd), "%s route add "INTERFACE_ROUTING,
			IP_CMD, interface_gw, TETHERING_ROUTING_TABLE, interface);
	if (_execute_command(cmd)) {
		ERR("cmd failed : %s\n", cmd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	return MOBILE_AP_ERROR_NONE;
}

int _del_interface_routing(const char *interface, const in_addr_t gateway)
{
	if (interface == NULL || interface[0] == '\0') {
		ERR("Invalid parameter\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	char cmd[MAX_BUF_SIZE] = {0, };
	struct in_addr addr;
	char *interface_gw;
	in_addr_t subnet;

	addr.s_addr = htonl(gateway);

	subnet = inet_netof(addr);
	addr = inet_makeaddr(subnet, 0);
	interface_gw = inet_ntoa(addr);

	snprintf(cmd, sizeof(cmd), "%s route del "INTERFACE_ROUTING,
			IP_CMD, interface_gw, TETHERING_ROUTING_TABLE, interface);
	if (_execute_command(cmd)) {
		ERR("cmd failed : %s\n", cmd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	return MOBILE_AP_ERROR_NONE;
}

int _add_routing_rule(const char *interface)
{
	if (interface == NULL || interface[0] == '\0') {
		ERR("Invalid parameter\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	char cmd[MAX_BUF_SIZE] = {0, };

	snprintf(cmd, sizeof(cmd), "%s rule add "SRC_ROUTING_RULE,
			IP_CMD, interface, TETHERING_ROUTING_TABLE);
	if (_execute_command(cmd)) {
		ERR("cmd failed : %s\n", cmd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	return MOBILE_AP_ERROR_NONE;
}

int _del_routing_rule(const char *interface)
{
	if (interface == NULL || interface[0] == '\0') {
		ERR("Invalid parameter\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	char cmd[MAX_BUF_SIZE] = {0, };

	snprintf(cmd, sizeof(cmd), "%s rule del "SRC_ROUTING_RULE,
			IP_CMD, interface, TETHERING_ROUTING_TABLE);
	if (_execute_command(cmd)) {
		ERR("cmd failed : %s\n", cmd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	return MOBILE_AP_ERROR_NONE;
}

int _flush_ip_address(const char *interface)
{
	if (interface == NULL || interface[0] == '\0') {
		ERR("Invalid parameter\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	char cmd[MAX_BUF_SIZE] = {0, };

	snprintf(cmd, sizeof(cmd), "%s addr flush dev %s",
			IP_CMD, interface);
	if (_execute_command(cmd)) {
		ERR("cmd failed : %s\n", cmd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	return MOBILE_AP_ERROR_NONE;
}

int _execute_command(const char *cmd)
{
	if (cmd == NULL) {
		ERR("Invalid param\n");
		return EXIT_FAILURE;
	}

	int status = 0;
	int exit_status = 0;
	pid_t pid = 0;
	gchar **args = NULL;

	SDBG("CMD : %s\n", cmd);

	args = g_strsplit_set(cmd, " ", -1);
	if (!args) {
		ERR("g_strsplit_set failed\n");
		return EXIT_FAILURE;
	}

	if ((pid = fork()) < 0) {
		ERR("fork failed\n");
		return EXIT_FAILURE;
	}

	if (!pid) {
		if (execv(args[0], args)) {
			ERR("execl failed\n");
		}

		ERR("Should never get here!\n");
		return EXIT_FAILURE;
	} else {
		/* Need to add timeout */
		waitpid(pid, &status, 0);
		g_strfreev(args);

		if (WIFEXITED(status)) {
			exit_status = WEXITSTATUS(status);
			if (exit_status) {
				ERR("child return : %d\n", exit_status);
				return EXIT_FAILURE;
			}
			return EXIT_SUCCESS;
		} else {
			ERR("child is terminated without exit\n");
			return EXIT_FAILURE;
		}
	}
}

int _get_tethering_type_from_ip(const char *ip, mobile_ap_type_e *type)
{
	if (ip == NULL || type == NULL) {
		ERR("Invalid param\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	static gboolean is_init = FALSE;
	static in_addr_t subnet_wifi;
	static in_addr_t subnet_bt_min;
	static in_addr_t subnet_bt_max;
	static in_addr_t subnet_usb;

	struct in_addr addr;
	in_addr_t subnet;

	if (inet_aton(ip, &addr) == 0) {
		SERR("Address : %s is invalid\n", ip);
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}
	subnet = inet_netof(addr);

	if (is_init == FALSE) {
		addr.s_addr = htonl(IP_ADDRESS_WIFI);
		subnet_wifi = inet_netof(addr);

		addr.s_addr = htonl(IP_ADDRESS_BT_1);
		subnet_bt_min = inet_netof(addr);

		addr.s_addr = htonl(IP_ADDRESS_BT_7);
		subnet_bt_max = inet_netof(addr);

		addr.s_addr = htonl(IP_ADDRESS_USB);
		subnet_usb = inet_netof(addr);
		is_init = TRUE;
	}

	if (subnet == subnet_wifi) {
		if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI))
			*type = MOBILE_AP_TYPE_WIFI;
		else
			*type = MOBILE_AP_TYPE_WIFI_AP;
		return MOBILE_AP_ERROR_NONE;
	} else if (subnet >= subnet_bt_min && subnet <= subnet_bt_max) {
		*type = MOBILE_AP_TYPE_BT;
		return MOBILE_AP_ERROR_NONE;
	} else if (subnet == subnet_usb) {
		*type = MOBILE_AP_TYPE_USB;
		return MOBILE_AP_ERROR_NONE;
	}

	SERR("Tethering type cannot be decided from %s\n", ip);

	return MOBILE_AP_ERROR_INVALID_PARAM;
}
