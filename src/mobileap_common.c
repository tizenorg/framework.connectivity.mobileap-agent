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
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "mobileap_notification.h"
#include "mobileap_common.h"

#define TETHERING_OBJECT_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS ((obj), \
	TETHERING_TYPE_OBJECT , TetheringObjectClass))

extern DBusConnection *tethering_conn;

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

void _emit_mobileap_dbus_signal(TetheringObject *obj,
				mobile_ap_sig_e num, const gchar *message)
{
	TetheringObjectClass *klass = TETHERING_OBJECT_GET_CLASS(obj);

	DBG("Emitting signal id [%d], with message [%s]\n", num, message);
	g_signal_emit(obj, klass->signals[num], 0, message);
}

void _send_dbus_station_info(const char *member, mobile_ap_station_info_t *info)
{
	if (tethering_conn == NULL)
		return;

	if (member == NULL || info == NULL) {
		ERR("Invalid param\n");
		return;
	}

	DBusMessage *msg = NULL;
	char *ip = info->ip;
	char *mac = info->mac;
	char *hostname = info->hostname;

	msg = dbus_message_new_signal(TETHERING_SERVICE_OBJECT_PATH,
			TETHERING_SERVICE_INTERFACE,
			SIGNAL_NAME_DHCP_STATUS);
	if (!msg) {
		ERR("Unable to allocate D-Bus signal\n");
		return;
	}

	if (!dbus_message_append_args(msg,
				DBUS_TYPE_STRING, &member,
				DBUS_TYPE_UINT32, &info->interface,
				DBUS_TYPE_STRING, &ip,
				DBUS_TYPE_STRING, &mac,
				DBUS_TYPE_STRING, &hostname,
				DBUS_TYPE_UINT32, &info->tm,
				DBUS_TYPE_INVALID)) {
		ERR("Event sending failed\n");
		dbus_message_unref(msg);
		return;
	}

	dbus_connection_send(tethering_conn, msg, NULL);
	dbus_message_unref(msg);

	return;
}


void _update_station_count(int count)
{
	static int prev_cnt = 0;
	char str[MH_NOTI_STR_MAX] = {0, };

	if (prev_cnt == count) {
		DBG("No need to update\n");
		return;
	}

	DBG("Update the number of station : %d\n", count);
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

	snprintf(str, MH_NOTI_STR_MAX, MH_NOTI_STR, count);
	if (prev_cnt == 0) {
		DBG("Create notification\n");
		_create_connected_noti(str, MH_NOTI_TITLE, MH_NOTI_ICON_PATH);
	} else {
		DBG("Update notification\n");
		_update_connected_noti(str);
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
		DBG("Already exist station : %s\n", info->mac);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	station_list = g_slist_append(station_list, info);
	for (l = station_list; l != NULL; l = g_slist_next(l)) {
		si = (mobile_ap_station_info_t *)l->data;
		DBG("[%d] interface : %d\n", i, si->interface);
		DBG("[%d] station MAC : %s\n", i, si->mac);
		DBG("[%d] station Hostname : %s\n", i, si->hostname);
		DBG("[%d] station IP : %s\n", i, si->ip);
		DBG("[%d] station connected time : %d\n", i, si->tm);
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
	DBG("Remove station MAC : %s\n", si->mac);
	station_list = g_slist_delete_link(station_list, l);
	_send_dbus_station_info("DhcpLeaseDeleted", si);
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

	while (l) {
		si = (mobile_ap_station_info_t *)l->data;
		DBG("interface : %d\n", si->interface);
		if (si->interface != type) {
			l = g_slist_next(l);
			continue;
		}

		DBG("Remove station MAC : %s\n", si->mac);
		_send_dbus_station_info("DhcpLeaseDeleted", si);
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
	DBG("Found station : %s\n", node->mac);
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
	DBG("Station count : %d\n", *count);

	return MOBILE_AP_ERROR_NONE;
}

int _station_info_foreach(GFunc func, void *user_data)
{
	if (func == NULL) {
		ERR("Invalid param\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	g_slist_foreach(station_list, func, user_data);

	return MOBILE_AP_ERROR_NONE;
}

int _add_data_usage_rule(const char *src, const char *dest)
{
	if (src == NULL || src[0] == '\0' ||
			dest == NULL || dest[0] == '\0' ||
			g_strcmp0(src, dest) == 0) {
		ERR("Invalid parameter\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	char cmd[MAX_BUF_SIZE] = {0, };

	snprintf(cmd, sizeof(cmd), "%s -A FORWARD "FORWARD_RULE,
			IPTABLES, src, dest);
	DBG("ADD IPTABLES RULE : %s\n", cmd);
	if (_execute_command(cmd)) {
		ERR("iptables failed : %s\n", cmd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	snprintf(cmd, sizeof(cmd), "%s -A FORWARD "FORWARD_RULE,
			IPTABLES, dest, src);
	DBG("ADD IPTABLES RULE : %s\n", cmd);
	if (_execute_command(cmd)) {
		ERR("iptables failed : %s\n", cmd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	return MOBILE_AP_ERROR_NONE;
}

int _del_data_usage_rule(const char *src, const char *dest)
{
	if (src == NULL || src[0] == '\0' ||
			dest == NULL || dest[0] == '\0' ||
			g_strcmp0(src, dest) == 0) {
		ERR("Invalid parameter\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	char cmd[MAX_BUF_SIZE] = {0, };

	snprintf(cmd, sizeof(cmd), "%s -D FORWARD "FORWARD_RULE,
			IPTABLES, src, dest);
	DBG("REMOVE IPTABLES RULE : %s\n", cmd);
	if (_execute_command(cmd)) {
		ERR("iptables failed : %s\n", cmd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	snprintf(cmd, sizeof(cmd), "%s -D FORWARD "FORWARD_RULE,
			IPTABLES, dest, src);
	DBG("REMOVE IPTABLES RULE : %s\n", cmd);
	if (_execute_command(cmd)) {
		ERR("iptables failed : %s\n", cmd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	return MOBILE_AP_ERROR_NONE;
}

int _get_data_usage(const char *src, const char *dest,
		unsigned long long *tx, unsigned long long *rx)
{
	if (src == NULL || src[0] == '\0' ||
			dest == NULL || dest[0] == '\0' ||
			tx == NULL || rx == NULL) {
		ERR("Invalid parameter\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	char cmd[MAX_BUF_SIZE] = {0, };
	char buf[MAX_BUF_SIZE] = {0, };
	FILE *fp = NULL;

	/* Tx : Src. -> Dest. */
	snprintf(cmd, sizeof(cmd),
			"%s -L FORWARD -vx | %s \"%s[ ]*%s\" | %s '{ print $2 }' > %s",
			IPTABLES, GREP, src, dest, AWK, DATA_USAGE_FILE);
	if (system(cmd) < 0) {
		ERR("\"cmd\" is failed\n");
	}

	/* Rx : Dest. -> Src. */
	snprintf(cmd, sizeof(cmd),
			"%s -L FORWARD -vx | %s \"%s[ ]*%s\" | %s '{ print $2 }' >> %s",
			IPTABLES, GREP, dest, src, AWK, DATA_USAGE_FILE);
	if (system(cmd) < 0) {
		ERR("\"cmd\" is failed\n");
	}

	fp = fopen(DATA_USAGE_FILE, "r");
	if (fp == NULL) {
		ERR("%s open failed\n", DATA_USAGE_FILE);
		ERR("%s\n", strerror(errno));
		return MOBILE_AP_ERROR_INTERNAL;
	}

	if (fgets(buf, sizeof(buf), fp) == NULL)
		*tx = 0LL;
	else
		*tx = atoll(buf);

	if (fgets(buf, sizeof(buf), fp) == NULL)
		*rx = 0LL;
	else
		*rx = atoll(buf);

	fclose(fp);
	unlink(DATA_USAGE_FILE);

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

	DBG("cmd : %s\n", cmd);

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
		DBG("child pid : %d\n", pid);

		/* Need to add timeout */
		waitpid(pid, &status, 0);
		g_strfreev(args);

		if (WIFEXITED(status)) {
			exit_status = WEXITSTATUS(status);
			if (exit_status) {
				ERR("child return : %d\n", exit_status);
				return EXIT_FAILURE;
			}
			DBG("child terminated normally\n");
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
		ERR("Address : %s is invalid\n", ip);
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
		*type = MOBILE_AP_TYPE_WIFI;
		return MOBILE_AP_ERROR_NONE;
	} else if (subnet >= subnet_bt_min && subnet <= subnet_bt_max) {
		*type = MOBILE_AP_TYPE_BT;
		return MOBILE_AP_ERROR_NONE;
	} else if (subnet == subnet_usb) {
		*type = MOBILE_AP_TYPE_USB;
		return MOBILE_AP_ERROR_NONE;
	}

	ERR("Tethering type cannot be decided from %s\n", ip);
	return MOBILE_AP_ERROR_INVALID_PARAM;
}
