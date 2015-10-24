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
#include <unistd.h>
#include <stdlib.h>
#include <glib.h>
#include <string.h>
#include <net_connection.h>

#include "mobileap_softap.h"
#include "mobileap_common.h"
#include "mobileap_network.h"
#include "mobileap_wifi.h"
#include "mobileap_bluetooth.h"
#include "mobileap_usb.h"
#include "mobileap_iptables.h"

typedef enum {
	__NO_SERVICE,
	__INTERNET,
	__TETHERING_ONLY
} tethering_cellular_service_type_e;

typedef struct {
	connection_profile_h handle;
	tethering_cellular_service_type_e svc_type;
} tethering_cellular_profile_s;

#define	MH_PORT_FORWARD_CONF_FILEPATH	"/tmp/mobileap_agent_port_forward_info"
#define	MH_MAX_PORT_FORWARD_RULE_LEN	64	/* interface(10) protocol(10) ip(15):port(5) ip(15):port(5) */
#define	MH_MAX_NO_OF_PORT_FORWARD_RULE	64

typedef struct {
	char *input_interface;
	char *proto;
	char *org_dest_ip;
	unsigned short org_dest_port;
	char *new_dest_ip;
	unsigned short new_dest_port;
} port_forward_info_s;

static Tethering *obj = NULL;
static connection_h connection = NULL;
static tethering_cellular_profile_s c_prof = {NULL, __NO_SERVICE};
static guint net_timeout_id;
static connection_profile_h tethered_prof = NULL;
static GSList *port_forward_info = NULL;


static gboolean __try_to_open_tethering_profile(gpointer user_data);

static mobile_ap_error_code_e __get_conn_error(int conn_error)
{
	mobile_ap_error_code_e err = MOBILE_AP_ERROR_NONE;

	switch (conn_error) {
	case CONNECTION_ERROR_NONE:
		err = MOBILE_AP_ERROR_NONE;
		break;

	case CONNECTION_ERROR_OUT_OF_MEMORY:
		err = MOBILE_AP_ERROR_RESOURCE;
		break;

	case CONNECTION_ERROR_INVALID_OPERATION:
		err = MOBILE_AP_ERROR_INTERNAL;
		break;

	case CONNECTION_ERROR_INVALID_PARAMETER:
		err = MOBILE_AP_ERROR_INVALID_PARAM;
		break;

	case CONNECTION_ERROR_ALREADY_EXISTS:
		err = MOBILE_AP_ERROR_ALREADY_ENABLED;
		break;

#ifndef TIZEN_TV
	case CONNECTION_ERROR_PERMISSION_DENIED:
		err = MOBILE_AP_ERROR_PERMISSION_DENIED;
		break;
#endif

	case CONNECTION_ERROR_DHCP_FAILED:
		err = MOBILE_AP_ERROR_DHCP;
		break;

	case CONNECTION_ERROR_NOW_IN_PROGRESS:
		err = MOBILE_AP_ERROR_IN_PROGRESS;
		break;

	default:
		ERR("Not defined error : %d\n", conn_error);
		err = MOBILE_AP_ERROR_INTERNAL;
		break;
	}

	return err;
}

static gboolean __is_valid_ipv4_addr(const char *ip)
{
	int i;
	int len;
	int dot_count = 0;
	int addr;
	char tmp_ip[16] = {0, };
	char *p = tmp_ip;

	if (ip == NULL)
		return FALSE;

	len = strlen(ip);
	if (len > 15 /* 255.255.255.255 */ || len < 7 /* 0.0.0.0 */)
		return FALSE;
	g_strlcpy(tmp_ip, ip, sizeof(tmp_ip));

	for (i = 0; i <= len; i++) {
		if (tmp_ip[i] == '.') {
			if (++dot_count > 3)
				return FALSE;
			if (&tmp_ip[i] == p)
				return FALSE;
			tmp_ip[i] = '\0';
			addr = atoi(p);
			if (addr < 0 || addr > 255)
				return FALSE;
			p = &tmp_ip[i + 1];
		} else if (tmp_ip[i] == '\0') {
			if (&tmp_ip[i] == p)
				return FALSE;
			addr = atoi(p);
			if (addr < 0 || addr > 255)
				return FALSE;
			break;
		} else if (tmp_ip[i] < '0' || tmp_ip[i] > '9')
			return FALSE;
	}

	if (dot_count != 3)
		return FALSE;

	return TRUE;
}

static void __clear_port_forward_info(void)
{
	GSList *l;
	GSList *temp_l;
	port_forward_info_s *pf;

	for (l = port_forward_info; l; ) {
		pf = (port_forward_info_s *)l->data;
		if (pf) {
			g_free(pf->new_dest_ip);
			g_free(pf->org_dest_ip);
			g_free(pf->proto);
			g_free(pf->input_interface);
			g_free(pf);
		}

		temp_l = l;
		l = g_slist_next(l);
		port_forward_info = g_slist_delete_link(port_forward_info, temp_l);
	}

	return;
}

static gboolean __read_port_forward_info(const char *conf_file)
{
	if (conf_file == NULL) {
		ERR("Invalid parameter\n");
		return FALSE;
	}

	DBG("+\n");

	FILE *fp;
	char buf[MH_MAX_PORT_FORWARD_RULE_LEN];
	port_forward_info_s *pf;
	int no_of_rule = 0;

	__clear_port_forward_info();

	fp = fopen(conf_file, "r");
	if (fp == NULL) {
		ERR("fopen is failed : %s\n", strerror(errno));
		return FALSE;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		int i;
		char *token;
		char *saveptr1 = NULL;
		char *saveptr2 = NULL;

		char *input_interface;
		char *proto;
		char *dest_ip[2];
		char *dest_port[2];

		if (no_of_rule++ >= MH_MAX_NO_OF_PORT_FORWARD_RULE) {
			DBG("There are too many rules\n");
			break;
		}

		/* "Input interface" "Protocol" "Original destination IP:Port" "New destination IP:Port" */
		/* pdp0 udp 10.90.50.38:23 192.168.43.10:23 */

		input_interface = strtok_r(buf, " ", &saveptr1);
		if (input_interface == NULL) {
			SERR("Invalid rule : %s\n", buf);
			continue;
		}

		proto = strtok_r(NULL, " ", &saveptr1);
		if (proto == NULL) {
			SERR("Invalid rule : %s\n", buf);
			continue;
		}

		for (i = 0; i < sizeof(dest_ip) / sizeof(char *); i++) {
			token = strtok_r(NULL, " ", &saveptr1);
			if (token == NULL) {
				SERR("Invalid rule : %s\n", buf);
				break;
			}

			dest_ip[i] = strtok_r(token, ":", &saveptr2);
			if (dest_ip[i] == NULL ||
					!__is_valid_ipv4_addr(dest_ip[i])) {
				SERR("Invalid rule : %s\n", buf);
				break;
			}

			dest_port[i] = strtok_r(NULL, ":", &saveptr2);
			if (dest_port[i] == NULL) {
				SERR("Invalid rule : %s\n", buf);
				break;
			}
		}

		if (i < sizeof(dest_ip) / sizeof(char *))
			continue;

		pf = (port_forward_info_s *)malloc(sizeof(port_forward_info_s));
		if (pf == NULL)
			break;

		pf->input_interface = g_strdup(input_interface);
		pf->proto = g_strdup(proto);
		pf->org_dest_ip = g_strdup(dest_ip[0]);
		pf->org_dest_port = (unsigned short)atoi(dest_port[0]);
		pf->new_dest_ip = g_strdup(dest_ip[1]);
		pf->new_dest_port = (unsigned short)atoi(dest_port[1]);
		port_forward_info = g_slist_append(port_forward_info, pf);

		SDBG("Port forward rule #%d : %s %s %s:%d %s:%d\n", no_of_rule,
				pf->input_interface, pf->proto,
				pf->org_dest_ip, pf->org_dest_port,
				pf->new_dest_ip, pf->new_dest_port);
	}

	fclose(fp);

	return TRUE;
}

static gboolean __is_valid_port_forward_info(port_forward_info_s *pf)
{
	if (pf == NULL)
		return FALSE;

	if (!pf->input_interface || !pf->proto ||
			!pf->org_dest_ip || !pf->new_dest_ip)
		return FALSE;

	if (!strlen(pf->input_interface) || !strlen(pf->proto) ||
			!strlen(pf->org_dest_ip) || !strlen(pf->new_dest_ip))
		return FALSE;

	return TRUE;
}

static void __print_cellular_profile(void)
{
	int ret = 0;
	char *apn = NULL;
	char *home_url = NULL;
	bool roaming = false;
	connection_cellular_service_type_e service_type;

	if (c_prof.handle == NULL)
		return;

	ret = connection_profile_get_cellular_service_type(c_prof.handle, &service_type);
	if (ret != CONNECTION_ERROR_NONE)
		ERR("connection API fail: 0x%X\n", ret);
	else
		SDBG("Service type: %d\n", service_type);

	ret = connection_profile_get_cellular_apn(c_prof.handle, &apn);
	if (ret != CONNECTION_ERROR_NONE)
		ERR("connection API fail: 0x%X\n", ret);
	else {
		SDBG("APN: %s\n", apn);
		g_free(apn);
	}

	ret = connection_profile_get_cellular_home_url(c_prof.handle, &home_url);
	if (ret != CONNECTION_ERROR_NONE)
		ERR("connection API fail: 0x%X\n", ret);
	else {
		SDBG("Home url: %s\n", home_url);
		g_free(home_url);
	}

	ret = connection_profile_is_cellular_roaming(c_prof.handle, &roaming);
	if (ret != CONNECTION_ERROR_NONE)
		ERR("connection API fail: 0x%X\n", ret);
	else
		SDBG("Roaming: %d\n", roaming);
}

static void __handle_open_network_error(void)
{
	int ret = MOBILE_AP_ERROR_NONE;

	if (_mobileap_is_disabled()) {
		return;
	}

	ret = _disable_wifi_tethering(obj);
	DBG("_disable_wifi_tethering returns %d\n", ret);

	ret = _disable_bt_tethering(obj);
	DBG("_disable_bt_tethering returns %d\n", ret);

	ret = _disable_usb_tethering(obj);
	DBG("_disable_usb_tethering returns %d\n", ret);

	tethering_emit_net_closed(obj);
}

static gboolean __is_equal_profile(connection_profile_h a, connection_profile_h b)
{
	char *a_id = NULL;
	char *b_id = NULL;
	int ret;

	ret = connection_profile_get_id(a, &a_id);
	if (ret != CONNECTION_ERROR_NONE || a_id == NULL) {
		ERR("connection_profile_get_id is failed [0x%X]\n", ret);
		return FALSE;
	}

	ret = connection_profile_get_id(b, &b_id);
	if (ret != CONNECTION_ERROR_NONE || b_id == NULL) {
		ERR("connection_profile_get_id is failed [0x%X]\n", ret);
		g_free(a_id);
		return FALSE;
	}

	ret = g_strcmp0(a_id, b_id);
	g_free(a_id);
	g_free(b_id);

	return (ret == 0) ? TRUE : FALSE;
}

static gboolean __is_connected_profile(connection_profile_h profile)
{
	if (profile == NULL) {
		ERR("profile is NULL\n");
		return FALSE;
	}

	int ret;
	connection_profile_state_e pstat = CONNECTION_PROFILE_STATE_DISCONNECTED;

	ret = connection_profile_get_state(profile, &pstat);
	if (ret != CONNECTION_ERROR_NONE) {
		ERR("connection_profile_get_state is failed: 0x%X\n", ret);
		return FALSE;
	}

	if (pstat != CONNECTION_PROFILE_STATE_CONNECTED) {
		return FALSE;
	}

	DBG("Profile is connected\n");
	return TRUE;
}

static void __connection_type_changed_cb(connection_type_e type, void *user_data)
{
	DBG("Changed connection type is [%s]\n",
			type == CONNECTION_TYPE_DISCONNECTED ? "DISCONNECTED" :
			type == CONNECTION_TYPE_WIFI ? "Wi-Fi" :
			type == CONNECTION_TYPE_CELLULAR ? "Cellular" :
			type == CONNECTION_TYPE_ETHERNET ? "Ethernet" :
			"Unknown");

	if (_mobileap_is_disabled()) {
		DBG("Tethering is disabled\n");
		return;
	}

	if (_open_network() != MOBILE_AP_ERROR_NONE) {
		ERR("_open_network() is failed\n");
		__handle_open_network_error();
	}

	return;
}

void __cellular_state_changed_cb(keynode_t *node, void *user_data)
{
	if (node == NULL) {
		ERR("Invalid parameter\n");
		return;
	}

	if (vconf_keynode_get_type(node) != VCONF_TYPE_INT) {
		ERR("Invalid vconf key type\n");
		return;
	}

	int ret;
	int cellular_state;
	connection_type_e net_type;

	cellular_state = vconf_keynode_get_int(node);
	SDBG("key = %s, value = %d(int)\n",
			vconf_keynode_get_name(node), cellular_state);

	if (_mobileap_is_disabled())
		return;

	if (cellular_state != VCONFKEY_NETWORK_CELLULAR_ON)
		return;

	ret = connection_get_type(connection, &net_type);
	if (ret != CONNECTION_ERROR_NONE) {
		ERR("connection_get_type is failed [0x%X]\n", ret);
		return;
	}

	if (net_type != CONNECTION_TYPE_DISCONNECTED &&
			net_type != CONNECTION_TYPE_CELLULAR)
		return;

	if (tethered_prof)
		return;

	DBG("VCONFKEY_NETWORK_CELLULAR_ON\n");
	if (_open_network() != MOBILE_AP_ERROR_NONE) {
		ERR("_open_network() is failed\n");
		__handle_open_network_error();
	}

	return;
}

static void __profile_state_changed_cb(connection_profile_state_e state, void *user_data)
{
	if (c_prof.handle == NULL || c_prof.svc_type == __NO_SERVICE) {
		ERR("There is no proper profile\n");
		return;
	}

	DBG("Tethering cellular profile is %s\n",
			state == CONNECTION_PROFILE_STATE_DISCONNECTED ? "Disconnected" :
			state == CONNECTION_PROFILE_STATE_ASSOCIATION ? "Associated" :
			state == CONNECTION_PROFILE_STATE_CONFIGURATION ? "Configured" :
			state == CONNECTION_PROFILE_STATE_CONNECTED ? "Connected" :
			"Unknown");

	int ret;
	int cellular_state;

	connection_profile_refresh(c_prof.handle);

	if (_mobileap_is_disabled())
		return;

	if (c_prof.svc_type != __TETHERING_ONLY)
		return;

	if (tethered_prof) {
		if (!__is_equal_profile(tethered_prof, c_prof.handle))
			return;
		connection_profile_refresh(tethered_prof);
	}

	if (state != CONNECTION_PROFILE_STATE_DISCONNECTED)
		return;

	DBG("Cellular profile is disconnected\n");
	_close_network();

	ret = vconf_get_int(VCONFKEY_NETWORK_CELLULAR_STATE, &cellular_state);
	if (ret < 0) {
		ERR("vconf_get_int is failed : %d\n", ret);
		if (vconf_ignore_key_changed(VCONFKEY_NETWORK_CELLULAR_STATE,
					__cellular_state_changed_cb) < 0) {
			ERR("vconf_ignore_key_changed is failed\n");
		}
		return;
	}

	if (cellular_state != VCONFKEY_NETWORK_CELLULAR_ON)
		return;

	if (_open_network() != MOBILE_AP_ERROR_NONE) {
		ERR("_open_network() is failed\n");
		__handle_open_network_error();
	}

	DBG("-\n");
	return;
}

static void __update_tethering_cellular_profile(void)
{
	int ret;
	connection_profile_h profile;
	tethering_cellular_service_type_e svc_type;

	ret = connection_get_default_cellular_service_profile(connection,
			CONNECTION_CELLULAR_SERVICE_TYPE_TETHERING, &profile);
	if (ret == CONNECTION_ERROR_NONE) {
		svc_type = __TETHERING_ONLY;
		goto DONE;
	}
	DBG("There is no tethering profile\n");

	ret = connection_get_default_cellular_service_profile(connection,
			CONNECTION_CELLULAR_SERVICE_TYPE_INTERNET, &profile);
	if (ret == CONNECTION_ERROR_NONE) {
		svc_type = __INTERNET;
		goto DONE;
	}
	ERR("Getting default connection for internet is failed\n");
	/* To-Do : Need to consider prepaid internet profile */

	if (c_prof.handle) {
		connection_profile_unset_state_changed_cb(c_prof.handle);
		connection_profile_destroy(c_prof.handle);
		c_prof.handle = NULL;
		c_prof.svc_type = __NO_SERVICE;
	}
	return;

DONE:
	if (c_prof.handle == NULL ||
			!__is_equal_profile(c_prof.handle, profile)) {
		if (c_prof.handle) {
			DBG("Tethering cellular profile is updated\n");
			connection_profile_unset_state_changed_cb(c_prof.handle);
			connection_profile_destroy(c_prof.handle);
		}

		c_prof.handle = profile;
		c_prof.svc_type = svc_type;
		connection_profile_set_state_changed_cb(c_prof.handle,
				__profile_state_changed_cb, NULL);
	} else {
		connection_profile_destroy(profile);
		connection_profile_refresh(c_prof.handle);
	}

	return;
}

static void __profile_closed_cb(connection_error_e result, void *user_data)
{
	connection_profile_refresh(c_prof.handle);

	if (result != CONNECTION_ERROR_NONE) {
		ERR("Unable to close profile [0x%X]", result);
	} else {
		DBG("Tethering profile is closed");
	}

	return;
}

static gboolean __close_tethering_profile(void)
{
	if (c_prof.handle == NULL || c_prof.svc_type == __NO_SERVICE) {
		ERR("There is no proper cellular profile\n");
		return FALSE;
	}

	int ret;
	connection_profile_state_e state;

	DBG("+\n");

	if (net_timeout_id) {
		g_source_remove(net_timeout_id);
		net_timeout_id = 0;
	}

	if (c_prof.svc_type == __INTERNET) {
		__profile_closed_cb(CONNECTION_ERROR_NONE, NULL);
		return TRUE;
	}

	ret = connection_profile_get_state(c_prof.handle, &state);
	if (ret != CONNECTION_ERROR_NONE) {
		ERR("connection_profile_get_state is failed [0x%X]\n", ret);
		return FALSE;
	}

	if (state == CONNECTION_PROFILE_STATE_DISCONNECTED) {
		DBG("Already disconnected profile\n");
		return TRUE;
	}

	ret = connection_close_profile(connection, c_prof.handle,
			__profile_closed_cb, NULL);
	if (ret != CONNECTION_ERROR_NONE) {
		ERR("Connection close Failed!!\n");
		return FALSE;
	}

	DBG("-\n");
	return TRUE;
}

static void __profile_opened_cb(connection_error_e result, void *user_data)
{
	if (c_prof.handle == NULL || c_prof.svc_type == __NO_SERVICE) {
		ERR("There is no proper profile\n");
		return;
	}

	int ret;
	connection_type_e net_type;

	DBG("+\n");

	connection_profile_refresh(c_prof.handle);

	if (_mobileap_is_disabled()) {
		__close_tethering_profile();
		return;
	}

	if (result == CONNECTION_ERROR_OPERATION_ABORTED) {
		DBG("connection_open_profile is cancelled\n");
		return;
	}

	/* Check opened and retry context */
	ret = connection_get_type(connection, &net_type);
	if (ret != CONNECTION_ERROR_NONE) {
		ERR("connection_get_type is failed\n");
		__close_tethering_profile();
		return;
	}

	if (net_type != CONNECTION_TYPE_DISCONNECTED &&
			net_type != CONNECTION_TYPE_CELLULAR) {
		DBG("Connection type is changed\n");
		__close_tethering_profile();
		return;
	}

	if (tethered_prof) {
		connection_profile_refresh(tethered_prof);
		return;
	}
	/* End of check */

	if (result != CONNECTION_ERROR_ALREADY_EXISTS &&
			result != CONNECTION_ERROR_NONE) {
		DBG("Retry to open profile [0x%X]\n", result);
		if (net_timeout_id) {
			g_source_remove(net_timeout_id);
			net_timeout_id = 0;
		}
		net_timeout_id = g_timeout_add(TETHERING_NET_OPEN_RETRY_INTERVAL,
				__try_to_open_tethering_profile,
				NULL);
		return;
	}

	DBG("Tethering profile is opened");

	__print_cellular_profile();

	connection_profile_clone(&tethered_prof, c_prof.handle);
	_set_masquerade();
	_add_default_router();
	_add_port_forward_rule();

	DBG("-\n");

	return;
}

static gboolean __open_tethering_profile(void)
{
	if (c_prof.handle == NULL || c_prof.svc_type == __NO_SERVICE) {
		ERR("There is no proper cellular profile\n");
		return FALSE;
	}

	int ret;

	DBG("+\n");

	if (c_prof.svc_type == __INTERNET) {
		return TRUE;
	}

	if (__is_connected_profile(c_prof.handle)) {
		DBG("Already connected profile\n");
		return TRUE;
	}

	ret = connection_open_profile(connection, c_prof.handle,
			__profile_opened_cb, NULL);
	if (ret != CONNECTION_ERROR_NONE) {
		ERR("Unable to open profile [0x%X]", ret);
		return FALSE;
	}

	DBG("-\n");
	return TRUE;
}

static gboolean __try_to_open_tethering_profile(gpointer user_data)
{
	DBG("+\n");

	if (_mobileap_is_disabled()) {
		DBG("Tethering is disabled\n");
		net_timeout_id = 0;
		return FALSE;
	}

	if (__open_tethering_profile() == FALSE)
		return TRUE;

	net_timeout_id = 0;
	return FALSE;
}

gboolean _is_trying_network_operation(void)
{
	if (net_timeout_id)
		return TRUE;

	return FALSE;
}

gboolean _get_network_interface_name(char **if_name)
{
	if (if_name == NULL) {
		ERR("if_name is NULL\n");
		return FALSE;
	}

	if (tethered_prof == NULL) {
		return FALSE;
	}

	int ret = 0;

	connection_profile_refresh(tethered_prof);

	ret = connection_profile_get_network_interface_name(tethered_prof, if_name);
	if (ret != CONNECTION_ERROR_NONE) {
		ERR("connection_profile_get_network_interface_name is failed : 0x%X\n", ret);
		return FALSE;
	}

	if (strlen(*if_name) == 0) {
		ERR("if_name is zero length\n");
		free(*if_name);
		return FALSE;
	}

	return TRUE;
}

gboolean _get_network_gateway_address(char **ip)
{
	if (ip == NULL) {
		ERR("ip is NULL\n");
		return FALSE;
	}

	if (tethered_prof == NULL) {
		return FALSE;
	}

	int ret = 0;

	connection_profile_refresh(tethered_prof);

	ret = connection_profile_get_gateway_address(tethered_prof,
			CONNECTION_ADDRESS_FAMILY_IPV4, ip);
	if (ret != CONNECTION_ERROR_NONE) {
		ERR("connection_profile_get_ip_address is failed : 0x%X\n", ret);
		return FALSE;
	}

	return TRUE;
}

gboolean _set_masquerade(void)
{
	char *if_name = NULL;

	if (_get_network_interface_name(&if_name) == FALSE) {
		ERR("_get_network_interface_name is failed\n");
		return FALSE;
	}
	SDBG("Network interface : %s\n", if_name);

	_mh_core_enable_masquerade(if_name);
	free(if_name);

	return TRUE;
}

gboolean _unset_masquerade(void)
{
	if (tethered_prof == NULL) {
		DBG("There is nothing to unset masquerading\n");
		return TRUE;
	}

	char *if_name = NULL;

	if (_get_network_interface_name(&if_name) == FALSE) {
		ERR("_get_network_interface_name is failed\n");
		return FALSE;
	}
	SDBG("Network interface : %s\n", if_name);

	_mh_core_disable_masquerade(if_name);
	free(if_name);

	return TRUE;
}

gboolean _add_default_router(void)
{
	if (tethered_prof == NULL) {
		DBG("There is no network\n");
		return TRUE;
	}

	char cmd[MAX_BUF_SIZE] = {0, };
	char *ip = NULL;
	char *interface = NULL;

	if (_get_network_gateway_address(&ip) == FALSE) {
		return FALSE;
	}

	if (_get_network_interface_name(&interface) == FALSE) {
		free(ip);
		return FALSE;
	}

	snprintf(cmd, sizeof(cmd), "%s route replace "DEFAULT_ROUTER,
			IP_CMD, ip, interface, TETHERING_ROUTING_TABLE);
	free(interface);
	free(ip);

	if (_execute_command(cmd)) {
		ERR("%s is failed\n", cmd);
		return FALSE;
	}

	return TRUE;
}

gboolean _del_default_router(void)
{
	if (tethered_prof == NULL) {
		DBG("There is no network\n");
		return TRUE;
	}

	char cmd[MAX_BUF_SIZE] = {0, };
	char *ip = NULL;
	char *interface = NULL;

	if (_get_network_gateway_address(&ip) == FALSE) {
		return FALSE;
	}

	if (_get_network_interface_name(&interface) == FALSE) {
		free(ip);
		return FALSE;
	}

	snprintf(cmd, sizeof(cmd), "%s route del "DEFAULT_ROUTER,
			IP_CMD, ip, interface, TETHERING_ROUTING_TABLE);
	free(interface);
	free(ip);

	if (_execute_command(cmd)) {
		ERR("%s is failed\n", cmd);
		return FALSE;
	}

	return TRUE;
}

void _add_port_forward_rule(void)
{
	DBG("+\n");

	GSList *l;
	port_forward_info_s *pf;

	if (access(MH_PORT_FORWARD_CONF_FILEPATH, F_OK) < 0) {
		return;
	}

	if (__read_port_forward_info(MH_PORT_FORWARD_CONF_FILEPATH) == FALSE) {
		ERR("__read_port_forward_info() is failed\n");
		return;
	}

	_iptables_create_chain(TABLE_NAT, TETH_NAT_PRE);
	_iptables_add_rule(PKT_REDIRECTION_RULE, TABLE_NAT, CHAIN_PRE,
		TETH_NAT_PRE);

	for (l = port_forward_info; l; l = g_slist_next(l)) {
		pf = (port_forward_info_s *)l->data;

		if (__is_valid_port_forward_info(pf) == FALSE)
			continue;

		_iptables_add_rule(PORT_FW_RULE, TABLE_NAT, TETH_NAT_PRE,
			pf->input_interface, pf->proto, pf->org_dest_ip,
			pf->new_dest_ip, (int)pf->org_dest_port, (int)pf->new_dest_port);
	}

	return;
}

void _del_port_forward_rule(void)
{
	GSList *l;
	GSList *temp_l;
	port_forward_info_s *pf;

	DBG("+\n");

	if (port_forward_info == NULL) {
		DBG("port forwarding rules were not applied, no need to deleted\n");
		return;
	}

	for(l = port_forward_info; l;) {
		pf = (port_forward_info_s *)l->data;
		if (pf) {
			g_free(pf->new_dest_ip);
			g_free(pf->org_dest_ip);
			g_free(pf->proto);
			g_free(pf->input_interface);
			g_free(pf);
		}

		temp_l = l;
		l = g_slist_next(l);
		port_forward_info = g_slist_delete_link(port_forward_info,
					temp_l);
	}

	_iptables_delete_rule(PKT_REDIRECTION_RULE, TABLE_NAT, CHAIN_PRE,
		TETH_NAT_PRE);
	_iptables_flush_rules(TABLE_NAT, TETH_NAT_PRE);
	_iptables_delete_chain(TABLE_NAT, TETH_NAT_PRE);

	return;
}

int _open_network(void)
{
	DBG("+\n");

	int ret;
	int con_ret;
	int cellular_state;
	connection_type_e net_type;

	ret = connection_get_type(connection, &net_type);
	if (ret != CONNECTION_ERROR_NONE) {
		ERR("connection_get_type is failed\n");
		con_ret = __get_conn_error(ret);
		return con_ret;
	}

	if (vconf_get_int(VCONFKEY_NETWORK_CELLULAR_STATE, &cellular_state) < 0) {
		ERR("vconf_get_int is failed\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	DBG("Connection type : %d, Cellular State : %d\n",
			net_type, cellular_state);

	if (tethered_prof) {
		if (net_type == CONNECTION_TYPE_CELLULAR) {
			__update_tethering_cellular_profile();
			if (__is_equal_profile(tethered_prof, c_prof.handle)) {
				DBG("Cellular profile is already configured\n");
				return MOBILE_AP_ERROR_NONE;
			}
		}

		DBG("There is already tethered profile\n");
		_close_network();
	}

	if (net_type == CONNECTION_TYPE_DISCONNECTED &&
			cellular_state != VCONFKEY_NETWORK_CELLULAR_ON) {
		DBG("There is no network\n");
		/* Callback will handle this once Network type is changed */
		return MOBILE_AP_ERROR_NONE;
	}

	switch (net_type) {
	case CONNECTION_TYPE_DISCONNECTED:
	case CONNECTION_TYPE_CELLULAR:
		__update_tethering_cellular_profile();
		if (c_prof.handle == NULL || c_prof.svc_type == __NO_SERVICE) {
			DBG("There is no proper cellular profile for tethering\n");
			return MOBILE_AP_ERROR_NONE;
		}
		__print_cellular_profile();

		if (!__is_connected_profile(c_prof.handle)) {
			if (c_prof.svc_type != __TETHERING_ONLY) {
				return MOBILE_AP_ERROR_NONE;
			}

			if (net_timeout_id) {
				g_source_remove(net_timeout_id);
				net_timeout_id = 0;
			}
			net_timeout_id = g_timeout_add(TETHERING_NET_OPEN_RETRY_INTERVAL,
					__try_to_open_tethering_profile, NULL);

			return MOBILE_AP_ERROR_NONE;
		}
		connection_profile_clone(&tethered_prof, c_prof.handle);
		break;

	case CONNECTION_TYPE_WIFI:
	case CONNECTION_TYPE_ETHERNET:
	case CONNECTION_TYPE_BT:
		ret = connection_get_current_profile(connection, &tethered_prof);
		if (ret != CONNECTION_ERROR_NONE) {
			ERR("connection_get_current_profile is failed [0x%X]\n", ret);
			con_ret = __get_conn_error(ret);
			return con_ret;
		}
		break;

	default:
		ERR("Unknown connection type : %d\n", net_type);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	_set_masquerade();
	_add_default_router();
	_add_port_forward_rule();

	DBG("-\n");

	return MOBILE_AP_ERROR_NONE;
}

void _close_network(void)
{
	if (tethered_prof == NULL) {
		DBG("There is no tethered profile\n");
		return;
	}

	DBG("+\n");

	_del_port_forward_rule();
	_del_default_router();
	_unset_masquerade();

	connection_profile_destroy(tethered_prof);
	tethered_prof = NULL;
	__close_tethering_profile();

	DBG("-\n");
	return;
}

gboolean _init_network(void *user_data)
{
	if (user_data == NULL) {
		ERR("Invalid parameter\n");
		return FALSE;
	}

	int ret;

	obj = (Tethering *)user_data;

	ret = connection_create(&connection);
	if (ret != CONNECTION_ERROR_NONE) {
		ERR("connection_create is failed : 0x%X\n", ret);
		goto FAIL;
	}

	ret = connection_set_type_changed_cb(connection,
			__connection_type_changed_cb, user_data);
	if (ret != CONNECTION_ERROR_NONE) {
		ERR("connection_set_type_changed cb is failed : 0x%X\n", ret);
		goto FAIL;
	}

	ret = vconf_notify_key_changed(VCONFKEY_NETWORK_CELLULAR_STATE,
			__cellular_state_changed_cb, NULL);
	if (ret < 0) {
		ERR("vconf_notify_key_changed is failed : %d\n", ret);
		connection_unset_type_changed_cb(connection);
		goto FAIL;
	}

	__update_tethering_cellular_profile();

	return TRUE;

FAIL:
	if (connection) {
		connection_destroy(connection);
		connection = NULL;
	}

	return FALSE;
}

gboolean _deinit_network(void)
{
	int ret;

	if (connection == NULL) {
		ERR("Connection handle is not initialized\n");
		return TRUE;
	}

	if (c_prof.handle) {
		vconf_ignore_key_changed(VCONFKEY_NETWORK_CELLULAR_STATE,
				__cellular_state_changed_cb);
		connection_profile_unset_state_changed_cb(c_prof.handle);
		connection_profile_destroy(c_prof.handle);
		c_prof.handle = NULL;
		c_prof.svc_type = __NO_SERVICE;
	}

	ret = connection_unset_type_changed_cb(connection);
	if (ret != CONNECTION_ERROR_NONE) {
		ERR("connection_unset_type_changed_cb is failed : %d\n", ret);
	}

	connection_destroy(connection);
	connection = NULL;
	obj = NULL;

	return TRUE;
}
