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
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include "mobileap_iptables.h"
#include "mobileap_softap.h"
#include "mobileap.h"
#include "mobileap_common.h"

#define CREATE_CHAIN_STR		"-t %s -N %s"  /* table_name, chain_name */
#define REDIRECTION_ADD_RULE_STR	"-t %s -A %s -j %s"
#define REDIRECTION_DEL_RULE_STR	"-t %s -D %s -j %s"
#define FLUSH_CMD_STR		"-t %s -F %s"
#define DELETE_CHAIN_STR	"-t %s -X %s"
#define FORWARD_RULE_WITH_ACTION_STR		"-t %s -A %s -i %s -o %s -j %s"
#define FORWARD_RULE_WITH_ACTION_AND_STATE_STR	"-t %s -A %s -i %s -o %s -m state --state %s -j %s"
#define MASQUERADE_RULE_STR		"-t %s -A %s -o %s -j MASQUERADE"
#define PORT_FORWARD_RULE_STR	"-t %s -A %s -i %s -p %s -d %s --dport %d -j DNAT --to %s:%d"
#define CLAMP_MSS_RULE_STR	"-t %s -A %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
#define DEFAULT_RULE_STR	"-t %s -A %s -j %s"


int _iptables_create_chain(const char *table_name, const char *chain_name)
{
	char cmd[MAX_BUF_SIZE] = { 0, };

	snprintf(cmd, sizeof(cmd), "%s "CREATE_CHAIN_STR, IPTABLES, table_name,
		chain_name);
	SDBG("command [%s]\n", cmd);
	if (_execute_command(cmd)) {
		SERR("command [%s] failed\n", cmd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	return MOBILE_AP_ERROR_NONE;
}

int _iptables_flush_rules(const char *table_name, const char *chain_name)
{
	char cmd[MAX_BUF_SIZE] = { 0, };

	snprintf(cmd, sizeof(cmd), "%s "FLUSH_CMD_STR, IPTABLES, table_name,
		chain_name);
	SDBG("command [%s]\n", cmd);
	if (_execute_command(cmd)) {
		SERR("command [%s] failed\n", cmd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	return MOBILE_AP_ERROR_NONE;
}

int _iptables_delete_chain(const char *table_name, const char *chain_name)
{
	char cmd[MAX_BUF_SIZE] = { 0, };

	snprintf(cmd, sizeof(cmd), "%s "DELETE_CHAIN_STR, IPTABLES, table_name,
		chain_name);
	SDBG("command [%s]\n", cmd);
	if (_execute_command(cmd)) {
		SERR("command [%s] failed\n", cmd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	return MOBILE_AP_ERROR_NONE;
}

int _iptables_add_rule(iptables_rule_e rule_type, const char *table, const char *chain, ...)
{
	if (table == NULL || chain == NULL) {
		ERR("invalid parameters\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	va_list ap;
	char cmd[MAX_BUF_SIZE] = { 0, };

	va_start(ap, chain);
	switch (rule_type) {
	case PKT_REDIRECTION_RULE: {
		char *dst_chain;

		dst_chain = va_arg(ap, char *);
		if (dst_chain == NULL) {
			ERR("invalid parameters\n");
			goto ERROR_EXIT;
		}

		snprintf(cmd, sizeof(cmd), "%s "REDIRECTION_ADD_RULE_STR, IPTABLES,
				table, chain, dst_chain);
		break;
	}

	case FORWARD_RULE_WITH_ACTION: {
		char *in_iface = NULL;
		char *out_iface = NULL;
		char *action = NULL;

		in_iface = va_arg(ap, char *);
		out_iface = va_arg(ap, char *);
		action = va_arg(ap, char *);

		if (in_iface == NULL || out_iface == NULL || action == NULL) {
			ERR("invalid parameters\n");
			goto ERROR_EXIT;
		}

		snprintf(cmd, sizeof(cmd), "%s "FORWARD_RULE_WITH_ACTION_STR, IPTABLES,
			table, chain, in_iface, out_iface, action);
		break;
	}

	case FORWARD_RULE_WITH_ACTION_AND_STATE: {
		char *in_iface = NULL;
		char *out_iface = NULL;
		char *action = NULL;
		char *state = NULL;

		in_iface = va_arg(ap, char *);
		out_iface = va_arg(ap, char *);
		action = va_arg(ap, char *);
		state = va_arg(ap, char *);

		if (in_iface == NULL || out_iface == NULL || action == NULL ||
				state == NULL) {
			ERR("invalid parameters\n");
			goto ERROR_EXIT;
		}

		snprintf(cmd, sizeof(cmd), "%s "FORWARD_RULE_WITH_ACTION_AND_STATE_STR,
			IPTABLES, table, chain, in_iface, out_iface, state, action);

		break;
	}

	case PORT_FW_RULE: {
		char *ip_iface = NULL;
		char *proto = NULL;
		char *org_ip = NULL;
		char *final_ip = NULL;
		unsigned short org_port = 0;
		unsigned short final_port = 0;

		ip_iface = va_arg(ap, char *);
		proto = va_arg(ap, char *);
		org_ip = va_arg(ap, char *);
		final_ip = va_arg(ap, char *);
		org_port = va_arg(ap, int);
		final_port = va_arg(ap, int);

		if (ip_iface == NULL || proto == NULL || org_ip == NULL ||
				final_ip == NULL) {
			ERR("invalid parameters\n");
			goto ERROR_EXIT;
		}

		snprintf(cmd, sizeof(cmd), "%s "PORT_FORWARD_RULE_STR,
			IPTABLES, table, chain, ip_iface, proto,
			org_ip, org_port, final_ip, final_port);
		break;
	}

	case MASQ_RULE: {
		char *ext_iface = NULL;

		ext_iface = va_arg(ap, char *);

		if (ext_iface == NULL) {
			ERR("invalid parameters\n");
			goto ERROR_EXIT;
		}

		snprintf(cmd, sizeof(cmd), "%s "MASQUERADE_RULE_STR, IPTABLES,
				table, chain, ext_iface);
		break;
	}

	case CLAMP_MSS_RULE: {
		snprintf(cmd, sizeof(cmd), "%s "CLAMP_MSS_RULE_STR, IPTABLES,
			table, chain);
		break;
	}

	case DEFAULT_RULE: {
		char *action;

		action = va_arg(ap, char *);

		if (action == NULL) {
			ERR("invalid parameters\n");
			goto ERROR_EXIT;
		}

		snprintf(cmd, sizeof(cmd), "%s "DEFAULT_RULE_STR, IPTABLES,
			table, chain, action);
		break;
	}

	default:
		ERR("case not supported\n");
		goto ERROR_EXIT;
	}

	if (_execute_command(cmd)) {
		SERR("command [%s] failed\n", cmd);
		goto ERROR_EXIT;
	}

	va_end(ap);
	return MOBILE_AP_ERROR_NONE;

ERROR_EXIT:
	va_end(ap);
	return MOBILE_AP_ERROR_INVALID_PARAM;
}

int _iptables_delete_rule(iptables_rule_e rule_type, const char *table, const char *chain, ...)
{
	va_list ap;
	char cmd[MAX_BUF_SIZE] = { 0, };

	va_start(ap, chain);
	switch (rule_type) {
	case PKT_REDIRECTION_RULE: {
		char *dst_chain = NULL;

		dst_chain = va_arg(ap, char *);
		snprintf(cmd, sizeof(cmd), "%s "REDIRECTION_DEL_RULE_STR, IPTABLES,
			table, chain, dst_chain);
		break;
	}
	default:
		ERR("case not supported\n");
		goto ERROR_EXIT;
	}

	if (_execute_command(cmd)) {
		SERR("command [%s] failed\n", cmd);
		return MOBILE_AP_ERROR_INTERNAL;
	}
	va_end(ap);
	return MOBILE_AP_ERROR_NONE;

ERROR_EXIT:
	va_end(ap);
	return MOBILE_AP_ERROR_INTERNAL;
}

int _get_data_usage(const char *src, const char *dest, unsigned long long *tx,
		unsigned long long *rx)
{
	if (src == NULL || src[0] == '\0' || dest == NULL || dest[0] == '\0' ||
			tx == NULL || rx == NULL) {
		ERR("Invalid parameter\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	char cmd[MAX_BUF_SIZE] = {0, };
	char buf[MAX_BUF_SIZE] = {0, };
	FILE *fp = NULL;

	/* Tx : Src. -> Dest. */
	snprintf(cmd, sizeof(cmd),
		"%s -t %s -L %s -vx | %s -v DROP | %s \"%s[ ]*%s\" | %s '{ print $2 }' > %s",
		IPTABLES, TABLE_FILTER, TETH_FILTER_FW, GREP, GREP, src, dest, AWK, DATA_USAGE_FILE);
	if (system(cmd) < 0) {
		ERR("cmd %s is failed\n", cmd);
	}

	*tx = 0;

	fp = fopen(DATA_USAGE_FILE, "r");
	if (fp == NULL) {
		ERR("%s open failed\n", DATA_USAGE_FILE);
		ERR("%s\n", strerror(errno));
		return MOBILE_AP_ERROR_INTERNAL;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		*tx += atoll(buf);
	}

	fclose(fp);
	unlink(DATA_USAGE_FILE);

	/* Rx : Dest. -> Src. */
	snprintf(cmd, sizeof(cmd),
		"%s -t %s -L %s -vx | %s -v DROP | %s \"%s[ ]*%s\" | %s '{ print $2 }' > %s",
		IPTABLES, TABLE_FILTER, TETH_FILTER_FW, GREP, GREP, dest, src, AWK, DATA_USAGE_FILE);
	if (system(cmd) < 0) {
		ERR("cmd %s is failed\n", cmd);
	}

	*rx = 0;

	fp = fopen(DATA_USAGE_FILE, "r");
	if (fp == NULL) {
		ERR("%s open failed\n", DATA_USAGE_FILE);
		ERR("%s\n", strerror(errno));
		return MOBILE_AP_ERROR_INTERNAL;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		*rx += atoll(buf);
	}

	fclose(fp);
	unlink(DATA_USAGE_FILE);

	return MOBILE_AP_ERROR_NONE;
}
