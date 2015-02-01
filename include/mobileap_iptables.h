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

#ifndef __MOBILEAP_IPTABLES_H__
#define __MOBILEAP_IPTABLES_H__

#define IPTABLES		"/usr/sbin/iptables"
#define TABLE_FILTER		"filter"
#define TABLE_NAT		"nat"
#define TABLE_MANGLE		"mangle"
#define CHAIN_FW		"FORWARD"
#define CHAIN_POST		"POSTROUTING"
#define CHAIN_PRE		"PREROUTING"
#define TETH_FILTER_FW		"teth_filter_fw"
#define TETH_NAT_POST		"teth_nat_post"
#define TETH_NAT_PRE		"teth_nat_pre"
#define STATE_RELATED_ESTAB	"RELATED,ESTABLISHED"
#define STATE_INVALID		"INVALID"
#define ACTION_DROP		"DROP"
#define ACTION_RETURN		"RETURN"

typedef enum {
	PKT_REDIRECTION_RULE,
	FORWARD_RULE_WITH_ACTION,
	FORWARD_RULE_WITH_ACTION_AND_STATE,
	DEFAULT_RULE,
	PORT_FW_RULE,
	MASQ_RULE,
	CLAMP_MSS_RULE,
} iptables_rule_e;

int _iptables_create_chain(const char *table_name, const char *chain_name);
int _iptables_flush_rules(const char *table_name, const char *chain_name);
int _iptables_delete_chain(const char *table_name, const char *chain_name);
int _iptables_add_rule(iptables_rule_e rule_type, const char *table,
	const char *chain, ...);
int _iptables_delete_rule(iptables_rule_e rule_type, const char *table,
	const char *chain, ...);
int _get_data_usage(const char *src, const char *dest, unsigned long long *tx,
	unsigned long long *rx);
#endif
