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
#include <dbus/dbus.h>
#include <bluetooth.h>
#ifndef TIZEN_TV
#include <bluetooth_internal.h>
#endif

#include "mobileap_softap.h"
#include "mobileap_common.h"
#include "mobileap_bluetooth.h"
#include "mobileap_handler.h"
#include "mobileap_notification.h"

typedef struct {
	bt_device_info_s *info;
	char *intf_name;
	const in_addr_t intf_ip;
} __bt_remote_device_s;

static __bt_remote_device_s __bt_remote_devices[MOBILE_AP_MAX_BT_STA] = {
	{NULL, NULL, IP_ADDRESS_BT_1},
	{NULL, NULL, IP_ADDRESS_BT_2},
	{NULL, NULL, IP_ADDRESS_BT_3},
	{NULL, NULL, IP_ADDRESS_BT_4}};

static GDBusMethodInvocation *g_context = NULL;

static void __bt_nap_connection_changed(bool connected, const char *remote_address,
				const char *interface_name, void *user_data);
static void __bt_adapter_state_changed(int result, bt_adapter_state_e adapter_state, void *user_data);
static void __handle_bt_adapter_visibility();

int __recheck_bt_adapter_timer = 0;

static __bt_remote_device_s *__find_bt_remote(const char *mac)
{
	int i;

	for (i = 0; i < MOBILE_AP_MAX_BT_STA; i++) {
		if (__bt_remote_devices[i].info == NULL)
			continue;

		if (!g_ascii_strcasecmp(__bt_remote_devices[i].info->remote_address, mac))
			break;
	}

	if (i == MOBILE_AP_MAX_BT_STA) {
		SERR("Not found : %s\n", mac);
		return NULL;
	}

	return &__bt_remote_devices[i];
}

static __bt_remote_device_s *__add_bt_remote(bt_device_info_s *info, const char *intf_name)
{
	int i;

	for (i = 0; i < MOBILE_AP_MAX_BT_STA; i++) {
		if (__bt_remote_devices[i].info == NULL)
			break;
	}

	if (i == MOBILE_AP_MAX_BT_STA) {
		ERR("Too many BT devices are connected\n");
		return NULL;
	}

	__bt_remote_devices[i].intf_name = g_strdup(intf_name);
	if (__bt_remote_devices[i].intf_name == NULL) {
		ERR("Memory allocation failed\n");
		return NULL;
	}

	_add_interface_routing(__bt_remote_devices[i].intf_name,
			__bt_remote_devices[i].intf_ip);
	_add_routing_rule(__bt_remote_devices[i].intf_name);
	__bt_remote_devices[i].info = info;

	return &__bt_remote_devices[i];
}

static gboolean __del_bt_remote(const char *mac)
{
	int i;

	for (i = 0; i < MOBILE_AP_MAX_BT_STA; i++) {
		if (__bt_remote_devices[i].info == NULL)
			continue;

		if (!g_ascii_strcasecmp(__bt_remote_devices[i].info->remote_address, mac))
			break;
	}

	if (i == MOBILE_AP_MAX_BT_STA) {
		SERR("Not found : %s\n", mac);
		return FALSE;
	}

	_del_routing_rule(__bt_remote_devices[i].intf_name);
	_del_interface_routing(__bt_remote_devices[i].intf_name,
			__bt_remote_devices[i].intf_ip);
	 bt_adapter_free_device_info(__bt_remote_devices[i].info);
	 g_free(__bt_remote_devices[i].intf_name);

	 __bt_remote_devices[i].info = NULL;
	 __bt_remote_devices[i].intf_name = NULL;

	return TRUE;
}

static void __del_bt_remote_all(void)
{
	int i;

	for (i = 0; i < MOBILE_AP_MAX_BT_STA; i++) {
		if (__bt_remote_devices[i].info) {
			bt_adapter_free_device_info(__bt_remote_devices[i].info);
			__bt_remote_devices[i].info = NULL;
		}

		if (__bt_remote_devices[i].intf_name) {
			_del_routing_rule(__bt_remote_devices[i].intf_name);
			_del_interface_routing(__bt_remote_devices[i].intf_name,
				__bt_remote_devices[i].intf_ip);
			g_free(__bt_remote_devices[i].intf_name);
			__bt_remote_devices[i].intf_name = NULL;
		}
	}

	return;
}

static mobile_ap_error_code_e __init_bt(Tethering *obj)
{
	int ret;

	ret = bt_initialize();
	if (ret != BT_ERROR_NONE) {
		ERR("bt_initialize is failed : %d\n", ret);
		return MOBILE_AP_ERROR_RESOURCE;
	}

	ret = bt_adapter_set_state_changed_cb(__bt_adapter_state_changed, (void *)obj);
	if (ret != BT_ERROR_NONE) {
		ERR("bt_adapter_set_state_changed_cb is failed : %d\n", ret);
		bt_deinitialize();
		return MOBILE_AP_ERROR_RESOURCE;
	}

	return MOBILE_AP_ERROR_NONE;
}

static void __deinit_bt(void)
{
	int ret;

	ret = bt_adapter_unset_state_changed_cb();
	if (ret != BT_ERROR_NONE)
		ERR("bt_adapter_unset_state_changed_cb is failed : %d\n", ret);

	ret = bt_deinitialize();
	if (ret != BT_ERROR_NONE)
		ERR("bt_deinitialize is failed : %d\n", ret);

	return;
}

static gboolean __is_bt_adapter_on(void)
{
	int ret;
	bt_adapter_state_e adapter_state = BT_ADAPTER_DISABLED;

	ret = bt_adapter_get_state(&adapter_state);
	if (ret != BT_ERROR_NONE) {
		ERR("bt_adapter_get_state is failed : %d\n", ret);
		return FALSE;
	}

	if (adapter_state == BT_ADAPTER_ENABLED)
		return TRUE;
	else
		return FALSE;
}

gboolean __bt_adapter_timeout_cb(Tethering *obj)
{
	DBG("+\n");

	static int retry_count = 0;
	if (__is_bt_adapter_on() == TRUE) {
		DBG("BT Adapter is enabled by other process \n");
		retry_count = 0;
		DBG("-\n");
		return FALSE;
	} else {
		if (++retry_count >= PS_RECHECK_COUNT_MAX) {
			retry_count = 0;
			ERR("_enable_bt_tethering() is failed because of bt_adapter_eanbled() failed:n");
			_mobileap_clear_state(MOBILE_AP_STATE_BT);
			__deinit_bt();
			tethering_complete_enable_bt_tethering(obj, g_context, MOBILE_AP_ERROR_INTERNAL);
			g_context = NULL;
			_unblock_device_sleep();
			DBG("-\n");
			return FALSE;
		} else {
			DBG("-\n");
			return TRUE;
		}
	}
}

static mobile_ap_error_code_e __turn_on_bt_adapter(gpointer data)
{
	int ret;

	Tethering *obj = (Tethering *)data;

	ret = bt_adapter_enable();
	if (ret == BT_ERROR_NOW_IN_PROGRESS) {
		if (__recheck_bt_adapter_timer) {
			g_source_remove(__recheck_bt_adapter_timer);
		}
		__recheck_bt_adapter_timer = g_timeout_add(PS_RECHECK_INTERVAL,
				__bt_adapter_timeout_cb, obj);
		return MOBILE_AP_ERROR_NONE;
	}

	if (ret != BT_ERROR_NONE && ret != BT_ERROR_ALREADY_DONE) {
		ERR("bt_adapter_enable is failed : %d\n", ret);
#ifndef TIZEN_TV
		if (ret == BT_ERROR_PERMISSION_DENIED)
			return MOBILE_AP_ERROR_PERMISSION_DENIED;
		else
#endif
			return MOBILE_AP_ERROR_RESOURCE;
	}

	return MOBILE_AP_ERROR_NONE;
}

static mobile_ap_error_code_e __turn_on_bt_nap(Tethering *obj)
{
	int bt_ret = BT_ERROR_NONE;

	bt_ret = bt_nap_set_connection_state_changed_cb(__bt_nap_connection_changed, (void *)obj);
	if (bt_ret != BT_ERROR_NONE) {
		ERR("bt_nap_set_connection_state_changed_cb is failed : %d\n", bt_ret);
		return MOBILE_AP_ERROR_RESOURCE;
	}

	bt_ret = bt_nap_activate();
	if (bt_ret != BT_ERROR_NONE && bt_ret != BT_ERROR_ALREADY_DONE) {
		bt_nap_unset_connection_state_changed_cb();
		ERR("bt_nap_activate is failed : %d\n", bt_ret);
#ifndef TIZEN_TV
		if (bt_ret == BT_ERROR_PERMISSION_DENIED)
			return MOBILE_AP_ERROR_PERMISSION_DENIED;
		else
#endif
			return MOBILE_AP_ERROR_RESOURCE;
	}

	return MOBILE_AP_ERROR_NONE;
}

static void __turn_off_bt_nap(void)
{
	int bt_ret;

	bt_ret = bt_nap_deactivate();
	if (bt_ret != BT_ERROR_NONE)
		ERR("bt_nap_deactivate is failed : %d\n", bt_ret);
	else
		DBG("bt_nap_deactivate is called\n");

	bt_ret = bt_nap_unset_connection_state_changed_cb();
	if (bt_ret != BT_ERROR_NONE)
		ERR("bt_nap_unset_connection_state_changed_cb is failed : %d\n", bt_ret);

	return;
}

mobile_ap_error_code_e _enable_bt_tethering(Tethering *obj)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;

	DBG("+\n");
	if (__recheck_bt_adapter_timer) {
		g_source_remove(__recheck_bt_adapter_timer);
		__recheck_bt_adapter_timer = 0;
	}

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI_AP)) {
		ERR("Wi-Fi AP is enabled\n");
		return MOBILE_AP_ERROR_RESOURCE;
	}

	ret = _init_tethering();
	if (ret != MOBILE_AP_ERROR_NONE) {
		return ret;
	}

	ret = __turn_on_bt_nap(obj);
	if (ret != MOBILE_AP_ERROR_NONE) {
		_deinit_tethering();
		return ret;
	}
	_delete_timeout_noti();
	_init_timeout_cb(MOBILE_AP_TYPE_BT, (void *)obj);
	_start_timeout_cb(MOBILE_AP_TYPE_BT, time(NULL) + TETHERING_CONN_TIMEOUT);

	DBG("-\n");
	return ret;
}

mobile_ap_error_code_e _disable_bt_tethering(Tethering *obj)
{
	int ret = BT_ERROR_NONE;
	if (!_mobileap_is_enabled(MOBILE_AP_STATE_BT)) {
		ERR("BT tethering has not been enabled\n");
		return MOBILE_AP_ERROR_NOT_ENABLED;
	}
	ret = bt_adapter_unset_visibility_mode_changed_cb();
	if (ret != BT_ERROR_NONE)
		ERR("bt_adapter_unset_visibility_mode_changed_cb is failed : %d\n", ret);

	_block_device_sleep();
	if (__is_bt_adapter_on()) {
		__turn_off_bt_nap();
		__deinit_bt();
	}

	_remove_station_info_all(MOBILE_AP_TYPE_BT);
	__del_bt_remote_all();
	_deinit_timeout_cb(MOBILE_AP_TYPE_BT);

	_deinit_tethering();
	_mobileap_clear_state(MOBILE_AP_STATE_BT);
	_unblock_device_sleep();

	return MOBILE_AP_ERROR_NONE;
}


static void __bt_nap_connection_changed(bool connected, const char *remote_address, const char *interface_name, void *user_data)
{
	if (remote_address == NULL || interface_name == NULL || user_data == NULL) {
		ERR("Invalid param\n");
		return;
	}

	__bt_remote_device_s *remote;
	bt_device_info_s *info;
	int ret;
	int n_station = 0;

	SDBG("Remote address : %s, Interface : %s, %s\n",
			remote_address, interface_name,
			connected ? "Connected" : "Disconnected");

	if (connected) {
		ret = bt_adapter_get_bonded_device_info(remote_address, &info);
		if (ret != BT_ERROR_NONE) {
			ERR("bt_adapter_get_bonded_device_info is failed : %d\n", ret);
			return;
		}

		remote = __add_bt_remote(info, interface_name);
		if (remote == NULL) {
			ERR("__add_bt_remote is failed\n");
			 bt_adapter_free_device_info(info);
			return;
		}

		ret = _mh_core_set_ip_address(interface_name, remote->intf_ip);
		if (ret != MOBILE_AP_ERROR_NONE) {
			ERR("Setting ip address error : %d\n", ret);
		}
	} else {
		_remove_station_info(remote_address, _slist_find_station_by_mac);
		if (__del_bt_remote(remote_address) == FALSE) {
			ERR("__del_bt_remote is failed\n");
		}

		_get_station_count((gconstpointer)MOBILE_AP_TYPE_BT,
				_slist_find_station_by_interface, &n_station);
		if (n_station == 0)
			_start_timeout_cb(MOBILE_AP_TYPE_BT, time(NULL) + TETHERING_CONN_TIMEOUT);
	}

	return;
}

static void __bt_adapter_state_changed(int result, bt_adapter_state_e adapter_state, void *user_data)
{
	if (user_data == NULL) {
		ERR("Invalid param\n");
		return;
	}

	DBG("+\n");

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_BT))
		return;

	int ret = MOBILE_AP_ERROR_RESOURCE;
	Tethering *obj = (Tethering *)user_data;

	if (result != BT_ERROR_NONE) {
		ERR("BT Adapter operation is failed : %d\n", result);
		goto FAIL;
	}

	SDBG("BT Adapter is %s\n", adapter_state == BT_ADAPTER_ENABLED ?
			"enabled" : "disabled");
	if (adapter_state == BT_ADAPTER_DISABLED) {
		_disable_bt_tethering(obj);
		tethering_emit_bluetooth_off(obj, SIGNAL_MSG_NOT_AVAIL_INTERFACE);
		return;
	} else {
		ret = _enable_bt_tethering(obj);
		if (ret != MOBILE_AP_ERROR_NONE) {
			ERR("_enable_bt_tethering() is failed : %d\n", ret);
			__deinit_bt();
			goto FAIL;
		}

		tethering_emit_bluetooth_on(obj);
		_create_tethering_active_noti();
		tethering_complete_enable_bt_tethering(obj, g_context, ret);
		__handle_bt_adapter_visibility();
		g_context = NULL;
		_unblock_device_sleep();

		return;
	}

FAIL:
	tethering_complete_enable_bt_tethering(obj, g_context, ret);
	g_context = NULL;
	_mobileap_clear_state(MOBILE_AP_STATE_BT);
	_unblock_device_sleep();

	return;
}

void _bt_get_remote_device_name(const char *mac, char **name)
{
	if (mac == NULL || name == NULL) {
		ERR("Invalid param\n");
		return;
	}

	__bt_remote_device_s *remote = NULL;

	remote = __find_bt_remote(mac);
	if (remote == NULL)
		return;

	*name = g_strdup(remote->info->remote_name);
	if (*name == NULL) {
		ERR("Memory allocation failed\n");
		return;
	}

	return;
}

static void __bt_adapter_visibility_changed_cb(int result,
				bt_adapter_visibility_mode_e visibility_mode, void *user_data)
{
	DBG("+\n");

	int ret;
	int duration;
	bt_adapter_visibility_mode_e mode = BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE;

	ret = bt_adapter_get_visibility(&mode, &duration);
	if (ret != BT_ERROR_NONE) {
		ERR("bt_adapter_get_visibility is failed 0x[%X]\n", ret);
	}

	if (mode == BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE) {
			ERR("_launch_toast_popup() is failed\n");
	}

	DBG("-\n");
}

static void __handle_bt_adapter_visibility()
{
	DBG("+\n");

	int ret;
	int duration;
	bt_adapter_visibility_mode_e mode = BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE;

	ret = bt_adapter_get_visibility(&mode, &duration);
	if (ret != BT_ERROR_NONE) {
		ERR("bt_adapter_get_visibility is failed 0x[%X]\n", ret);
	}

	if (mode == BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE) {
		ret = bt_adapter_set_visibility(BT_ADAPTER_VISIBILITY_MODE_LIMITED_DISCOVERABLE, 120);
		if (ret != BT_ERROR_NONE) {
			ERR("bt_adapter_set_visibility is failed 0x[%X]\n", ret);
		}
	}
	bt_adapter_set_visibility_mode_changed_cb(__bt_adapter_visibility_changed_cb, NULL);
	DBG("-\n");
}

gboolean tethering_enable_bt_tethering(Tethering *obj,
		GDBusMethodInvocation *context)
{
	mobile_ap_error_code_e ret;
	gboolean ret_val = FALSE;

	DBG("+\n");

	g_assert(obj != NULL);
	g_assert(context != NULL);

	if (g_context) {
		DBG("It is turnning on\n");
		tethering_complete_enable_bt_tethering(obj, context,
				MOBILE_AP_ERROR_IN_PROGRESS);
		return FALSE;
	}

	g_context = context;

	_block_device_sleep();

	ret = __init_bt(obj);
	if (ret != MOBILE_AP_ERROR_NONE)
		goto DONE;

	if (!_mobileap_set_state(MOBILE_AP_STATE_BT)) {
		ret = MOBILE_AP_ERROR_RESOURCE;
		__deinit_bt();
		goto DONE;
	}

	if (__is_bt_adapter_on() == FALSE) {
		DBG("Bluetooth is deactivated\n");
		if (__turn_on_bt_adapter((gpointer)obj) != MOBILE_AP_ERROR_NONE) {
			ERR("__turn_on_bt_adapter is failed\n");
			ret = MOBILE_AP_ERROR_INTERNAL;
			_mobileap_clear_state(MOBILE_AP_STATE_BT);
			__deinit_bt();
			goto DONE;
		}

		return TRUE;
	}

	ret = _enable_bt_tethering(obj);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_enable_bt_tethering() is failed : %d\n", ret);
		_mobileap_clear_state(MOBILE_AP_STATE_BT);
		__deinit_bt();
	} else {
		tethering_emit_bluetooth_on(obj);
		_create_tethering_active_noti();
		__handle_bt_adapter_visibility();
		ret_val = TRUE;
	}

DONE:
	tethering_complete_enable_bt_tethering(obj, g_context, ret);
	g_context = NULL;

	_unblock_device_sleep();
	DBG("-\n");
	return ret_val;
}

gboolean tethering_disable_bt_tethering(Tethering *obj,
		GDBusMethodInvocation *context)
{
	mobile_ap_error_code_e ret;

	DBG("+\n");

	g_assert(obj != NULL);
	g_assert(context != NULL);

	ret = _disable_bt_tethering(obj);
	if (ret != MOBILE_AP_ERROR_NONE) {
		tethering_complete_disable_bt_tethering(obj, context,
				MOBILE_AP_DISABLE_BT_TETHERING_CFM, ret);
		return FALSE;
	}

	tethering_emit_bluetooth_off(obj, NULL);
	tethering_complete_disable_bt_tethering(obj, context,
			MOBILE_AP_DISABLE_BT_TETHERING_CFM, ret);
	return TRUE;
}

gboolean _is_trying_bt_operation(void)
{
	return (g_context ? TRUE : FALSE);
}
