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
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <bluetooth.h>

#include "mobileap_agent.h"
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
	{NULL, NULL, IP_ADDRESS_BT_4},
	{NULL, NULL, IP_ADDRESS_BT_5},
	{NULL, NULL, IP_ADDRESS_BT_6},
	{NULL, NULL, IP_ADDRESS_BT_7}};

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
		ERR("Not found : %s\n", mac);
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
		ERR("Not found : %s\n", mac);
		return FALSE;
	}

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
			g_free(__bt_remote_devices[i].intf_name);
			__bt_remote_devices[i].intf_name = NULL;
		}
	}

	return;
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

	DBG("Remote address : %s, Interface : %s, %s\n",
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
			_start_timeout_cb(MOBILE_AP_TYPE_BT);
	}

	return;
}

static mobile_ap_error_code_e __activate_bt_nap(TetheringObject *obj)
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
		return MOBILE_AP_ERROR_RESOURCE;
	}

	return MOBILE_AP_ERROR_NONE;
}

static void __deactivate_bt_nap(void)
{
	int bt_ret;

	bt_ret = bt_nap_deactivate();
	if (bt_ret != BT_ERROR_NONE)
		ERR("bt_nap_deactivate is failed : %d\n", bt_ret);

	bt_ret = bt_nap_unset_connection_state_changed_cb();
	if (bt_ret != BT_ERROR_NONE)
		ERR("bt_nap_unset_connection_state_changed_cb is failed : %d\n", bt_ret);

	return;
}

static void __bt_adapter_state_changed(int result, bt_adapter_state_e adapter_state, void *user_data)
{
	if (user_data == NULL) {
		ERR("Invalid param\n");
		return;
	}

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_BT))
		return;

	int ret;
	int duration;
	bt_adapter_visibility_mode_e mode;
	TetheringObject *obj = (TetheringObject *)user_data;
	DBusGMethodInvocation *context = obj->bt_context;

	obj->bt_context = NULL;
	if (result != BT_ERROR_NONE) {
		ERR("BT Adapter operation is failed : %d\n", result);
		if (context) {
			ret = MOBILE_AP_ERROR_RESOURCE;
			dbus_g_method_return(context,
					MOBILE_AP_ENABLE_BT_TETHERING_CFM, ret);
			_mobileap_clear_state(MOBILE_AP_STATE_BT);
		}
		return;
	}

	DBG("BT Adapter is %s\n", adapter_state == BT_ADAPTER_ENABLED ?
			"enabled" : "disabled");
	if (adapter_state == BT_ADAPTER_DISABLED) {
		_disable_bt_tethering(obj);
		_emit_mobileap_dbus_signal(obj, E_SIGNAL_BT_TETHER_OFF,
				SIGNAL_MSG_NOT_AVAIL_INTERFACE);
		return;
	} else {
		ret = bt_adapter_get_visibility(&mode, &duration);
		if (ret == BT_ERROR_NONE && mode == BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE)
			_create_status_noti("Bluetooth visible time is off. You may not find your device.");
	}

	ret = __activate_bt_nap(obj);
	if (ret != MOBILE_AP_ERROR_NONE) {
		bt_adapter_unset_state_changed_cb();
		bt_deinitialize();
		_deinit_tethering(obj);
		dbus_g_method_return(context,
				MOBILE_AP_ENABLE_BT_TETHERING_CFM, ret);
		_mobileap_clear_state(MOBILE_AP_STATE_BT);
		return;
	}

	_emit_mobileap_dbus_signal(obj, E_SIGNAL_BT_TETHER_ON, NULL);
	if (context)
		dbus_g_method_return(context,
				MOBILE_AP_ENABLE_BT_TETHERING_CFM, ret);
	return;
}

void _bt_get_remote_device_name(TetheringObject *obj, const char *mac, char **name)
{
	if (obj == NULL || mac == NULL || name == NULL) {
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

mobile_ap_error_code_e _enable_bt_tethering(TetheringObject *obj,
		DBusGMethodInvocation *context)
{
	mobile_ap_error_code_e ret = MOBILE_AP_ERROR_NONE;
	int bt_ret;
	int duration;
	bt_adapter_visibility_mode_e mode;
	bt_adapter_state_e adapter_state = BT_ADAPTER_DISABLED;

	if (_mobileap_is_enabled(MOBILE_AP_STATE_BT)) {
		ERR("Bluetooth tethering is already enabled\n");
		ret = MOBILE_AP_ERROR_ALREADY_ENABLED;
		return ret;
	}

	if (obj->bt_context != NULL) {
		ERR("Bluetooth tethering request is progressing\n");
		ret = MOBILE_AP_ERROR_IN_PROGRESS;
		return ret;
	}

	if (!_mobileap_set_state(MOBILE_AP_STATE_BT)) {
		ret = MOBILE_AP_ERROR_RESOURCE;
		goto FAIL;
	}

	if (!_init_tethering(obj)) {
		ret = MOBILE_AP_ERROR_RESOURCE;
		goto FAIL;
	}

	bt_ret = bt_initialize();
	if (bt_ret != BT_ERROR_NONE) {
		ERR("bt_initialize is failed : %d\n", bt_ret);
		_deinit_tethering(obj);
		ret = MOBILE_AP_ERROR_RESOURCE;
		goto FAIL;
	}

	bt_ret = bt_adapter_set_state_changed_cb(__bt_adapter_state_changed, (void *)obj);
	if (bt_ret != BT_ERROR_NONE) {
		ERR("bt_adapter_set_state_changed_cb is failed : %d\n", bt_ret);
		bt_deinitialize();
		_deinit_tethering(obj);
		ret = MOBILE_AP_ERROR_RESOURCE;
		goto FAIL;
	}

	bt_ret = bt_adapter_get_state(&adapter_state);
	if (bt_ret != BT_ERROR_NONE) {
		ERR("bt_adapter_get_state is failed : %d\n", bt_ret);
		bt_adapter_unset_state_changed_cb();
		bt_deinitialize();
		_deinit_tethering(obj);
		ret = MOBILE_AP_ERROR_RESOURCE;
		goto FAIL;
	}

	if (adapter_state == BT_ADAPTER_DISABLED) {
		bt_ret = bt_adapter_enable();
		if (bt_ret != BT_ERROR_NONE) {
			ERR("bt_adapter_enable is failed : %d\n", bt_ret);
			bt_adapter_unset_state_changed_cb();
			bt_deinitialize();
			_deinit_tethering(obj);
			ret = MOBILE_AP_ERROR_RESOURCE;
			goto FAIL;
		}
		obj->bt_context = context;
		return ret;
	} else {
		bt_ret = bt_adapter_get_visibility(&mode, &duration);
		if (bt_ret == BT_ERROR_NONE && mode == BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE)
			_create_status_noti("Bluetooth visible time is off. You may not find your device.");

	}

	ret = __activate_bt_nap(obj);
	if (ret != MOBILE_AP_ERROR_NONE) {
		bt_adapter_unset_state_changed_cb();
		bt_deinitialize();
		_deinit_tethering(obj);
		ret = MOBILE_AP_ERROR_RESOURCE;
		goto FAIL;
	}

	_delete_timeout_noti();
	_init_timeout_cb(MOBILE_AP_TYPE_BT, (void *)obj);
	_start_timeout_cb(MOBILE_AP_TYPE_BT);

	return ret;

FAIL:
	_mobileap_clear_state(MOBILE_AP_STATE_BT);

	return ret;
}

mobile_ap_error_code_e _disable_bt_tethering(TetheringObject *obj)
{
	int bt_ret;

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_BT)) {
		ERR("BT tethering has not been enabled\n");
		return MOBILE_AP_ERROR_NOT_ENABLED;
	}

	__deactivate_bt_nap();

	bt_ret = bt_adapter_unset_state_changed_cb();
	if (bt_ret != BT_ERROR_NONE)
		ERR("bt_adapter_unset_state_changed_cb is failed : %d\n", bt_ret);

	bt_ret = bt_deinitialize();
	if (bt_ret != BT_ERROR_NONE)
		ERR("bt_deinitialize is failed : %d\n", bt_ret);

	_remove_station_info_all(MOBILE_AP_TYPE_BT);
	__del_bt_remote_all();
	_deinit_timeout_cb(MOBILE_AP_TYPE_BT);

	_deinit_tethering(obj);
	_mobileap_clear_state(MOBILE_AP_STATE_BT);

	return MOBILE_AP_ERROR_NONE;
}

gboolean tethering_enable_bt_tethering(TetheringObject *obj,
		DBusGMethodInvocation *context)
{
	mobile_ap_error_code_e ret;

	DBG("+\n");

	g_assert(obj != NULL);
	g_assert(context != NULL);


	ret = _enable_bt_tethering(obj, context);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("_enable_bt_tethering() is failed : %d\n", ret);
		dbus_g_method_return(context,
				MOBILE_AP_ENABLE_BT_TETHERING_CFM, ret);
		return FALSE;
	} else if (obj->bt_context == NULL) {
		_emit_mobileap_dbus_signal(obj, E_SIGNAL_BT_TETHER_ON, NULL);
		dbus_g_method_return(context,
				MOBILE_AP_ENABLE_BT_TETHERING_CFM, ret);
	}

	return TRUE;
}


gboolean tethering_disable_bt_tethering(TetheringObject *obj,
		DBusGMethodInvocation *context)
{
	mobile_ap_error_code_e ret;

	DBG("+\n");

	g_assert(obj != NULL);
	g_assert(context != NULL);

	ret = _disable_bt_tethering(obj);
	if (ret != MOBILE_AP_ERROR_NONE) {
		dbus_g_method_return(context, MOBILE_AP_DISABLE_BT_TETHERING_CFM, ret);
		return FALSE;
	}

	_emit_mobileap_dbus_signal(obj, E_SIGNAL_BT_TETHER_OFF, NULL);
	dbus_g_method_return(context, MOBILE_AP_DISABLE_BT_TETHERING_CFM, ret);
	return TRUE;
}
