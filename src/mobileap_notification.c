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

#include <glib.h>
#include <dbus/dbus.h>
#include <stdio.h>
#include <string.h>
#include <notification.h>
#include <notification_list.h>
#include <notification_text_domain.h>
#include <notification_internal.h>
#include <bluetooth.h>
#include <bundle_internal.h>

#include "mobileap_softap.h"
#include "mobileap_notification.h"

#define MH_NOTI_LAUNCH_PKGNAME	"ug-setting-mobileap-efl"
#define MH_NOTI_CALLER_PKGNAME	"mobileap-agent"
#define MH_LOCALE_DOMAIN	"ug-setting-mobileap-efl"
#define MH_LOCALE_DIR "/usr/ug/res/locale"


static int connected_noti_id = 0;
static int timeout_noti_id = 0;

static int __create_status_noti(const char *content)
{
	if (content == NULL)
		return MOBILE_AP_ERROR_INVALID_PARAM;

	notification_error_e ret;

	ret = notification_status_message_post(content);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("notification_status_message_post() is failed : %d\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	return MOBILE_AP_ERROR_NONE;
}

int _create_timeout_noti(const char *icon_path)
{
	DBG("+\n");

	notification_h noti = NULL;
	notification_error_e ret = NOTIFICATION_ERROR_NONE;
	char *old_icon_path = NULL;
	char *general_icon_path = NULL;

	if (timeout_noti_id) {
		noti = notification_load(MH_NOTI_CALLER_PKGNAME, timeout_noti_id);
		if (noti == NULL) {
			DBG("Notification can be deleted already\n");
		} else {
			ret = notification_get_image(noti,
					NOTIFICATION_IMAGE_TYPE_ICON, &old_icon_path);
			if (ret == NOTIFICATION_ERROR_NONE) {
				if (g_strcmp0(icon_path, old_icon_path))
					general_icon_path = MH_NOTI_ICON_GENERAL;
			}

			ret = notification_delete(noti);
			if (ret != NOTIFICATION_ERROR_NONE) {
				ERR("Fail to notification_delete [%d]\n", ret);

				ret = notification_free(noti);
				if (ret != NOTIFICATION_ERROR_NONE)
					ERR("Fail to notification_free [%d]\n", ret);
				return MOBILE_AP_ERROR_INTERNAL;
			}

			ret = notification_free(noti);
			if (ret != NOTIFICATION_ERROR_NONE) {
				ERR("Fail to notification_free [%d]\n", ret);
			}
		}

		timeout_noti_id = 0;
	}

	noti = notification_create(NOTIFICATION_TYPE_NOTI);
	if (!noti) {
		ERR("Fail to notification_create\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	ret = notification_set_pkgname(noti, MH_NOTI_CALLER_PKGNAME);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_pkgname [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_property(noti,
			NOTIFICATION_PROP_VOLATILE_DISPLAY);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_property [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_layout(noti, NOTIFICATION_LY_NOTI_EVENT_SINGLE);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_layout [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_image(noti,
			NOTIFICATION_IMAGE_TYPE_ICON, general_icon_path ?
			general_icon_path : icon_path);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_image [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_text(noti,
			NOTIFICATION_TEXT_TYPE_TITLE, NULL,
			MH_STR_CONNECTION_TIMEOUT,
			NOTIFICATION_VARIABLE_TYPE_NONE);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_text [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_text(noti,
			NOTIFICATION_TEXT_TYPE_CONTENT, NULL,
			MH_STR_CONFIGURE_TETHERING,
			NOTIFICATION_VARIABLE_TYPE_NONE);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_text [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_text_domain(noti, MH_LOCALE_DOMAIN, MH_LOCALE_DIR);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_text_domain [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_application(noti, MH_NOTI_LAUNCH_PKGNAME);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_application [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_insert(noti, &timeout_noti_id);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_insert [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_free(noti);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_free [%d]\n", ret);
		goto FAIL;
	}

	DBG("-\n");
	return MOBILE_AP_ERROR_NONE;

FAIL:
	ret = notification_free(noti);
	if (ret != NOTIFICATION_ERROR_NONE)
		ERR("Fail to notification_free [%d]\n", ret);

	return MOBILE_AP_ERROR_INTERNAL;
}

int _delete_timeout_noti(void)
{
	notification_error_e ret = NOTIFICATION_ERROR_NONE;
	notification_list_h noti_list = NULL;
	notification_list_h l = NULL;
	notification_h noti = NULL;
	notification_ly_type_e layout;

	DBG("+\n");

	ret = notification_get_detail_list(MH_NOTI_CALLER_PKGNAME,
			NOTIFICATION_GROUP_ID_NONE,
			NOTIFICATION_PRIV_ID_NONE,
			-1,
			&noti_list);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_get_detail_list\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	if (noti_list == NULL) {
		return MOBILE_AP_ERROR_NONE;
	}

	for (l = noti_list; l; l = notification_list_get_next(l)) {
		noti = notification_list_get_data(l);
		if (noti == NULL)
			break;

		ret = notification_get_layout(noti, &layout);
		if (ret == NOTIFICATION_ERROR_NONE &&
				layout == NOTIFICATION_LY_NOTI_EVENT_SINGLE) {
			DBG("Found timeout noti\n");
			notification_delete(noti);
		}
	}

	notification_free_list(noti_list);

	DBG("-\n");

	return MOBILE_AP_ERROR_NONE;
}

int _create_connected_noti(int count, const char *icon_path)
{
	DBG("+\n");
	notification_h noti = NULL;
	notification_error_e ret = NOTIFICATION_ERROR_NONE;
	bundle *b = NULL;

	noti = notification_create(NOTIFICATION_TYPE_ONGOING);
	if (!noti) {
		ERR("Fail to notification_create\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	ret = notification_set_pkgname(noti, MH_NOTI_CALLER_PKGNAME);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_pkgname [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_property(noti,
			NOTIFICATION_PROP_DISABLE_AUTO_DELETE |
			NOTIFICATION_PROP_VOLATILE_DISPLAY);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_property [%d]\n", ret);
		goto FAIL;
	}

	b = bundle_create();
	bundle_add(b, "caller", "notification");

#ifndef TIZEN_TV
	appsvc_set_pkgname(b, "ug-setting-mobileap-efl");
#endif

	ret = notification_set_execute_option(noti,
			NOTIFICATION_EXECUTE_TYPE_SINGLE_LAUNCH, "Launch", NULL, b);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Failed to notification_set_execute_option");
		goto FAIL;
	}

	ERR("Successfully added notification");

	ret = notification_set_layout(noti, NOTIFICATION_LY_ONGOING_EVENT);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_image [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_image(noti, NOTIFICATION_IMAGE_TYPE_ICON, icon_path);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_image [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_text(noti,
			NOTIFICATION_TEXT_TYPE_TITLE, NULL,
			MH_STR_TETHERING,
			NOTIFICATION_VARIABLE_TYPE_NONE);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_text [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_text(noti,
			NOTIFICATION_TEXT_TYPE_CONTENT, NULL,
			MH_STR_CONNECTED_DEV,
			NOTIFICATION_VARIABLE_TYPE_INT, count,
			NOTIFICATION_VARIABLE_TYPE_NONE);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_text [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_text_domain(noti, MH_LOCALE_DOMAIN, MH_LOCALE_DIR);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_text_domain [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_application(noti, MH_NOTI_LAUNCH_PKGNAME);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_application [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_display_applist(noti,
			NOTIFICATION_DISPLAY_APP_ALL ^ NOTIFICATION_DISPLAY_APP_INDICATOR);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_display_applist [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_insert(noti, &connected_noti_id);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_insert [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_free(noti);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_free [%d]\n", ret);
		goto FAIL;
	}

	DBG("-\n");
	return MOBILE_AP_ERROR_NONE;

FAIL:
	if (b != NULL)
		bundle_free(b);
	ret = notification_free(noti);
	if (ret != NOTIFICATION_ERROR_NONE)
		ERR("Fail to notification_free [%d]\n", ret);
	return MOBILE_AP_ERROR_INTERNAL;
}

int _update_connected_noti(int count, const char *icon_path)
{
	DBG("+\n");

	notification_h noti = NULL;
	notification_error_e ret = NOTIFICATION_ERROR_NONE;

	noti = notification_load(MH_NOTI_CALLER_PKGNAME, connected_noti_id);
	if (noti == NULL) {
		ERR("notification_load is failed\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	ret = notification_set_image(noti,
			NOTIFICATION_IMAGE_TYPE_ICON, icon_path);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_image [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_set_text(noti,
			NOTIFICATION_TEXT_TYPE_CONTENT, NULL,
			MH_STR_CONNECTED_DEV,
			NOTIFICATION_VARIABLE_TYPE_INT, count,
			NOTIFICATION_VARIABLE_TYPE_NONE);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_set_text [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_update(noti);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_update [%d]\n", ret);
		goto FAIL;
	}

	ret = notification_free(noti);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_free [%d]\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	DBG("-\n");
	return MOBILE_AP_ERROR_NONE;

FAIL:
	ret = notification_free(noti);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_free [%d]\n", ret);
	}

	return MOBILE_AP_ERROR_INTERNAL;
}

int _delete_connected_noti(void)
{
	DBG("+\n");
	notification_h noti = NULL;
	notification_error_e ret;

	noti = notification_load(MH_NOTI_CALLER_PKGNAME, connected_noti_id);
	if (noti == NULL) {
		ERR("notification_load is failed\n");
		connected_noti_id = 0;
		return MOBILE_AP_ERROR_INTERNAL;
	}
	connected_noti_id = 0;

	ret = notification_delete(noti);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_delete [%d]\n", ret);

		ret = notification_free(noti);
		if (ret != NOTIFICATION_ERROR_NONE)
			ERR("Fail to notification_free [%d]\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	ret = notification_free(noti);
	if (ret != NOTIFICATION_ERROR_NONE) {
		ERR("Fail to notification_free [%d]\n", ret);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	DBG("-\n");
	return MOBILE_AP_ERROR_NONE;
}

void _create_tethering_active_noti(void)
{
	int active_count = 0;

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI))
		active_count++;

	if (_mobileap_is_enabled(MOBILE_AP_STATE_BT))
		active_count++;

	if (_mobileap_is_enabled(MOBILE_AP_STATE_USB))
		active_count++;

	if (active_count == 1)
		__create_status_noti(_("IDS_MOBILEAP_BODY_TETHERING_ACTIVE_ABB"));

	return;
}

void _create_bt_tethering_active_noti(void)
{
	int ret;
	bt_adapter_visibility_mode_e mode = BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE;
	int duration;
	char *str1 = NULL;
	char *str2 = NULL;

	if (!_mobileap_is_enabled(MOBILE_AP_STATE_WIFI) &&
			!_mobileap_is_enabled(MOBILE_AP_STATE_USB)) {
		str1 = MH_STR_TETHERING_ACTIVE;
		__create_status_noti(str1);
	}

	ret = bt_adapter_get_visibility(&mode, &duration);
	if (ret != BT_ERROR_NONE) {
		ERR("bt_adapter_get_visibility is failed 0x[%X]\n", ret);
	}

	if (mode == BT_ADAPTER_VISIBILITY_MODE_NON_DISCOVERABLE) {
		str2 = MH_STR_BT_VISIBILITY;
		__create_status_noti(str2);
	}

	return;
}
