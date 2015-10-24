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

#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <glib.h>
#include <glib-object.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/wireless.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "mobileap_common.h"
#include "mobileap_softap.h"
#include "mobileap_handler.h"
#include "mobileap_wifi.h"
#include "mobileap_iptables.h"

#define NETCONFIG_SERVICE				"net.netconfig"
#define NETCONFIG_WIFI_INTERFACE		"net.netconfig.wifi"
#define NETCONFIG_WIFI_PATH				"/net/netconfig/wifi"

#define NETCONFIG_DBUS_REPLY_TIMEOUT	(10 * 1000)

static pid_t dnsmasq_pid = 0;
static pid_t hostapd_pid = 0;
static int hostapd_ctrl_fd = 0;
static int hostapd_monitor_fd = 0;
static GIOChannel *hostapd_io_channel = NULL;
static guint hostapd_io_source = 0;
GSList *sta_timer_list = NULL;

static gboolean __hostapd_connect_timer_cb(gpointer user_data);

static char *__find_first_caps_char(char *str)
{
	if (str == NULL) {
		ERR("NULL string passes\n");
		return NULL;
	}

	while(*str) {
		if (isupper(*str)) {
			return str;
		}
		str++;
	}
	return NULL;
}

static int __issue_ioctl(int sock_fd, char *if_name, char *cmd, char *buf)
{
	int ret_val = MOBILE_AP_ERROR_NONE;
	struct iwreq iwr;

	memset(buf, 0, MAX_BUF_SIZE);
	memset(&iwr, 0, sizeof(iwr));

	/* Configure ioctl parameters */
	g_strlcpy(iwr.ifr_name, if_name, IFNAMSIZ);
	g_strlcpy(buf, cmd, MAX_BUF_SIZE);
	iwr.u.data.pointer = buf;
	iwr.u.data.length = MAX_BUF_SIZE;

	usleep(DRIVER_DELAY);

	/* Issue ioctl */
	if ((ioctl(sock_fd, SIOCSIWPRIV, &iwr)) < 0) {
		ERR("ioctl failed...!!!\n");
		ret_val = MOBILE_AP_ERROR_INTERNAL;
	}

	return ret_val;
}

static int __get_psk_hexascii(const char *pass, const unsigned char *salt,
		char *psk, unsigned int psk_len)
{
	if (pass == NULL || salt == NULL || psk == NULL || psk_len <
			(SHA256_DIGEST_LENGTH * 2 + 1)) {
		ERR("Invalid parameter\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	int i = 0;
	int d_16 = 0;
	int r_16 = 0;
	unsigned char buf[SHA256_DIGEST_LENGTH] = {0, };

	if (!PKCS5_PBKDF2_HMAC_SHA1(pass, strlen(pass),
				salt, strlen((const char *)salt),
				PSK_ITERATION_COUNT, sizeof(buf), buf)) {
		ERR("Getting psk is failed\n");
		return MOBILE_AP_ERROR_RESOURCE;
	}

	for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		d_16 = buf[i] >> 4;
		r_16 = buf[i] & 0xf;

		psk[i << 1] = d_16 < 10 ? d_16 + '0' : d_16 - 10 + 'a';
		psk[(i << 1) + 1] = r_16 < 10 ? r_16 + '0' : r_16 - 10 + 'a';
	}
	psk[i << 1] = '\0';

	return MOBILE_AP_ERROR_NONE;
}

static int __execute_hostapd(const mobile_ap_type_e type, const char *ssid,
		const char *security, const char *passphrase, int hide_mode)
{
	DBG("+\n");

	char *conf = NULL;
	char *old_conf;
	char buf[HOSTAPD_CONF_LEN] = "";
	FILE *fp = NULL;
	pid_t pid;
	int ret;
	char key[MOBILE_AP_WIFI_KEY_MAX_LEN + 1];
	/* Default conf. */
	snprintf(buf, sizeof(buf), HOSTAPD_CONF,
			WIFI_IF,
			HOSTAPD_CTRL_INTF_DIR,
			ssid,
			MOBILE_AP_WIFI_CHANNEL,
			hide_mode ? 2 : 0,
			MOBILE_AP_MAX_WIFI_STA);
	conf = g_strdup(buf);

	/* Vendor elements conf. */
	if (type == MOBILE_AP_TYPE_WIFI) {
		snprintf(buf, sizeof(buf),
				"vendor_elements=%s\n", HOSTAPD_VENDOR_ELEMENTS_TETH);
	} else if (type == MOBILE_AP_TYPE_WIFI_AP) {
		snprintf(buf, sizeof(buf),
				"vendor_elements=%s\n", HOSTAPD_VENDOR_ELEMENTS_WIFI_AP);
	} else {
		ERR("Unknown type: %d\n", type);
		g_free(conf);
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}
	old_conf = conf;
	conf = g_strconcat(old_conf, buf, NULL);
	g_free(old_conf);

	/* Security conf. */
	if (security != NULL && !strcmp(security, "wpa2-psk")) {
		ret = __get_psk_hexascii(passphrase, (const unsigned char *)ssid, key, sizeof(key));
		if (ret != MOBILE_AP_ERROR_NONE) {
			g_free(conf);
			ERR("hex conversion failed\n");
			return MOBILE_AP_ERROR_RESOURCE;
		}
		snprintf(buf, sizeof(buf),
				"wpa=2\nrsn_pairwise=CCMP\nwpa_psk=%s\n", key);

		old_conf = conf;
		conf = g_strconcat(old_conf, buf, NULL);
		g_free(old_conf);
	}

	fp = fopen(HOSTAPD_CONF_FILE, "w");
	if (NULL == fp) {
		ERR("Could not create the file.\n");
		g_free(conf);
		return MOBILE_AP_ERROR_RESOURCE;
	}

	if (conf) {
		fputs(conf, fp);
		g_free(conf);
	}
	fclose(fp);

	pid = fork();
	if (pid < 0) {
		ERR("fork failed\n");
		return MOBILE_AP_ERROR_RESOURCE;
	}

	if (pid == 0) {
		if (execl(HOSTAPD_BIN, HOSTAPD_BIN, "-e", HOSTAPD_ENTROPY_FILE,
					HOSTAPD_CONF_FILE,
					"-f", HOSTAPD_DEBUG_FILE, "-ddd",
					(char *)NULL)) {
			ERR("execl failed\n");
		}

		ERR("Should not get here!");
		return MOBILE_AP_ERROR_RESOURCE;
	}

	hostapd_pid = pid;

	return MOBILE_AP_ERROR_NONE;
}

static int __terminate_hostapd()
{
	DBG("+\n");

	int ret;

	if (hostapd_pid == 0) {
		ERR("There is no hostapd\n");
		return MOBILE_AP_ERROR_NONE;
	}

	kill(hostapd_pid, SIGTERM);
	waitpid(hostapd_pid, NULL, 0);
	hostapd_pid = 0;

	ret = unlink(HOSTAPD_CONF_FILE);
	if (ret < 0) {
		ERR("unlink is failed : %s\n", strerror(errno));
	}

	return MOBILE_AP_ERROR_NONE;
}

/*
 * number NUM_STA(void)
 * addr STA-FIRST(void)
 * addr STA-NEXT(addr)
 * void DISASSOCIATE(addr)
 * void READ_WHITELIST(filename)
 * void SET_MAXCLIENT(number)
 */
static int __send_hostapd_req(int fd, const char *req, const int req_len,
		char *buf, int *buf_len)
{
	if (fd < 0 || req == NULL || req_len <= 0 ||
			buf == NULL || buf_len == NULL || *buf_len <= 0) {
		ERR("Invalid param\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	struct timeval tv = {10, 0};
	fd_set fds;
	int ret = 0;

	ret = send(fd, req, req_len, 0);
	if (ret < 0) {
		ERR("send is failed : %s\n", strerror(errno));
		return MOBILE_AP_ERROR_INTERNAL;
	}

	while (TRUE) {
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		ret = select(fd + 1, &fds, NULL, NULL, &tv);
		if (ret < 0) {
			return MOBILE_AP_ERROR_INTERNAL;
		} else if (ret == 0) {
			ERR("There is no response from hostapd\n");
			return MOBILE_AP_ERROR_INTERNAL;
		} else if (!FD_ISSET(fd, &fds)) {
			ERR("Unknown case\n");
			return MOBILE_AP_ERROR_INTERNAL;
		}

		ret = recv(fd, buf, (*buf_len) - 1, 0);
		if (ret < 0) {
			ERR("recv is failed\n");
			return MOBILE_AP_ERROR_INTERNAL;
		}

		if (buf[0] == '<') {
			ERR("Unsolicited message\n");
			continue;
		}

		*buf_len = ret;
		buf[ret] = '\0';
		if (ret == 0) {
			ERR("socket is closed\n");
		}

		break;
	}

	return MOBILE_AP_ERROR_NONE;
}

static int __open_hostapd_intf(int *fd, const char *intf)
{
	if (fd == NULL || intf == NULL) {
		ERR("fd is NULL\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	DBG("+\n");

	int retry = 0;
	char ctrl_intf[255] = {0, };
	struct sockaddr_un src;
	struct sockaddr_un dest;
	struct stat stat_buf;

	*fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (*fd < 0) {
		ERR("socket is failed\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	src.sun_family = AF_UNIX;
	g_strlcpy(src.sun_path, intf, sizeof(src.sun_path));

	if (stat(src.sun_path, &stat_buf) == 0) {
		unlink(src.sun_path);
	}

	if (bind(*fd, (struct sockaddr *)&src, sizeof(src)) < 0) {
		ERR("bind is failed\n");
		close(*fd);
		*fd = -1;
		unlink(src.sun_path);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	snprintf(ctrl_intf, sizeof(ctrl_intf), "%s/%s",
			HOSTAPD_CTRL_INTF_DIR, WIFI_IF);
	dest.sun_family = AF_UNIX;
	g_strlcpy(dest.sun_path, ctrl_intf, sizeof(dest.sun_path));

	while (connect(*fd, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
		if (++retry >= HOSTAPD_RETRY_MAX)
			goto FAIL;
		usleep(HOSTAPD_RETRY_DELAY);
	}

	return MOBILE_AP_ERROR_NONE;

FAIL:
	ERR("Cannot make connection to hostapd\n");
	close(*fd);
	*fd = -1;
	unlink(src.sun_path);

	return MOBILE_AP_ERROR_INTERNAL;
}

static int __close_hostapd_intf(int *fd)
{
	DBG("+\n");

	if (fd == NULL) {
		ERR("fd is NULL\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	if (*fd > 0)
		close(*fd);
	*fd = -1;

	return MOBILE_AP_ERROR_NONE;
}

static gboolean __hostapd_monitor_cb(GIOChannel *source)
{
	DBG("+\n");

	GSList *l;
	char buf[HOSTAPD_REQ_MAX_LEN + 1] = {0, };
	char *pbuf = NULL;
	gsize read = 0;
	int n_station = 0;
	int type;
	sta_timer_t *ptr = NULL;
	char *mac = NULL;
	char *end = NULL;
	gboolean discon_event = FALSE;


#if !GLIB_CHECK_VERSION(2, 31, 0)
	int ret = 0;

	ret = g_io_channel_read(hostapd_io_channel, buf,
			HOSTAPD_REQ_MAX_LEN, &read);
	if (ret != G_IO_ERROR_NONE) {
		ERR("g_io_channel_read is failed\n");
		return FALSE;
	}
#else
	GError *err = NULL;
	GIOStatus ios;

	ios = g_io_channel_read_chars(hostapd_io_channel, buf,
			HOSTAPD_REQ_MAX_LEN, &read, &err);
	if (err != NULL) {
		ERR("g_io_channel_read_chars is failed : %s\n", err->message);
		g_error_free(err);
		return FALSE;
	} else if (ios != G_IO_STATUS_NORMAL) {
		ERR("g_io_channel_read_chars is failed : %d\n", ios);
		return FALSE;
	}
#endif

	buf[read] = '\0';
	pbuf = strrchr(buf, '\n');
	if (pbuf != NULL)
		*pbuf = '\0';

	SDBG("Read string from hostapd = [%s]\n", buf);
	pbuf = buf;
	/* concatenated string, containing multiple events can arrive */
	while (pbuf && *pbuf) {
		pbuf = __find_first_caps_char(pbuf);
		if (!pbuf || !*pbuf) {
			break;
		}

		if (!strncmp(pbuf, HOSTAPD_STA_CONN, HOSTAPD_STA_CONN_LEN)) {
			pbuf = pbuf + HOSTAPD_STA_CONN_LEN;
			if (!pbuf || !*pbuf) {
				ERR("No mac address\n");
				return TRUE;
			}

			end = strchr(pbuf, '<');
			if (end && *end) {
				mac = g_strndup(pbuf, (long)(end - pbuf));
				pbuf = end + 1;
			} else {
				mac = g_strdup(pbuf);
				pbuf += strlen(mac);
			}

			if (mac == NULL) {
				ERR("strdup failed\n");
				return TRUE;
			}

			for (l = sta_timer_list; l != NULL; l = g_slist_next(l)) {
				ptr = (sta_timer_t *)l->data;
				if (ptr == NULL) {
					continue;
				}

				if (g_strcmp0(ptr->mac_addr, mac) == 0) {
					g_free(mac);
					mac = NULL;
					break;
				}
			}

			/* Matched station found, so skip */
			if (l != NULL) {
				continue;
			}

			SDBG("%s%s\n", HOSTAPD_STA_CONN, mac);
			ptr = (sta_timer_t *)g_malloc(sizeof(sta_timer_t));
			if (ptr == NULL) {
				ERR("g_malloc failed\n");
				g_free(mac);
				mac = NULL;
				return TRUE;
			}
			ptr->mac_addr = mac;
			ptr->tid = g_timeout_add(HOSTAPD_DHCP_MAX_INTERVAL,
					__hostapd_connect_timer_cb, mac);
			sta_timer_list = g_slist_append(sta_timer_list, ptr);

		} else if (!strncmp(pbuf, HOSTAPD_STA_DISCONN, HOSTAPD_STA_DISCONN_LEN)) {
			pbuf = pbuf + HOSTAPD_STA_DISCONN_LEN;
			if (!pbuf || !*pbuf) {
				break;
			}

			end = strchr(pbuf, '<');
			if (end && *end) {
				mac = g_strndup(pbuf, (long)(end - pbuf));
				pbuf = end + 1;
			} else {
				mac = g_strdup(pbuf);
				pbuf += strlen(mac);
			}

			if (mac == NULL) {
				ERR("strdup failed\n");
				return TRUE;
			}

			SDBG("%s%s\n", HOSTAPD_STA_DISCONN, mac);
			_remove_station_info(mac, _slist_find_station_by_mac);

			/*
			 * Destroy the timer if its not expired before disconnection
			 */
			_destroy_dhcp_ack_timer(mac);
			g_free(mac);
			mac = NULL;
			discon_event = TRUE;

		} else {
			pbuf = strchr(pbuf, '>');
			if (pbuf == NULL)
				break;
			pbuf++;
		}
	}

	if (discon_event == FALSE)
		goto DONE;

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI)) {
		type = MOBILE_AP_TYPE_WIFI;
	} else if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI_AP)) {
		type = MOBILE_AP_TYPE_WIFI_AP;
	} else {
		goto DONE;
	}

	_get_station_count((gconstpointer)type,
			_slist_find_station_by_interface, &n_station);

	if (n_station == 0) {
		if (type == MOBILE_AP_TYPE_WIFI)
			_start_timeout_cb(type, time(NULL) + TETHERING_CONN_TIMEOUT);
		else if (type == MOBILE_AP_TYPE_WIFI_AP)
			_start_timeout_cb(type, time(NULL) + WIFI_AP_CONN_TIMEOUT);
	}
DONE:
	return TRUE;
}

static int __open_hostapd_monitor(int *fd)
{
	if (fd == NULL) {
		ERR("fd is NULL\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	DBG("+\n");

	char buf[HOSTAPD_REQ_MAX_LEN] = {0, };
	int buf_len = 0;

	if (__open_hostapd_intf(fd, MH_MONITOR_INTF) != MOBILE_AP_ERROR_NONE) {
		ERR("__open_hostapd_intf() is failed\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	hostapd_io_channel = g_io_channel_unix_new(*fd);
	if (hostapd_io_channel == NULL) {
		ERR("g_io_channel_unix_new is failed\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	g_io_channel_set_encoding(hostapd_io_channel, NULL, NULL);
	g_io_channel_set_flags(hostapd_io_channel,
			G_IO_FLAG_APPEND | G_IO_FLAG_NONBLOCK, NULL);

	hostapd_io_source = g_io_add_watch(hostapd_io_channel, G_IO_IN,
			(GIOFunc)__hostapd_monitor_cb, NULL);

	buf_len = sizeof(buf);
	__send_hostapd_req(*fd, HOSTAPD_MONITOR_ATTACH,
			strlen(HOSTAPD_MONITOR_ATTACH), buf, &buf_len);

	return MOBILE_AP_ERROR_NONE;
}

static int __close_hostapd_monitor(int *fd)
{
	GError *err = NULL;
	char buf[HOSTAPD_REQ_MAX_LEN] = {0, };
	int buf_len = 0;

	buf_len = sizeof(buf);
	__send_hostapd_req(*fd, HOSTAPD_MONITOR_DETACH,
			strlen(HOSTAPD_MONITOR_DETACH), buf, &buf_len);

	if (hostapd_io_source != 0) {
		g_source_remove(hostapd_io_source);
		hostapd_io_source = 0;
	}

	if (hostapd_io_channel != NULL) {
		g_io_channel_shutdown(hostapd_io_channel, TRUE, &err);
		g_io_channel_unref(hostapd_io_channel);
		hostapd_io_channel = NULL;
	}

	__close_hostapd_intf(fd);

	return MOBILE_AP_ERROR_NONE;
}

static mobile_ap_drv_interface_e __get_drv_interface(void)
{
	static mobile_ap_drv_interface_e drv_interface = MOBILE_AP_DRV_INTERFACE_NONE;

	if (drv_interface != MOBILE_AP_DRV_INTERFACE_NONE) {
		return drv_interface;
	}

	const char *drv_rfkill_path = "/sys/devices/platform";
	const char *wext_drv[] = {
		"bcm4329-b1", "bcm4330-b0",
		"bcm4330-b1", "bcm4330-b2",
		NULL};

	char path[MAX_BUF_SIZE] = { 0 };
	struct stat stat_buf = { 0 };
	int fd = 0;
	int i = 0;

	drv_interface = MOBILE_AP_NL80211;

	for (i = 0; wext_drv[i] != NULL; i++) {
		snprintf(path, sizeof(path), "%s/%s",
				drv_rfkill_path, wext_drv[i]);
		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;

		if (fstat(fd, &stat_buf) == 0 && S_ISDIR(stat_buf.st_mode)) {
			drv_interface = MOBILE_AP_WEXT;
			close(fd);
			break;
		}

		close(fd);
	}

	return drv_interface;
}

static int __mh_core_softap_firmware_start(void)
{
	int err = 0;
	DBusError error;
	DBusMessageIter iter;
	DBusMessage *reply = NULL;
	DBusMessage *message = NULL;
	DBusConnection *connection = NULL;
	const char *device = "softap";

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		ERR("Failed to get system bus");
		return -EIO;
	}

	message = dbus_message_new_method_call(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE ".Firmware", "Start");
	if (message == NULL) {
		ERR("Failed DBus method call");
		dbus_connection_unref(connection);
		return -EIO;
	}

	dbus_message_iter_init_append(message, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &device);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection, message,
			NETCONFIG_DBUS_REPLY_TIMEOUT, &error);
	if (dbus_error_is_set(&error) == TRUE) {
		if (NULL != strstr(error.message, ".AlreadyExists")) {
			// softap already enabled
		} else {
			ERR("dbus_connection_send_with_reply_and_block() failed. "
					"DBus error [%s: %s]", error.name, error.message);

			err = -EIO;

			dbus_error_free(&error);
		}

		dbus_error_free(&error);
	}

	if (reply != NULL)
		dbus_message_unref(reply);

	dbus_message_unref(message);
	dbus_connection_unref(connection);

	return err;
}

static int __mh_core_softap_firmware_stop(void)
{
	int err = 0;
	DBusError error;
	DBusMessageIter iter;
	DBusMessage *reply = NULL;
	DBusMessage *message = NULL;
	DBusConnection *connection = NULL;
	const char *device = "softap";

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		ERR("Failed to get system bus");
		return -EIO;
	}

	message = dbus_message_new_method_call(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE ".Firmware", "Stop");
	if (message == NULL) {
		ERR("Failed DBus method call");
		dbus_connection_unref(connection);
		return -EIO;
	}

	dbus_message_iter_init_append(message, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &device);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection, message,
			NETCONFIG_DBUS_REPLY_TIMEOUT, &error);
	if (dbus_error_is_set(&error) == TRUE) {
		if (NULL != strstr(error.message, ".AlreadyExists")) {
			// softap already disabled
		} else {
			ERR("dbus_connection_send_with_reply_and_block() failed. "
					"DBus error [%s: %s]", error.name, error.message);

			err = -EIO;

			dbus_error_free(&error);
		}

		dbus_error_free(&error);
	}

	if (reply != NULL)
		dbus_message_unref(reply);

	dbus_message_unref(message);
	dbus_connection_unref(connection);

	return err;
}

int _mh_core_enable_softap(const mobile_ap_type_e type, const char *ssid,
		const char *security, const char *key, int hide_mode)
{
	if (ssid == NULL || security == NULL || key == NULL) {
		ERR("Invalid param\n");
		return MOBILE_AP_ERROR_INTERNAL;
	}

	char cmd[MAX_BUF_SIZE];
	int ret_status = MOBILE_AP_ERROR_NONE;
	mobile_ap_drv_interface_e drv_interface = MOBILE_AP_DRV_INTERFACE_NONE;

	int sock_fd;
	char *if_name = WIFI_IF;
	char buf[MAX_BUF_SIZE] = { 0 };

	char wext_ssid[MOBILE_AP_WIFI_SSID_MAX_LEN] = { 0 };
	char *ptr = NULL;

	if (__mh_core_softap_firmware_start() < 0)
		return MOBILE_AP_ERROR_INTERNAL;

	drv_interface = __get_drv_interface();

	switch (drv_interface) {
	case MOBILE_AP_WEXT:
		if ((sock_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
			ERR("Failed to open socket...!!!\n");
			ret_status = MOBILE_AP_ERROR_RESOURCE;
			break;
		}

		/*
		 * In case of Wireless extension interface,
		 * 32 byte SSID including null character can be accepted.
		 */
		g_strlcpy(wext_ssid, ssid, sizeof(wext_ssid));
		if (!g_utf8_validate(wext_ssid, -1, (const char **)&ptr))
			*ptr = '\0';

		snprintf(cmd, MAX_BUF_SIZE, "ASCII_CMD=AP_CFG,"
					"SSID_LEN=%d,SSID=%s,"
					"SEC=%s,KEY_LEN=%d,KEY=%s,CHANNEL=%d,"
					"PREAMBLE=0,MAX_SCB=%d,HIDE=%d,END",
					strlen(wext_ssid), wext_ssid,
					security, strlen(key), key,
					MOBILE_AP_WIFI_CHANNEL,
					MOBILE_AP_MAX_WIFI_STA, hide_mode);
		ret_status = __issue_ioctl(sock_fd, if_name, cmd, buf);
		if (ret_status != MOBILE_AP_ERROR_NONE) {
			ERR("__issue_ioctl failed...!!!\n");
			close(sock_fd);
			break;
		}

		/* Start broadcasting of BSS. */
		snprintf(cmd, MAX_BUF_SIZE, "ASCII_CMD=AP_BSS_START");
		ret_status = __issue_ioctl(sock_fd, if_name, cmd, buf);
		if (ret_status != MOBILE_AP_ERROR_NONE) {
			ERR("__issue_ioctl failed...!!!\n");
			close(sock_fd);
			break;
		}

		close(sock_fd);

		ret_status = _mh_core_set_ip_address(SOFTAP_IF,
				IP_ADDRESS_SOFTAP);
		if (ret_status != MOBILE_AP_ERROR_NONE) {
			ERR("_mh_core_set_ip_address of SOFTAP_IF is failed\n");
			break;
		}

		ret_status = _mh_core_set_ip_address(WIFI_IF,
				IP_ADDRESS_WIFI);
		if (ret_status != MOBILE_AP_ERROR_NONE) {
			ERR("_mh_core_set_ip_address of WIFI_IF is failed\n");
			break;
		}
		break;

	case MOBILE_AP_NL80211:

		ret_status = _mh_core_set_ip_address(WIFI_IF,
				IP_ADDRESS_SOFTAP);
		if (ret_status != MOBILE_AP_ERROR_NONE) {
			ERR("_mh_core_set_ip_address is failed\n");
			break;
		}

		ret_status = __execute_hostapd(type, ssid, security, key, hide_mode);
		if (ret_status != MOBILE_AP_ERROR_NONE) {
			ERR("__execute_hostapd is failed\n");
			break;
		}

		ret_status = __open_hostapd_intf(&hostapd_ctrl_fd, MH_CTRL_INTF);
		if (ret_status != MOBILE_AP_ERROR_NONE) {
			ERR("__open_hostapd_intf is failed\n");
			__terminate_hostapd();
			break;
		}

		ret_status = __open_hostapd_monitor(&hostapd_monitor_fd);
		if (ret_status != MOBILE_AP_ERROR_NONE) {
			ERR("__open_hostapd_monitor is failed\n");
			__close_hostapd_intf(&hostapd_ctrl_fd);
			__terminate_hostapd();
			break;
		}

		break;

	default:
		ERR("Unknown driver interface : %d\n", drv_interface);
		break;
	}

	if (ret_status != MOBILE_AP_ERROR_NONE)
		__mh_core_softap_firmware_stop();

	return ret_status;
}

int _mh_core_disable_softap(void)
{
	char cmd[MAX_BUF_SIZE] = { 0 };
	int ret_status = MOBILE_AP_ERROR_NONE;
	mobile_ap_drv_interface_e drv_interface = MOBILE_AP_DRV_INTERFACE_NONE;

	int sock_fd = 0;
	char buf[MAX_BUF_SIZE] = { 0 };
	char *if_name = WIFI_IF;

	drv_interface = __get_drv_interface();

	switch (drv_interface) {
	case MOBILE_AP_WEXT:
		if ((sock_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
			ERR("Failed to open socket...!!!\n");
			ret_status = MOBILE_AP_ERROR_RESOURCE;
			break;
		}

		/* Stop broadcasting of BSS. */
		snprintf(cmd, MAX_BUF_SIZE, "ASCII_CMD=AP_BSS_STOP");
		ret_status = __issue_ioctl(sock_fd, if_name, cmd, buf);
		if (ret_status != MOBILE_AP_ERROR_NONE) {
			ERR("__issue_ioctl failed...!!!\n");
			close(sock_fd);
			break;
		}

		close(sock_fd);
		break;

	case MOBILE_AP_NL80211:
		ret_status = __close_hostapd_intf(&hostapd_ctrl_fd);
		if (ret_status != MOBILE_AP_ERROR_NONE)
			ERR("hostapd termination is failed\n");

		ret_status = __close_hostapd_monitor(&hostapd_monitor_fd);
		if (ret_status != MOBILE_AP_ERROR_NONE)
			ERR("hostapd termination is failed\n");

		ret_status = __terminate_hostapd();
		if (ret_status != MOBILE_AP_ERROR_NONE) {
			ERR("hostapd termination is failed\n");
		}
		break;

	default:
		ERR("Unknown driver interface : %d\n", drv_interface);
		break;
	}

	if (__mh_core_softap_firmware_stop() < 0)
		ret_status = MOBILE_AP_ERROR_INTERNAL;

	return ret_status;
}

static int __get_device_info_by_wext(softap_device_info_t *di)
{
	int sock_fd = 0;
	char *if_name = SOFTAP_IF;
	char cmd[MAX_BUF_SIZE];
	char buf[MAX_BUF_SIZE] = { 0 };
	int ret = MOBILE_AP_ERROR_NONE;

	char *buf_ptr = NULL;
	int i;

	if ((sock_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		ERR("Failed to open socket...!!!\n");
		di->number = 0;
		return MOBILE_AP_ERROR_RESOURCE;
	}

	snprintf(cmd, MAX_BUF_SIZE, "AP_GET_STA_LIST");
	ret = __issue_ioctl(sock_fd, if_name, cmd, buf);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("__issue_ioctl failed...!!!\n");
		di->number = 0;
		close(sock_fd);
		return ret;
	}

	buf_ptr = buf;

	sscanf(buf_ptr, "%02x", &di->number);

	buf_ptr += 2;
	for (i = 0; i < di->number; i++) {
		unsigned int l_bssid[MOBILE_AP_WIFI_BSSID_LEN];
		sscanf(buf_ptr, "%02X%02X%02X%02X%02X%02X", &l_bssid[0],
					&l_bssid[1], &l_bssid[2], &l_bssid[3],
					&l_bssid[4], &l_bssid[5]);
		snprintf(di->bssid[i], MOBILE_AP_STR_INFO_LEN,
					"%02X:%02X:%02X:%02X:%02X:%02X",
					l_bssid[0], l_bssid[1], l_bssid[2],
					l_bssid[3], l_bssid[4], l_bssid[5]);

		SDBG("STA[%d] address[%s]\n", i, di->bssid[i]);

		buf_ptr += 12;
	}

	close(sock_fd);

	return ret;
}

static int __get_device_info_by_nl80211(softap_device_info_t *di)
{
	int ret = 0;
	int no_of_sta = 0;
	int buf_len = 0;
	char req[HOSTAPD_REQ_MAX_LEN] = {0, };
	char buf[MOBILE_AP_STR_INFO_LEN] = {0, };

	buf_len = sizeof(buf);
	g_strlcpy(req, "NUM_STA", sizeof(req));
	ret = __send_hostapd_req(hostapd_ctrl_fd,
			req, strlen(req), buf, &buf_len);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("__send_hostapd_req is failed : %d\n", ret);
		return ret;
	}

	DBG("The number of station : %s\n", buf);
	if (atoi(buf) == 0) {
		DBG("There is no station\n");
		return MOBILE_AP_ERROR_NONE;
	}

	buf_len = sizeof(buf);
	g_strlcpy(req, "STA-FIRST", sizeof(req));
	ret = __send_hostapd_req(hostapd_ctrl_fd,
			req, strlen(req), buf, &buf_len);
	if (ret != MOBILE_AP_ERROR_NONE) {
		ERR("__send_hostapd_req is failed : %d\n", ret);
		return ret;
	}

	do {
		if (!strncmp(buf, "FAIL", 4)) {
			ERR("FAIL is returned\n");
			break;
		}

		if (buf[0] == '\0') {
			ERR("NULL string\n");
			break;
		}

		SDBG("Station : %s\n", buf);
		g_strlcpy(di->bssid[no_of_sta++], buf, MOBILE_AP_STR_INFO_LEN);

		buf_len = sizeof(buf);
		snprintf(req, sizeof(req), "STA-NEXT %s", buf);
		ret = __send_hostapd_req(hostapd_ctrl_fd,
				req, strlen(req), buf, &buf_len);
	} while (ret == MOBILE_AP_ERROR_NONE);

	di->number = no_of_sta;

	return ret;
}

int _mh_core_get_device_info(softap_device_info_t *di)
{
	if (di == NULL) {
		ERR("Invalid param\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	int ret = MOBILE_AP_ERROR_NONE;

	switch (__get_drv_interface()) {
	case MOBILE_AP_WEXT:
		ret = __get_device_info_by_wext(di);
		break;

	case MOBILE_AP_NL80211:
		ret = __get_device_info_by_nl80211(di);
		break;

	default:
		ERR("Unknown interface\n");
		break;
	}

	return ret;
}

int _mh_core_execute_dhcp_server(void)
{
	char buf[DNSMASQ_CONF_LEN] = "";
	FILE *fp = NULL;
	pid_t pid;

	fp = fopen(DNSMASQ_CONF_FILE, "w");
	if (NULL == fp) {
		ERR("Could not create the file.\n");
		return MOBILE_AP_ERROR_RESOURCE;
	}
	snprintf(buf, DNSMASQ_CONF_LEN, DNSMASQ_CONF);
	fputs(buf, fp);
	fclose(fp);

	pid = fork();
	if (pid < 0) {
		ERR("fork failed\n");
		return MOBILE_AP_ERROR_RESOURCE;
	}

	if (pid == 0) {
		/* -d : Debug mode
		 * -p 0 : DNS off
		 * -C file : Configuration file path
		 */
		if (execl("/usr/bin/dnsmasq", "/usr/bin/dnsmasq", "-d",
					"-p", "0", "-C", DNSMASQ_CONF_FILE,
					(char *)NULL)) {
			ERR("execl failed\n");
		}

		ERR("Should not get here!");
		return MOBILE_AP_ERROR_RESOURCE;
	}

	dnsmasq_pid = pid;

	return MOBILE_AP_ERROR_NONE;
}

int _mh_core_terminate_dhcp_server(void)
{
	int ret;

	if (dnsmasq_pid == 0) {
		ERR("There is no dnsmasq\n");
		return MOBILE_AP_ERROR_NONE;
	}

	kill(dnsmasq_pid, SIGTERM);
	waitpid(dnsmasq_pid, NULL, 0);
	dnsmasq_pid = 0;

	ret = unlink(DNSMASQ_CONF_FILE);
	if (ret < 0) {
		ERR("unlink is failed : %s\n", strerror(errno));
	}

	return MOBILE_AP_ERROR_NONE;
}

int _mh_core_enable_masquerade(const char *ext_if)
{
	if (ext_if == NULL || strlen(ext_if) == 0) {
		ERR("ext_if[%s] is invalid\n", ext_if);
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	int fd = -1;

	fd = open(IP_FORWARD, O_WRONLY);
	if (fd < 0) {
		ERR("open failed\n");
		return MOBILE_AP_ERROR_RESOURCE;
	}

	if (write(fd, "1", 1) != 1) {
		ERR("write failed\n");
		close(fd);
		return MOBILE_AP_ERROR_INTERNAL;
	}
	close(fd);

	_iptables_create_chain(TABLE_NAT, TETH_NAT_POST);
	_iptables_add_rule(PKT_REDIRECTION_RULE, TABLE_NAT, CHAIN_POST,
			TETH_NAT_POST);
	_iptables_add_rule(MASQ_RULE, TABLE_NAT, TETH_NAT_POST, ext_if);

	_iptables_create_chain(TABLE_FILTER, TETH_FILTER_FW);

	_iptables_add_rule(PKT_REDIRECTION_RULE, TABLE_FILTER, CHAIN_FW,
			TETH_FILTER_FW);

	_iptables_add_rule(CLAMP_MSS_RULE, TABLE_FILTER, TETH_FILTER_FW);

	_iptables_add_rule(FORWARD_RULE_WITH_ACTION_AND_STATE, TABLE_FILTER, TETH_FILTER_FW,
		BT_IF_ALL, ext_if, ACTION_RETURN, STATE_RELATED_ESTAB);
	_iptables_add_rule(FORWARD_RULE_WITH_ACTION_AND_STATE, TABLE_FILTER, TETH_FILTER_FW,
		WIFI_IF, ext_if, ACTION_RETURN, STATE_RELATED_ESTAB);
	_iptables_add_rule(FORWARD_RULE_WITH_ACTION_AND_STATE, TABLE_FILTER, TETH_FILTER_FW,
		USB_IF, ext_if, ACTION_RETURN, STATE_RELATED_ESTAB);

	_iptables_add_rule(FORWARD_RULE_WITH_ACTION_AND_STATE, TABLE_FILTER, TETH_FILTER_FW,
		ext_if, BT_IF_ALL, ACTION_DROP, STATE_INVALID);
	_iptables_add_rule(FORWARD_RULE_WITH_ACTION_AND_STATE, TABLE_FILTER, TETH_FILTER_FW,
		ext_if, WIFI_IF, ACTION_DROP, STATE_INVALID);
	_iptables_add_rule(FORWARD_RULE_WITH_ACTION_AND_STATE, TABLE_FILTER, TETH_FILTER_FW,
		ext_if, USB_IF, ACTION_DROP, STATE_INVALID);

	_iptables_add_rule(FORWARD_RULE_WITH_ACTION, TABLE_FILTER, TETH_FILTER_FW,
		ext_if, BT_IF_ALL, ACTION_RETURN);
	_iptables_add_rule(FORWARD_RULE_WITH_ACTION, TABLE_FILTER, TETH_FILTER_FW,
		ext_if, WIFI_IF, ACTION_RETURN);
	_iptables_add_rule(FORWARD_RULE_WITH_ACTION, TABLE_FILTER, TETH_FILTER_FW,
		ext_if, USB_IF, ACTION_RETURN);

	_iptables_add_rule(FORWARD_RULE_WITH_ACTION, TABLE_FILTER, TETH_FILTER_FW,
		BT_IF_ALL, ext_if, ACTION_RETURN);
	_iptables_add_rule(FORWARD_RULE_WITH_ACTION, TABLE_FILTER, TETH_FILTER_FW,
		WIFI_IF, ext_if, ACTION_RETURN);
	_iptables_add_rule(FORWARD_RULE_WITH_ACTION, TABLE_FILTER, TETH_FILTER_FW,
		USB_IF, ext_if, ACTION_RETURN);

	_iptables_add_rule(DEFAULT_RULE, TABLE_FILTER, TETH_FILTER_FW,
		ACTION_DROP);

	return MOBILE_AP_ERROR_NONE;
}

int _mh_core_disable_masquerade(const char *ext_if)
{
	if (ext_if == NULL || strlen(ext_if) == 0) {
		ERR("ext_if[%s] is invalid\n", ext_if);
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	int fd = -1;

	fd = open(IP_FORWARD, O_WRONLY);
	if (fd < 0) {
		ERR("open failed\n");
		return MOBILE_AP_ERROR_RESOURCE;
	}

	if (write(fd, "0", 1) != 1) {
		ERR("write failed\n");
		close(fd);
		return MOBILE_AP_ERROR_INTERNAL;
	}
	close(fd);

	_iptables_delete_rule(PKT_REDIRECTION_RULE, TABLE_NAT, CHAIN_POST,
			TETH_NAT_POST);
	_iptables_flush_rules(TABLE_NAT, TETH_NAT_POST);
	_iptables_delete_chain(TABLE_NAT, TETH_NAT_POST);

	_iptables_delete_rule(PKT_REDIRECTION_RULE, TABLE_FILTER, CHAIN_FW,
			TETH_FILTER_FW);
	_iptables_flush_rules(TABLE_FILTER, TETH_FILTER_FW);
	_iptables_delete_chain(TABLE_FILTER, TETH_FILTER_FW);

	return MOBILE_AP_ERROR_NONE;
}

int _mh_core_set_ip_address(const char *if_name, const in_addr_t ip)
{
	struct ifreq ifr;
	struct sockaddr_in addr;
	int sock_fd;

	SDBG("if_name : %s ip address : 0x%X\n", if_name, ip);

	if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		ERR("socket open failed!!!\n");
		return MOBILE_AP_ERROR_RESOURCE;
	}

	g_strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);

	memset(&addr, 0, sizeof(struct sockaddr));
	addr.sin_family = AF_INET;
	addr.sin_port = 0;
	addr.sin_addr.s_addr = htonl(ip);

	memcpy(&ifr.ifr_addr, &addr, sizeof(struct sockaddr));
	if (ioctl(sock_fd, SIOCSIFADDR, &ifr) < 0) {
		ERR("ioctl failed...!!!\n");
		close(sock_fd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) < 0) {
		ERR("ioctl failed...!!!\n");
		close(sock_fd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) < 0) {
		ERR("ioctl failed...!!!\n");
		close(sock_fd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	close(sock_fd);

	return MOBILE_AP_ERROR_NONE;
}

static gboolean __send_station_event_cb(gpointer data)
{
	int sig = GPOINTER_TO_INT(data);
	int n_station = 0;
	int type;
	mobile_ap_station_info_t *si = NULL;

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI))
		type = MOBILE_AP_TYPE_WIFI;
	else if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI_AP))
		type = MOBILE_AP_TYPE_WIFI_AP;
	else
		return FALSE;

	if (sig == SIGUSR1) {
		DBG("STA connected(%d)\n", sig);
		/* STA connection is handled in the dnsmasq signal handler */
	} else if (sig == SIGUSR2) {
		DBG("STA disconnected(%d)\n", sig);

		/* Temporarily care only one station.
		 * Driver team should be support detail information */
		if (_get_station_info((gconstpointer)type,
				_slist_find_station_by_interface,
				&si) != MOBILE_AP_ERROR_NONE) {
			return FALSE;
		}
		_remove_station_info(si->mac, _slist_find_station_by_mac);

		_get_station_count((gconstpointer)type,
				_slist_find_station_by_interface, &n_station);
		if (n_station == 0) {
			if (type == MOBILE_AP_TYPE_WIFI)
				_start_timeout_cb(type, time(NULL) + TETHERING_CONN_TIMEOUT);
			else if (type == MOBILE_AP_TYPE_WIFI_AP)
				_start_timeout_cb(type, time(NULL) + WIFI_AP_CONN_TIMEOUT);
		}
	}

	return FALSE;
}

static void __handle_station_signal(int sig)
{
	int idle_id = 0;
	idle_id = g_idle_add(__send_station_event_cb, GINT_TO_POINTER(sig));
	if (idle_id == 0) {
		ERR("g_idle_add is failed\n");
	}
}

void _register_wifi_station_handler(void)
{
	struct sigaction sa;

	if (__get_drv_interface() != MOBILE_AP_WEXT)
		return;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = __handle_station_signal;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);

	return;
}

void _unregister_wifi_station_handler(void)
{
	struct sigaction sa;

	if (__get_drv_interface() != MOBILE_AP_WEXT)
		return;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);

	return;
}

static gboolean __hostapd_connect_timer_cb(gpointer user_data)
{
	char *mac = (char *)user_data;
	GSList *l = NULL;
	GSList *temp = NULL;
	sta_timer_t *ptr = NULL;
	mobile_ap_station_info_t *info = NULL;
	time_t tm;
	int n_station = 0;
	int type;
	int ret;

	if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI))
		type = MOBILE_AP_TYPE_WIFI;
	else if (_mobileap_is_enabled(MOBILE_AP_STATE_WIFI_AP))
		type = MOBILE_AP_TYPE_WIFI_AP;
	else
		return FALSE;

	for (l = sta_timer_list; l != NULL; l = g_slist_next(l)) {
		ptr = (sta_timer_t *)l->data;
		if (ptr == NULL)
			continue;

		if (!g_strcmp0(ptr->mac_addr, mac)) {
			DBG("client with Static IP, Add station\n");

			info = (mobile_ap_station_info_t *)g_malloc(sizeof(mobile_ap_station_info_t));
			if (info == NULL) {
				ERR("g_malloc failed\n");
				g_free(ptr->mac_addr);
				g_free(ptr);
				temp = l;
				l = g_slist_next(l);
				sta_timer_list = g_slist_delete_link(sta_timer_list, temp);
				break;
			}

			time(&tm);
			info->tm = tm;
			info->interface = type;
			g_strlcpy(info->ip, "", sizeof(info->ip));
			g_strlcpy(info->mac, mac, sizeof(info->mac));

			ret = _get_wifi_name_from_lease_info(mac, &info->hostname);
			if (ret != MOBILE_AP_ERROR_NONE)
				info->hostname = g_strdup(MOBILE_AP_NAME_UNKNOWN);

			g_free(ptr->mac_addr);
			g_free(ptr);
			temp = l;
			l = g_slist_next(l);
			sta_timer_list = g_slist_delete_link(sta_timer_list, temp);

			goto SUCCESS;
		}
	}

	return FALSE;

SUCCESS :
	if (_add_station_info(info) != MOBILE_AP_ERROR_NONE) {
		g_free(info->hostname);
		g_free(info);
		return FALSE;
	}

	_get_station_count((gconstpointer)type,
			_slist_find_station_by_interface, &n_station);
	if (n_station == 1)
		_stop_timeout_cb(type);

	_send_dbus_station_info("DhcpConnected", info);

	return FALSE;
}

void _flush_dhcp_ack_timer(void)
{
	DBG("+\n");

	GSList *l = NULL;
	GSList *temp = NULL;
	sta_timer_t *ptr = NULL;

	for (l = sta_timer_list; l != NULL; l = g_slist_next(l)) {
		ptr = (sta_timer_t *)l->data;
		if (ptr) {
			if (ptr->tid != 0) {
				g_source_remove(ptr->tid);
				ptr->tid = 0;
			}
			g_free(ptr->mac_addr);
			g_free(ptr);
		}

		temp = l;
		l = g_slist_next(l);
		sta_timer_list = g_slist_delete_link(sta_timer_list, temp);
	}

	DBG("-\n");
	return;
}

void _destroy_dhcp_ack_timer(char *mac_addr)
{
	DBG("+\n");
	if (mac_addr == NULL) {
		ERR("mac address passed NULL\n");
		return;
	}

	GSList *l = NULL;
	GSList *temp = NULL;
	sta_timer_t *ptr = NULL;

	for (l = sta_timer_list; l != NULL; l = g_slist_next(l)) {

		ptr = (sta_timer_t *)l->data;
		if (ptr == NULL)
			continue;

		if (!g_strcmp0(ptr->mac_addr, mac_addr)) {

			if (ptr->tid != 0) {
				g_source_remove(ptr->tid);
				ptr->tid = 0;
			}
			g_free(ptr->mac_addr);
			g_free(ptr);
			temp = l;
			l = g_slist_next(l);
			sta_timer_list = g_slist_delete_link(sta_timer_list,
						temp);
			break;
		}
	}

	DBG("-\n");
	return;
}
