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
#include <dbus/dbus-glib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
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
#include "mobileap_agent.h"
#include "mobileap_handler.h"

static pid_t dnsmasq_pid = 0;
static pid_t hostapd_pid = 0;
static int hostapd_ctrl_fd = 0;
static int hostapd_monitor_fd = 0;
static GIOChannel *hostapd_io_channel = NULL;
static guint hostapd_io_source = 0;

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

static int __get_psk_hexascii(const char *pass, const unsigned char *salt, char *psk, unsigned int psk_len)
{
	if (pass == NULL || salt == NULL || psk == NULL || psk_len == 0) {
		ERR("Invalid parameter\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	if (psk_len < SHA256_DIGEST_LENGTH * 2 + 1) {
		ERR("Invalid parameter\n");
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	int i;
	int d_16;
	int r_16;
	unsigned char buf[SHA256_DIGEST_LENGTH] = {0, };

	if (!PKCS5_PBKDF2_HMAC_SHA1(pass, strlen(pass),
				salt, strlen((const char *)salt),
				PSK_ITERATION_COUNT, sizeof(buf), buf)) {
		ERR("Getting psk is failed\n");
		return MOBILE_AP_ERROR_INTERNAL;
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

static int __execute_hostapd(const char *ssid, const char *security,
		const char *key, int hide_mode)
{
	DBG("+\n");

	char psk[2 * SHA256_DIGEST_LENGTH + 1] = {0, };
	char buf[HOSTAPD_CONF_LEN] = "";
	char sec_buf[HOSTAPD_CONF_LEN] = "";
	FILE *fp = NULL;
	pid_t pid;

	if (security != NULL && !strcmp(security, "wpa2-psk")) {
		if (__get_psk_hexascii(key, (const unsigned char *)ssid, psk,
					sizeof(psk)) != MOBILE_AP_ERROR_NONE) {
			ERR("Getting PSK(Hex ascii type) is failed\n");
			return MOBILE_AP_ERROR_INTERNAL;
		}

		snprintf(sec_buf, HOSTAPD_CONF_LEN,
				"wpa=2\nrsn_pairwise=CCMP\nwpa_psk=%s\nwps_state=2\neap_server=1",
				psk);
	}

	snprintf(buf, HOSTAPD_CONF_LEN, HOSTAPD_CONF,
			WIFI_IF,
			HOSTAPD_CTRL_INTF_DIR,
			ssid,
			MOBILE_AP_WIFI_CHANNEL,
			hide_mode ? 2 : 0,
			MOBILE_AP_MAX_WIFI_STA,
			sec_buf);

	fp = fopen(HOSTAPD_CONF_FILE, "w");
	if (NULL == fp) {
		ERR("Could not create the file.\n");
		return MOBILE_AP_ERROR_RESOURCE;
	}
	fputs(buf, fp);
	fclose(fp);

	pid = fork();
	if (pid < 0) {
		ERR("fork failed\n");
		return MOBILE_AP_ERROR_RESOURCE;
	}

        if (pid == 0) {
		if (execl(HOSTAPD_BIN, HOSTAPD_BIN, "-e", HOSTAPD_ENTROPY_FILE,
					HOSTAPD_CONF_FILE,
					"-f", HOSTAPD_DEBUG_FILE, "-dd",
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

	if (hostapd_pid == 0) {
		DBG("There is no hostapd\n");
		return MOBILE_AP_ERROR_NONE;
	}

	kill(hostapd_pid, SIGTERM);
	waitpid(hostapd_pid, NULL, 0);
	hostapd_pid = 0;

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
			DBG("Unsolicited message\n");
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
		DBG("There is already mh interface. It will be removed\n");
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
		DBG("connect is failed : %s\n", strerror(errno));
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

	char buf[HOSTAPD_REQ_MAX_LEN] = {0, };
	char *pbuf = NULL;
	gsize read = 0;
	int n_station = 0;

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

	if (buf[0] == '<' && (pbuf = strchr(buf, '>')) != NULL) {
		pbuf++;
	} else {
		pbuf = buf;
	}

	DBG("Event : %s\n", pbuf);

	if (!strncmp(pbuf, HOSTAPD_STA_DISCONN, strlen(HOSTAPD_STA_DISCONN))) {
		pbuf = strchr(pbuf, ' ');
		if (pbuf == NULL) {
			ERR("There is no info. for disconnected station\n");
			return TRUE;
		}
		pbuf++;

		DBG("Disconnected station MAC : %s\n", pbuf);
		_remove_station_info(pbuf, _slist_find_station_by_mac);

		_get_station_count((gconstpointer)MOBILE_AP_TYPE_WIFI,
				_slist_find_station_by_interface, &n_station);
		if (n_station == 0)
			_start_timeout_cb(MOBILE_AP_TYPE_WIFI);

		return TRUE;
	} else {
		DBG("Event is not handled\n");
	}

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
	DBG("return : %s\n", buf);

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
	DBG("return : %s\n", buf);

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

int _mh_core_enable_softap(const char *ssid, const char *security,
		const char *key, int hide_mode)
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

	snprintf(cmd, sizeof(cmd), "%s softap", WLAN_SCRIPT);
	if (_execute_command(cmd)) {
		ERR("execute script failed : %s\n", cmd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	drv_interface = __get_drv_interface();

	switch (drv_interface) {
	case MOBILE_AP_WEXT:
		if ((sock_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
			ERR("Failed to open socket...!!!\n");
			ret_status = MOBILE_AP_ERROR_RESOURCE;
			break;
		}

		snprintf(cmd, MAX_BUF_SIZE, "ASCII_CMD=AP_CFG,"
					"SSID_LEN=%d,SSID=%s,"
					"SEC=%s,KEY_LEN=%d,KEY=%s,CHANNEL=%d,"
					"PREAMBLE=0,MAX_SCB=%d,HIDE=%d,END",
					strlen(ssid), ssid,
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

		DBG("Setting softap is OK\n");
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

		ret_status = __execute_hostapd(ssid, security, key, hide_mode);
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
		DBG("Unknown driver interface : %d\n", drv_interface);
		break;
	}

	if (ret_status != MOBILE_AP_ERROR_NONE) {
		snprintf(cmd, sizeof(cmd), "%s stop", WLAN_SCRIPT);
		if (_execute_command(cmd)) {
			ERR("execute script failed : %s\n", cmd);
		}
	}

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
		DBG("Unknown driver interface : %d\n", drv_interface);
		break;
	}

	snprintf(cmd, sizeof(cmd), "%s stop", WLAN_SCRIPT);
	if (_execute_command(cmd)) {
		ERR("execute script failed : %s\n", cmd);
		ret_status = MOBILE_AP_ERROR_INTERNAL;
	}

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
	DBG("connected station : %d\n", di->number);

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

		DBG("STA[%d] address[%s]\n", i, di->bssid[i]);

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

		DBG("Station : %s\n", buf);
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
	if (dnsmasq_pid == 0) {
		DBG("There is no dnsmasq\n");
		return MOBILE_AP_ERROR_NONE;
	}

	kill(dnsmasq_pid, SIGTERM);
	waitpid(dnsmasq_pid, NULL, 0);
	dnsmasq_pid = 0;

	return MOBILE_AP_ERROR_NONE;
}

int _mh_core_enable_masquerade(const char *ext_if)
{
	if (ext_if == NULL || strlen(ext_if) == 0) {
		ERR("ext_if[%s] is invalid\n", ext_if);
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	int fd = -1;
	char cmd[MAX_BUF_SIZE] = {0, };

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

	snprintf(cmd, sizeof(cmd), "%s -t nat -A POSTROUTING "MASQUERADE_RULE,
			IPTABLES, ext_if);
	if (_execute_command(cmd)) {
		ERR("iptables failed : %s\n", cmd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	_add_data_usage_rule(WIFI_IF, ext_if);
	_add_data_usage_rule(BT_IF_ALL, ext_if);
	_add_data_usage_rule(USB_IF, ext_if);

	return MOBILE_AP_ERROR_NONE;
}

int _mh_core_disable_masquerade(const char *ext_if)
{
	if (ext_if == NULL || strlen(ext_if) == 0) {
		ERR("ext_if[%s] is invalid\n", ext_if);
		return MOBILE_AP_ERROR_INVALID_PARAM;
	}

	int fd = -1;
	char cmd[MAX_BUF_SIZE] = {0, };

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

	snprintf(cmd, sizeof(cmd), "%s -t nat -D POSTROUTING "MASQUERADE_RULE,
			IPTABLES, ext_if);
	if (_execute_command(cmd)) {
		ERR("iptables failed : %s\n", cmd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	_del_data_usage_rule(WIFI_IF, ext_if);
	_del_data_usage_rule(BT_IF_ALL, ext_if);
	_del_data_usage_rule(USB_IF, ext_if);

	return MOBILE_AP_ERROR_NONE;
}

void _mh_core_add_data_to_array(GPtrArray *array, guint type, gchar *dev_name)
{
	GValue value = {0, {{0}}};

	g_value_init(&value, DBUS_STRUCT_UINT_STRING);
	g_value_take_boxed(&value,
			dbus_g_type_specialized_construct(DBUS_STRUCT_UINT_STRING));
	dbus_g_type_struct_set(&value, 0, type, 1, dev_name, G_MAXUINT);
	g_ptr_array_add(array, g_value_get_boxed(&value));
}

int _mh_core_set_ip_address(const char *if_name, const in_addr_t ip)
{
	struct ifreq ifr;
	struct sockaddr_in addr;
	int sock_fd;

	DBG("if_name : %s ip address : 0x%X\n", if_name, ip);

	if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		ERR("socket open failed!!!\n");
		perror("ioctl fail");
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
		perror("ioctl fail");
		close(sock_fd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) < 0) {
		ERR("ioctl failed...!!!\n");
		perror("ioctl fail");
		close(sock_fd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) < 0) {
		ERR("ioctl failed...!!!\n");
		perror("ioctl fail");
		close(sock_fd);
		return MOBILE_AP_ERROR_INTERNAL;
	}

	close(sock_fd);

	return MOBILE_AP_ERROR_NONE;
}
