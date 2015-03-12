#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#ifdef PC_BUILD
#define log_printf(level, fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#include <debug/log.h>
#endif

#include "airos-stats.h"
#include "cJSON.h"

#define MAX_BUF_LEN 32768

airos_stats_t *stats;

static char* read_output(int fd) {
	static char buf[MAX_BUF_LEN];

	memset(buf, 0, MAX_BUF_LEN);
	ssize_t len, pos = 0;
	while ((len = read(fd, buf + pos, MAX_BUF_LEN - pos)) > 0)
		pos+= len;

	char* eol = strchr(buf, '\r');
	if (eol)
		memset(buf, ' ', eol - buf);

	return pos > 0 ? buf : NULL;
}

static const char* get_process_output(const char *path, const char *arg1, const char *arg2) {
	int pipefd[2];
	if (pipe(pipefd) == -1) {
		log_printf(LOG_VERBOSE, "pipe() error: %s (%d)\n", strerror(errno), errno);
		return NULL;
	}

	pid_t pid = fork();
	if (pid == -1) {
		log_printf(LOG_VERBOSE, "fork() error: %s (%d)\n", strerror(errno), errno);
		return NULL;
	}

	if (pid == 0) {
		prctl(PR_SET_PDEATHSIG, SIGHUP); /* SIGHUP when parent terminates */
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[0]);
		int rc = execl(path, arg1, arg2, (char*) NULL);
		if (rc == -1)
			close(STDOUT_FILENO);
		_exit(EXIT_FAILURE);
	}
	else {
		close(pipefd[1]);
		const char* output = read_output(pipefd[0]);
		close(pipefd[0]);

		int status; /* TODO: timeout & co */
		waitpid(pid, &status, WUNTRACED | WCONTINUED);
		if (WIFEXITED(status) && WEXITSTATUS(status)) {
			log_printf(LOG_VERBOSE, "child exited with status %d\n", WEXITSTATUS(status));
		}

		return output;
	}

	return NULL;
}

static const char* get_status_cgi(void) {
#ifdef PC_BUILD
	return get_process_output("/bin/cat", "cat", "./status.json");
#else
	return get_process_output("/usr/www/status.cgi", "status.cgi", (const char*) NULL);
#endif
}

static const char* get_wstalist(size_t *len) {
#ifdef PC_BUILD
	*len=0;
	return get_process_output("/bin/cat", "cat", "stalist.json");
#else
	struct stat st;
	const char *mem = 0;
	int fd = open("/tmp/stats/wstalist", O_RDONLY);

	*len=0;
	if (fd < 0)
		return 0;
	if (fstat(fd, &st) != 0) {
		close(fd);
		return 0;
	}
	mem = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		close(fd);
		return 0;
	}
	close(fd);
	*len = st.st_size;
	return mem;
#endif
}

static int get_json_uint32(cJSON* item, const char* key, uint32_t* dest) {
	cJSON* value = cJSON_GetObjectItem(item, key);
	if (!value || value->type != cJSON_Number)
		return -1;

	*dest = (uint32_t) value->valueint;
	return 0;
}

static int get_json_int(cJSON* item, const char* key, int* dest) {
	cJSON* value = cJSON_GetObjectItem(item, key);
	if (!value || value->type != cJSON_Number)
		return -1;

	*dest = value->valueint;
	return 0;
}

static int get_json_string(cJSON* item, const char* key, char* dest, size_t len) {
	cJSON* value = cJSON_GetObjectItem(item, key);
	if (!value || value->type != cJSON_String)
		return -1;

	strncpy(dest, value->valuestring, len);
	return 0;
}

static int get_json_uint64(cJSON* item, const char* key, uint64_t* dest) {
	cJSON* value = cJSON_GetObjectItem(item, key);
	if (!value || value->type != cJSON_Number)
		return -1;

	*dest = (uint64_t) value->valueint;
	return 0;
}

static int get_json_hwaddr(cJSON* item, const char* key, char* dest, size_t len) {
	cJSON* value = cJSON_GetObjectItem(item, key);
	if (!value || value->type != cJSON_String)
		return -1;

	char buf[18];
	memset(buf, 0, sizeof(buf));
	strncpy(buf, value->valuestring, sizeof(buf) - 1);

	if (len >=6 && strlen(buf) == 17) {
		int ret = sscanf(buf, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
			&dest[0], &dest[1], &dest[2], &dest[3], &dest[4], &dest[5]);
		if (ret == 6)
			return 0;
	}

	return -2;
}

static int get_json_ipaddr(cJSON* item, const char* key, struct in_addr* dest) {
	cJSON* value = cJSON_GetObjectItem(item, key);
	if (!value || value->type != cJSON_String)
		return -1;

	char buf[32];
	memset(buf, 0, sizeof(buf));
	strncpy(buf, value->valuestring, sizeof(buf) - 1);

	if (inet_aton(buf, dest) == 0)
		return -2;

	return 0;
}

static int get_json_float(cJSON* item, const char* key, float* dest) {
	cJSON* value = cJSON_GetObjectItem(item, key);
	if (!value) return -1;

	int rc = 0;
	if (value->type == cJSON_String) {
		char buf[32];
		memset(buf, 0, sizeof(buf));

		rc = get_json_string(item, key, buf, sizeof(buf) -1);
		if (rc == 0) *dest = atof(buf);
	}
	else if (value->type == cJSON_Number) {
		*dest = (float) value->valuedouble;
	}
	else
		rc = -2;

	return rc;
}

static int get_int_array(cJSON* json, const char* key, int32_t* arr, size_t len) {
	cJSON* value = cJSON_GetObjectItem(json, key);
	if (!value || value->type != cJSON_Array) return -1;

	int i, count = cJSON_GetArraySize(value);
	for (i = 0; i < count && i < len; ++i) {
		cJSON* item = cJSON_GetArrayItem(value, i);
		if (item && item->type == cJSON_Number)
			arr[i] = item->valueint;
	}

	return 0;
}

static int get_rssi_stats(cJSON* wl, rssi_stats_t* rs) {
	int rc = get_int_array(wl, "chainrssi", rs->rssi, sizeof(rs->rssi));
	if (rc) return rc;

	rc = get_int_array(wl, "chainrssimgmt", rs->rssi_mgmt, sizeof(rs->rssi_mgmt));
	if (rc) return rc;

	rc = get_int_array(wl, "chainrssiext", rs->rssi_ext, sizeof(rs->rssi_ext));
	if (rc) return rc;

	return 0;
}

static int get_radio_stats(cJSON* json, radio_stats_t* stats) {
	strncpy(stats->ifname, "ath0", sizeof(stats->ifname));

	cJSON* wl = cJSON_GetObjectItem(json, "wireless");
	if (!wl) return -1;

	char mode[IFNAMSIZ];
	uint32_t wds, aprepeater;
	if (get_json_string(wl, "mode", mode, sizeof(mode)) == 0 &&
		get_json_uint32(wl, "wds", &wds) == 0 &&
		get_json_uint32(wl, "aprepeater", &aprepeater) == 0) {
		if (strncmp(mode, "ap", sizeof("ap") - 1) == 0) {
			if (!wds)
				stats->mode = 2;
			else
				stats->mode = !aprepeater ? 4 : 3;
		}
		else {
			stats->mode = 1;
		}
	}

	get_json_uint32(wl, "countrycode", &stats->country_code);

	char buf[32];
	if (get_json_string(wl, "frequency", buf, sizeof(buf)) == 0)
		sscanf(buf, "%u MHz", &stats->frequency);

	if (get_json_string(wl, "dfs", buf, sizeof(buf)) == 0)
		stats->dfs_status = atoi(buf) ? 1 : 2;

	get_json_int(wl, "txpower", &stats->txpower);
	get_json_uint32(wl, "distance", &stats->distance);
	get_json_uint32(wl, "tx_chainmask", &stats->chainmask);
	get_json_string(wl, "antenna", stats->antenna, sizeof(stats->antenna));
	get_rssi_stats(wl, &stats->rssi_stats);

	return 0;
}

static int get_airmax_stats(cJSON* json, airmax_stats_t* stats) {
	strncpy(stats->ifname, "ath0", sizeof(stats->ifname));

	cJSON* wl = cJSON_GetObjectItem(json, "wireless");
	if (!wl) return -1;

	cJSON* airmax = cJSON_GetObjectItem(wl, "polling");
	if (!airmax) return -2;

	get_json_uint32(airmax, "enabled", &stats->status);
	stats->status = stats->status ? 1 : 2;
	if (stats->status) {
		get_json_uint32(airmax, "quality", &stats->quality);
		get_json_uint32(airmax, "capacity", &stats->capacity);
		get_json_uint32(airmax, "priority", &stats->priority);
		get_json_uint32(airmax, "noack", &stats->no_ack);
		stats->no_ack = stats->no_ack ? 1 : 2;
	}
	return 0;
}

static int get_airsync_stats(cJSON* json, airsync_stats_t* stats) {
	strncpy(stats->ifname, "ath0", sizeof(stats->ifname));

	cJSON* wl = cJSON_GetObjectItem(json, "wireless");
	if (!wl) return -1;

	cJSON* airmax = cJSON_GetObjectItem(wl, "polling");
	if (!airmax) return -2;

	get_json_uint32(airmax, "airsync_mode", &stats->mode);
	get_json_uint32(airmax, "aircync_connections", &stats->count);
	get_json_uint32(airmax, "airsync_down_util", &stats->down_util);
	get_json_uint32(airmax, "airsync_up_util", &stats->up_util);

	return 0;
}

static int get_airsel_stats(cJSON* json, airsel_stats_t* stats) {
	strncpy(stats->ifname, "ath0", sizeof(stats->ifname));

	cJSON* wl = cJSON_GetObjectItem(json, "wireless");
	if (!wl) return -1;

	cJSON* airmax = cJSON_GetObjectItem(wl, "polling");
	if (!airmax) return -2;

	get_json_uint32(airmax, "airselect", &stats->status);
	stats->status = stats->status ? 1 : 2;
	get_json_uint32(airmax, "airselect_interval", &stats->interval);

	return 0;
}

static int get_wlan_stats(cJSON* json, wlan_stats_t* stats) {
	strncpy(stats->ifname, "ath0", sizeof(stats->ifname));

	cJSON* wl = cJSON_GetObjectItem(json, "wireless");
	if (!wl) return -1;

	get_json_string(wl, "essid", stats->ssid, sizeof(stats->ssid));
	get_json_uint32(wl, "hide_essid", &stats->hide_ssid);
	stats->hide_ssid = stats->hide_ssid ? 1 : 2;

	get_json_hwaddr(wl, "apmac", stats->ap_hwaddr, sizeof(stats->ap_hwaddr));
	get_json_int(wl, "signal", &stats->signal);
	get_json_uint32(wl, "rssi", &stats->rssi);
	get_json_int(wl, "noisef", &stats->noise_floor);
	get_json_uint32(wl, "ccq", &stats->ccq);
	stats->ccq /= 10;
	get_json_float(wl, "txrate", &stats->tx_rate);
	get_json_float(wl, "rxrate", &stats->rx_rate);
	get_json_string(wl, "security", stats->security, sizeof(stats->security));
	get_json_uint32(wl, "wds", &stats->wds_status);
	stats->wds_status = stats->wds_status ? 1 : 2;
	get_json_uint32(wl, "aprepeater", &stats->repeater_status);
	stats->repeater_status = stats->repeater_status ? 1 : 2;

	get_json_uint32(wl, "chanbw", &stats->channel_width);
	if (!stats->channel_width)
		get_json_uint32(wl, "chwidth", &stats->channel_width);

	return 0;
}

static void print_sta(const sta_info_t* info) {
	log_printf(LOG_VERBOSE, "\nhwaddr:   " __MACSTR "\n", __MAC2STR(info->hwaddr));
	log_printf(LOG_VERBOSE, "name:     %s\n", info->name);
	log_printf(LOG_VERBOSE, "signal:   %d\n", info->signal);
	log_printf(LOG_VERBOSE, "noisef:   %d\n", info->noisef);
	log_printf(LOG_VERBOSE, "dist:     %u\n", info->distance);
	log_printf(LOG_VERBOSE, "ccq:      %u\n", info->ccq);
	log_printf(LOG_VERBOSE, "amq: %u amc: %u amp: %u\n",
			info->quality, info->capacity, info->priority);
	log_printf(LOG_VERBOSE, "ip:       %s\n", inet_ntoa(info->ip));
	log_printf(LOG_VERBOSE, "tx_rate:  %g\n", info->tx_rate);
	log_printf(LOG_VERBOSE, "rx_rate:  %g\n", info->rx_rate);
	log_printf(LOG_VERBOSE, "tx_bytes: %llu\n", info->tx_bytes);
	log_printf(LOG_VERBOSE, "rx_bytes: %llu\n", info->rx_bytes);
	log_printf(LOG_VERBOSE, "conn_time: %u\n", info->conn_time);
}

static int attach_stalist(airos_stats_t* stats) {
	size_t len = 0;
	const char* sl_buf = get_wstalist(&len);
	if (sl_buf) {
		cJSON* sl_json = cJSON_Parse(sl_buf);
		munmap(sl_buf, len);
		if (!sl_json) {
			cJSON_Delete(sl_json);
			log_printf(LOG_VERBOSE, "failed to parse station list\n");
			return -1;
		}

		int i, st_count = cJSON_GetArraySize(sl_json);

		if (stats->sta_list.count < st_count) {
			sta_info_t* tmp = stats->sta_list.sta;
			size_t arr_size = st_count * sizeof(stats->sta_list.sta[0]);
			stats->sta_list.sta = realloc(stats->sta_list.sta, arr_size);
			if (stats->sta_list.sta != NULL) {
				stats->sta_list.count = st_count;
				memset(stats->sta_list.sta, 0, arr_size);
			}
			else {
				stats->sta_list.count = 0;
				free(tmp);
				return -3;
			}
		}

		for (i = 0; i < st_count; ++i) {
			cJSON* sta = cJSON_GetArrayItem(sl_json, i);
			if (!sta) break;

			sta_info_t* info = &stats->sta_list.sta[i];

			get_json_hwaddr(sta, "mac", info->hwaddr, sizeof(info->hwaddr));
			get_json_string(sta, "name", info->name, sizeof(info->name) - 1);
			get_json_int(sta, "signal", &info->signal);
			get_json_int(sta, "noisefloor", &info->noisef);
			get_json_uint32(sta, "distance", &info->distance);
			get_json_uint32(sta, "ccq", &info->ccq);

			cJSON* airmax = cJSON_GetObjectItem(sta, "airmax");
			if (airmax && airmax->type == cJSON_Object) {
				get_json_uint32(airmax, "quality", &info->quality);
				get_json_uint32(airmax, "capacity", &info->capacity);
				get_json_uint32(airmax, "priority", &info->priority);

                                cJSON* airmax_rx = cJSON_GetObjectItem(airmax, "rx");
                                if (airmax_rx && airmax_rx->type == cJSON_Object) {
                                    get_json_uint32(airmax_rx, "cinr", &info->cinr);
                                }
			}

			get_json_ipaddr(sta, "lastip", &info->ip);
			get_json_float(sta, "tx", &info->tx_rate);
			get_json_float(sta, "rx", &info->rx_rate);
			get_json_uint32(sta, "uptime", &info->conn_time);
			info->conn_time *= 100;

			cJSON* counters = cJSON_GetObjectItem(sta, "stats");
			if (counters && counters->type == cJSON_Object) {
				get_json_uint64(counters, "tx_bytes", &info->tx_bytes);
				get_json_uint64(counters, "rx_bytes", &info->rx_bytes);
			}
#ifdef PC_BUILD
			print_sta(info);
#endif
		}

		cJSON_Delete(sl_json);
	}
	return 0;
}

void airos_cleanup_stats(void) {
        if (!stats) return;
	free(stats->sta_list.sta);
	free(stats);
	stats = NULL;
}

const airos_stats_t* airos_get_stats(void) {
	sta_info_t* tmp = NULL;
	if (stats == NULL) {
		stats = malloc(sizeof(airos_stats_t));
		atexit(airos_cleanup_stats);
		memset(stats, 0, sizeof(*stats));
	}

	const char* st_buf = get_status_cgi();
	if (!st_buf)
		return NULL;

	cJSON* st_json = cJSON_Parse(st_buf);
	if (!st_json)
		return NULL;

	if (stats->sta_list.sta)
		tmp = stats->sta_list.sta;
	memset(stats, 0, sizeof(*stats));
	if (tmp)
		stats->sta_list.sta = tmp;

	get_radio_stats(st_json, &stats->radio_stats);
	get_airmax_stats(st_json, &stats->airmax_stats);
	get_airsync_stats(st_json, &stats->airsync_stats);
	get_airsel_stats(st_json, &stats->airsel_stats);
	get_wlan_stats(st_json, &stats->wlan_stats);

	cJSON_Delete(st_json);

	attach_stalist(stats);

	return stats;
}

