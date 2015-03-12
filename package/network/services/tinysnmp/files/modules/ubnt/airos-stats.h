#ifndef __AIROS_STATS_H_
#define __AIROS_STATS_H_

#include <stdint.h>
#include <net/if.h>
#include <netinet/in.h>

#ifndef ARRAYSIZE
#define ARRAYSIZE(a) (sizeof((a))/sizeof((a)[0]))
#endif

#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif

#ifndef __MAC2STR
#define __MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#endif

#ifndef __MACSTR
#define __MACSTR "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX"
#endif

typedef struct {
	int32_t rssi[3];
	int32_t rssi_mgmt[3];
	int32_t rssi_ext[3];
} rssi_stats_t;

typedef struct {
	char     ifname[IFNAMSIZ];
	uint32_t mode;
	uint32_t country_code;
	uint32_t frequency;
	uint32_t dfs_status;
	int      txpower;
	uint32_t distance;
	uint32_t chainmask;
	char     antenna[IFNAMSIZ];
	rssi_stats_t rssi_stats;
} radio_stats_t;

typedef struct {
	char     ifname[IFNAMSIZ];
	uint32_t status;
	uint32_t quality;
	uint32_t capacity;
	uint32_t priority;
	uint32_t no_ack;
} airmax_stats_t;

typedef struct {
	char ifname[IFNAMSIZ];
	uint32_t mode;
	uint32_t count;
	uint32_t down_util;
	uint32_t up_util;
} airsync_stats_t;

typedef struct {
	char ifname[IFNAMSIZ];
	uint32_t status;
	uint32_t interval;
} airsel_stats_t;

typedef struct {
	char ifname[IFNAMSIZ];
	char ssid[IFNAMSIZ];
	uint32_t hide_ssid;
	char ap_hwaddr[6];
	int32_t signal;
	uint32_t rssi;
	uint32_t ccq;
	int32_t noise_floor;
	float tx_rate;
	float rx_rate;
	char security[16];
	uint32_t wds_status;
	uint32_t repeater_status;
	uint32_t channel_width;
} wlan_stats_t;

typedef struct {
	char hwaddr[6];
	char name[IFNAMSIZ];
	int32_t signal;
	int32_t noisef;
	uint32_t distance;
	uint32_t ccq;
	uint32_t quality;
	uint32_t capacity;
	uint32_t priority;
	struct in_addr ip;
	float tx_rate;
	float rx_rate;
	uint64_t tx_bytes;
	uint64_t rx_bytes;
	uint32_t conn_time;
	uint32_t cinr;
} sta_info_t;

typedef struct {
	uint32_t count;
	sta_info_t* sta;
} sta_list_t;

typedef struct {
	radio_stats_t   radio_stats;
	airmax_stats_t  airmax_stats;
	airsync_stats_t airsync_stats;
	airsel_stats_t  airsel_stats;
	wlan_stats_t    wlan_stats;
	sta_list_t      sta_list;
} airos_stats_t;

const airos_stats_t* airos_get_stats(void);

#endif

