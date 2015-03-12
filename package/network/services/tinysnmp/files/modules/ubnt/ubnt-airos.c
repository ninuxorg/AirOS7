#include <string.h>

#include <debug/log.h>
#include <abz/error.h>

#include <tinysnmp/agent/ifcache.h>

#include "ubnt-airos.h"
#include "airos-stats.h"

const char* const AIROS_MIB_STR = "airOS MIB";

static int update(struct odb **odb, const uint32_t *oid, uint8_t type, const void *data) {
	snmp_value_t value;
	value.type = type;

	switch (type)
	{
		case BER_INTEGER:
			value.data.INTEGER = *(int32_t*) data;
			break;
		case BER_Counter32:
			value.data.Counter32 = *(uint32_t*) data;
			break;
		case BER_Gauge32:
			value.data.Gauge32 = *(uint32_t*) data;
			break;
		case BER_TimeTicks:
			value.data.TimeTicks = *(uint32_t*) data;
			break;
		case BER_Counter64:
			value.data.Counter64 = *(uint64_t*) data;
			break;
		case BER_OID:
			value.data.OID = (uint32_t*) data;
			break;
		case BER_OCTET_STRING:
			value.data.OCTET_STRING = *(octet_string_t *) data;
			break;
		case BER_IpAddress:
			value.data.IpAddress = *(uint32_t*) data;
			break;
		default:
			abz_set_error ("invalid type (0x%02x) specified",type);
			return -1;
	}

	return odb_add(odb, oid, &value);
}

#define set_value(idx, val_type, val) do { \
	table[idx_col] = idx; \
	int rc = update(odb, table, val_type, val); \
	if (rc) return rc; \
} while (0)

static int update_or_table(struct odb **odb, uint32_t index) {
	uint32_t table[] = { 11, 43, 6, 1, 4, 1, 41112, 1, 1, 1, 0, index };
	const uint8_t idx_col = 10;

	set_value(1, BER_INTEGER, &index);

	uint32_t airmax_oid[] = { 8, 43, 6, 1, 4, 1, 41112, 1, 4 };
	set_value(2, BER_OID, airmax_oid);

	octet_string_t str;
	str.len = strlen(AIROS_MIB_STR);
	str.buf = (unsigned char*) AIROS_MIB_STR;
	set_value(3, BER_OCTET_STRING, &str);

	return 0;
}

static int update_radio_stats(struct odb **odb, const airos_stats_t* stats) {
	const radio_stats_t* st = &stats->radio_stats;
	int ifindex = ifcache_get_ifindex(st->ifname);
	log_printf(LOG_VERBOSE, "updating radio statistics of %s (ifindex: %d)\n", st->ifname, ifindex);

	uint32_t table[] = { 12, 43, 6, 1, 4, 1, 41112, 1, 4, 1, 1, 0, 1 };
	const uint8_t idx_col = 11;

	set_value(1, BER_INTEGER, &ifindex);
	set_value(2, BER_INTEGER, &st->mode);
	set_value(3, BER_INTEGER, &st->country_code);
	set_value(4, BER_INTEGER, &st->frequency);
	set_value(5, BER_INTEGER, &st->dfs_status);
	set_value(6, BER_INTEGER, &st->txpower);
	set_value(7, BER_INTEGER, &st->distance);
	set_value(8, BER_INTEGER, &st->chainmask);

	octet_string_t str;
	str.len = strlen(st->antenna);
	str.buf = (unsigned char*) st->antenna;
	set_value(9, BER_OCTET_STRING, &str);

	int i;
	for (i = 0; i < 2; ++i) {
		uint32_t chaintable[] = { 13, 43, 6, 1, 4, 1, 41112, 1, 4, 2, 1, 0, 1, i + 1 };
		uint8_t col = 11;

		chaintable[col] = 1;
		int rc = update(odb, chaintable, BER_INTEGER, &chaintable[13]);

		chaintable[col] = 2;
		rc = update(odb, chaintable, BER_INTEGER, &st->rssi_stats.rssi[i]);

		chaintable[col] = 3;
		rc = update(odb, chaintable, BER_INTEGER, &st->rssi_stats.rssi_mgmt[i]);

		chaintable[col] = 4;
		rc = update(odb, chaintable, BER_INTEGER, &st->rssi_stats.rssi_ext[i]);
	}

	return 0;
}

static int update_airmax_stats(struct odb **odb, const airos_stats_t* stats) {
	const airmax_stats_t* st = &stats->airmax_stats;
	int ifindex = ifcache_get_ifindex(st->ifname);
	log_printf(LOG_VERBOSE, "updating airmax statistics of %s (ifindex: %d)\n", st->ifname, ifindex);

	uint32_t table[] = { 12, 43, 6, 1, 4, 1, 41112, 1, 4, 6, 1, 0, 1 };
	const uint8_t idx_col = 11;

	set_value(1, BER_INTEGER, &ifindex);
	set_value(2, BER_INTEGER, &st->status);
	set_value(3, BER_INTEGER, &st->quality);
	set_value(4, BER_INTEGER, &st->capacity);
	set_value(5, BER_INTEGER, &st->priority);
	set_value(6, BER_INTEGER, &st->no_ack);

	return 0;
}

static int update_airsync_stats(struct odb **odb, const airos_stats_t* stats) {
	const airsync_stats_t* st = &stats->airsync_stats;
	int ifindex = ifcache_get_ifindex(st->ifname);
	log_printf(LOG_VERBOSE, "updating airsync statistics of %s (ifindex: %d)\n", st->ifname, ifindex);

	uint32_t table[] = { 12, 43, 6, 1, 4, 1, 41112, 1, 4, 3, 1, 0, 1 };
	const uint8_t idx_col = 11;

	set_value(1, BER_INTEGER, &ifindex);
	set_value(2, BER_INTEGER, &st->mode);
	set_value(3, BER_INTEGER, &st->count);
	set_value(4, BER_INTEGER, &st->down_util);
	set_value(5, BER_INTEGER, &st->up_util);

	return 0;
}

static int update_airsel_stats(struct odb **odb, const airos_stats_t* stats) {
	const airsel_stats_t* st = &stats->airsel_stats;
	int ifindex = ifcache_get_ifindex(st->ifname);
	log_printf(LOG_VERBOSE, "updating airselect statistics of %s (ifindex: %d)\n", st->ifname, ifindex);

	uint32_t table[] = { 12, 43, 6, 1, 4, 1, 41112, 1, 4, 4, 1, 0, 1 };
	const uint8_t idx_col = 11;

	set_value(1, BER_INTEGER, &ifindex);
	set_value(2, BER_INTEGER, &st->status);
	set_value(3, BER_INTEGER, &st->interval);

	return 0;
}

static int update_wlan_stats(struct odb **odb, const airos_stats_t* stats) {
	const wlan_stats_t* st = &stats->wlan_stats;
	int ifindex = ifcache_get_ifindex(st->ifname);
	log_printf(LOG_VERBOSE, "updating wlan statistics of %s (ifindex: %d)\n", st->ifname, ifindex);

	uint32_t table[] = { 12, 43, 6, 1, 4, 1, 41112, 1, 4, 5, 1, 0, 1 };
	const uint8_t idx_col = 11;

	set_value(1, BER_INTEGER, &ifindex);

	octet_string_t str;
	str.len = strlen(st->ssid);
	str.buf = (unsigned char*) st->ssid;
	set_value(2, BER_OCTET_STRING, &str);

	set_value(3, BER_INTEGER, &st->hide_ssid);

	str.len = sizeof(st->ap_hwaddr);
	str.buf = (uint8_t*) st->ap_hwaddr;
	set_value(4, BER_OCTET_STRING, &str);

	set_value(5, BER_INTEGER, &st->signal);
	set_value(6, BER_INTEGER, &st->rssi);
	set_value(7, BER_INTEGER, &st->ccq);
	set_value(8, BER_INTEGER, &st->noise_floor);

	int rate = st->tx_rate * 1000;
	set_value(9, BER_INTEGER, &rate);
	rate = st->rx_rate * 1000;
	set_value(10, BER_INTEGER, &rate);

	str.len = strlen(st->security);
	str.buf = (unsigned char*) st->security;
	set_value(11, BER_OCTET_STRING, &str);

	set_value(12, BER_INTEGER, &st->wds_status);
	set_value(13, BER_INTEGER, &st->repeater_status);
	set_value(14, BER_INTEGER, &st->channel_width);
	set_value(15, BER_Gauge32, &stats->sta_list.count);

	return 0;
}

static int update_stalist_stats(struct odb **odb, const airos_stats_t* stats) {
	const wlan_stats_t* st = &stats->wlan_stats;
	int ifindex = ifcache_get_ifindex(st->ifname);
	log_printf(LOG_VERBOSE, "updating stalist of %s (ifindex: %d)\n", st->ifname, ifindex);

        uint32_t table[] = { 18, 43, 6, 1, 4, 1, 41112, 1, 4, 7, 1, 1, 1, 0, 0, 0, 0, 0, 0 };
	const uint8_t idx_col = 11;

	int i;
	for (i = 0; i < stats->sta_list.count; ++i) {
		sta_info_t* sta = &stats->sta_list.sta[i];

                octet_string_t str;

		str.len = sizeof(sta->hwaddr);
		str.buf = (uint8_t*) sta->hwaddr;
                table[13] = str.buf[0];
		table[14] = str.buf[1];
		table[15] = str.buf[2];
		table[16] = str.buf[3];
		table[17] = str.buf[4];
		table[18] = str.buf[5];
		set_value(1, BER_OCTET_STRING, &str);

		str.len = sizeof(sta->name);
		str.buf = (uint8_t*) sta->name;
		set_value(2, BER_OCTET_STRING, &str);


		set_value(3, BER_INTEGER, &sta->signal);
		set_value(4, BER_INTEGER, &sta->noisef);
		set_value(5, BER_INTEGER, &sta->distance);
		set_value(6, BER_INTEGER, &sta->ccq);
		set_value(7, BER_INTEGER, &sta->priority);
		set_value(8, BER_INTEGER, &sta->quality);
		set_value(9, BER_INTEGER, &sta->capacity);
		set_value(10, BER_IpAddress, &sta->ip.s_addr);

		int rate = sta->tx_rate * 1000;
		set_value(11, BER_INTEGER, &rate);
		rate = sta->rx_rate * 1000;
		set_value(12, BER_INTEGER, &rate);

		set_value(13, BER_Counter64, &sta->tx_bytes);
		set_value(14, BER_Counter64, &sta->rx_bytes);
		set_value(15, BER_TimeTicks, &sta->conn_time);

		set_value(16, BER_INTEGER, &sta->cinr);
	}


	return 0;
}

static int update_airos_stats(struct odb **odb) {
	const airos_stats_t* stats = airos_get_stats();
	if (!stats) return -1;

	int rc = update_radio_stats(odb, stats);
	if (rc) return rc;

	rc = update_airmax_stats(odb, stats);
	if (rc) return rc;

	rc = update_airsync_stats(odb, stats);
	if (rc) return rc;

	rc = update_airsel_stats(odb, stats);
	if (rc) return rc;

	rc = update_wlan_stats(odb, stats);
	if (rc) return rc;

	rc = update_stalist_stats(odb, stats);
	return rc;
}

int update_airos_table(struct odb **odb, uint32_t index) {
	int rc = update_or_table(odb, index);
	if (rc) return rc;

	rc = update_airos_stats(odb);
	return rc;
}

