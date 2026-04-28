#pragma once

#include <cstdint>

#pragma pack(push, 1)
struct iphdr_t {
	uint8_t ver_ihl;
	uint8_t tos;
	uint16_t total_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t src_ip;
	uint32_t dst_ip;
};
#pragma pack(pop)
