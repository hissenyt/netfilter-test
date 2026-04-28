#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <strings.h>
#include <unistd.h>
#include <cerrno>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "iphdr.h"
#include "tcphdr.h"

static char* block_host;

static int is_http_method(const char* data, int len) {
	if (len >= 4 && memcmp(data, "GET ", 4) == 0) return 1;
	if (len >= 5 && memcmp(data, "POST ", 5) == 0) return 1;
	if (len >= 5 && memcmp(data, "HEAD ", 5) == 0) return 1;
	if (len >= 4 && memcmp(data, "PUT ", 4) == 0) return 1;
	if (len >= 7 && memcmp(data, "DELETE ", 7) == 0) return 1;
	if (len >= 8 && memcmp(data, "OPTIONS ", 8) == 0) return 1;
	if (len >= 6 && memcmp(data, "PATCH ", 6) == 0) return 1;
	return 0;
}

static int same_host(char* p, int len) {
	while (len > 0 && (*p == ' ' || *p == '\t')) {
		p++;
		len--;
	}

	while (len > 0) {
		char c = p[len - 1];
		if (c == '\r' || c == '\n' || c == ' ' || c == '\t') len--;
		else break;
	}

	int host_len = strlen(block_host);

	if (len == host_len && strncasecmp(p, block_host, host_len) == 0) return 1;
	if (len > host_len && strncasecmp(p, block_host, host_len) == 0 && p[host_len] == ':') return 1;

	return 0;
}

static int find_host(char* data, int len) {
	char* p = data;
	char* end = data + len;

	while (p < end) {
		char* line_end = (char*)memchr(p, '\n', end - p);
		if (line_end == NULL) line_end = end;

		int line_len = line_end - p;

		if (line_len >= 5 && strncasecmp(p, "Host:", 5) == 0) {
			if (same_host(p + 5, line_len - 5)) return 1;
		}

		if (line_end == end) break;
		p = line_end + 1;
	}

	return 0;
}

static int check_packet(unsigned char* packet, int len) {
	if (len < (int)sizeof(iphdr_t)) return 0;

	iphdr_t* ip = (iphdr_t*)packet;

	int ip_header_len = (ip->ver_ihl & 0x0F) * 4;
	if ((ip->ver_ihl >> 4) != 4) return 0;
	if (ip->protocol != IPPROTO_TCP) return 0;
	if (ip_header_len < 20) return 0;

	int total_len = ntohs(ip->total_len);
	if (total_len > len) total_len = len;
	if (total_len < ip_header_len + (int)sizeof(tcphdr_t)) return 0;

	tcphdr_t* tcp = (tcphdr_t*)(packet + ip_header_len);

	int tcp_header_len = ((ntohs(tcp->off_flags) >> 12) & 0x0F) * 4;
	if (tcp_header_len < 20) return 0;

	int data_offset = ip_header_len + tcp_header_len;
	if (total_len <= data_offset) return 0;

	char* data = (char*)(packet + data_offset);
	int data_len = total_len - data_offset;

	if (!is_http_method(data, data_len)) return 0;

	return find_host(data, data_len);
}

static unsigned int get_id(struct nfq_data* tb) {
	struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(tb);
	if (ph == NULL) return 0;
	return ntohl(ph->packet_id);
}

static int cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa, void* data) {
	unsigned int id = get_id(nfa);
	unsigned char* packet;
	int len = nfq_get_payload(nfa, &packet);

	if (len >= 0 && check_packet(packet, len)) {
		printf("drop %s\n", block_host);
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		printf("syntax : %s <host>\n", argv[0]);
		printf("sample : %s test.gilgil.net\n", argv[0]);
		return 1;
	}

	block_host = argv[1];

	struct nfq_handle* h = nfq_open();
	if (h == NULL) {
		fprintf(stderr, "nfq_open failed\n");
		return 1;
	}

	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "nfq_unbind_pf failed\n");
		nfq_close(h);
		return 1;
	}

	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "nfq_bind_pf failed\n");
		nfq_close(h);
		return 1;
	}

	struct nfq_q_handle* qh = nfq_create_queue(h, 0, &cb, NULL);
	if (qh == NULL) {
		fprintf(stderr, "nfq_create_queue failed\n");
		nfq_close(h);
		return 1;
	}

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "nfq_set_mode failed\n");
		nfq_destroy_queue(qh);
		nfq_close(h);
		return 1;
	}

	printf("blocked host : %s\n", block_host);

	int fd = nfq_fd(h);
	char buf[4096] __attribute__((aligned));

	while (1) {
		int rv = recv(fd, buf, sizeof(buf), 0);

		if (rv >= 0) {
			nfq_handle_packet(h, buf, rv);
			continue;
		}

		if (errno == ENOBUFS) continue;

		perror("recv");
		break;
	}

	nfq_destroy_queue(qh);
	nfq_close(h);

	return 0;
}
