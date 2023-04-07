#include "list.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static struct route_table_entry *rtable;
static uint32_t rtable_len;

static struct arp_entry *arp_table;
static uint32_t arp_table_len;

static doubly_linked_list_t *waiting_queue;

static inline uint32_t dr_get_ip_from_char(char *char_ip)
{
	uint32_t int_ip;

	inet_pton(AF_INET, char_ip, &int_ip);
	return int_ip;
}

static inline int32_t dr_comparator(const void *p, const void *q)
{
	struct route_table_entry route1 = *(struct route_table_entry *)p;
	struct route_table_entry route2 = *(struct route_table_entry *)q;

	if (ntohl(route1.prefix) > ntohl(route2.prefix))
		return 1;

	if (ntohl(route1.prefix) == ntohl(route2.prefix))
		if (ntohl(route1.mask) > ntohl(route2.mask))
			return 1;

	return -1;
}

static struct route_table_entry *dr_get_next_route(uint32_t ip_dest)
{
	int l = 0;
	int r = rtable_len - 1;
	struct route_table_entry *next_hop = NULL;

	while (l <= r) {
		int m = l + (r - l) / 2;

		if ((ip_dest & rtable[m].mask) == rtable[m].prefix && !next_hop)
			next_hop = &rtable[m];

		if ((ip_dest & rtable[m].mask) == rtable[m].prefix && next_hop)
			if (ntohl(rtable[m].mask) > ntohl(next_hop->mask))
				next_hop = &rtable[m];

		if (ntohl(rtable[m].prefix) <= ntohl(ip_dest))
			l = m + 1;
		else
			r = m - 1;
	}
	return next_hop;
}

static struct arp_entry *dr_get_arp_entry(uint32_t given_ip)
{
	for (int i = 0; i < arp_table_len; ++i)
		if (arp_table[i].ip == given_ip)
			return &arp_table[i];

	return NULL;
}

static void dr_send_arp_request(struct ether_header *eth_hdr,
								struct route_table_entry *next_route,
								uint32_t interface)
{
	struct arp_header *arp_hdr = (struct arp_header *)((char *)eth_hdr +
								 sizeof(*eth_hdr));

	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(0x0800);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);
	get_interface_mac(next_route->interface, arp_hdr->sha);

	uint32_t router_ip = dr_get_ip_from_char(get_interface_ip(interface));
	arp_hdr->spa = router_ip;

	memset(arp_hdr->tha, 0, sizeof(arp_hdr->tha));
	arp_hdr->tpa = next_route->next_hop;

	memset(eth_hdr->ether_dhost, 0xff, sizeof(eth_hdr->ether_dhost));
	eth_hdr->ether_type = htons(0x0806);

	send_to_link(next_route->interface, (char *)eth_hdr, sizeof(*eth_hdr) +
				sizeof(*arp_hdr));
}

static void dr_icmp_packet(struct ether_header *eth_hdr,
						   uint8_t type,
						   uint32_t interface)
{
	struct iphdr *ip_hdr = (struct iphdr *)((char *)eth_hdr +
						   sizeof(*eth_hdr));
	struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr +
							   sizeof(*ip_hdr));

	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr,
							  sizeof(*icmp_hdr)));

	uint32_t icmp_len = sizeof(struct iphdr) + 8; 
	int8_t *icmp_body = malloc(icmp_len);
	memcpy(icmp_body, ip_hdr, icmp_len);

	uint32_t router_ip = dr_get_ip_from_char(get_interface_ip(interface));

	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = router_ip;
	ip_hdr->ttl = htons(MAX_TTL);
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(sizeof(*icmp_hdr) + sizeof(*ip_hdr) + icmp_len);
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)));

	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost,
		  sizeof(eth_hdr->ether_shost));
	get_interface_mac(interface, eth_hdr->ether_shost);

	memcpy((char *)icmp_hdr + sizeof(*icmp_hdr), icmp_body, icmp_len);

	send_to_link(interface, (char *)eth_hdr, sizeof(*eth_hdr) +
											 sizeof(*ip_hdr) +
											 sizeof(*icmp_hdr) +
											 icmp_len);
	free(icmp_body);
}

static void dr_ip_packet(struct ether_header *eth_hdr,
						 uint32_t interface,
						 uint32_t len)
{
	struct iphdr *ip_hdr = (struct iphdr *)((char *)eth_hdr +
						   sizeof(*eth_hdr));
	uint32_t router_ip = dr_get_ip_from_char(get_interface_ip(interface));

	if (ip_hdr->daddr != router_ip) {
		uint16_t received_checksum = ip_hdr->check;

		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)));

		if (received_checksum != ip_hdr->check) {
			printf("Wrong checksum. Drop package.\n");
			return;
		}

		if (ip_hdr->ttl <= 1) {
			printf("TTL <= 1.\n");

			/* Implement ICMP "Time exceeded" */
			dr_icmp_packet(eth_hdr, 11, interface);
			return;
		}

		--ip_hdr->ttl;
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)));

		struct route_table_entry *next_route = dr_get_next_route(ip_hdr->daddr);

		if (!next_route) {
			printf("Route for destination not found.\n");

			/* Implement ICMP "Destination unreachable" */
			dr_icmp_packet(eth_hdr, 3, interface);
			return;
		}

		struct arp_entry *next_arp = dr_get_arp_entry(next_route->next_hop);

		get_interface_mac(next_route->interface, eth_hdr->ether_shost);

		if (!next_arp) {

			/* Insert packet in queue, send ARP request for it */

			struct waiting_queue_entry *entry = malloc(sizeof(*entry));
			entry->eth_hdr = malloc(len);
			memcpy(entry->eth_hdr, eth_hdr, len);
			entry->len = len;
			entry->next_route = next_route;
			dll_add_nth_node(waiting_queue, waiting_queue->size, entry,
							sizeof(*entry));

			dr_send_arp_request(eth_hdr, next_route, interface);
			return;
		}

		memcpy(eth_hdr->ether_dhost, next_arp->mac, sizeof(next_arp->mac));

		send_to_link(next_route->interface, (char *)eth_hdr, len);
	} else {
		struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr +
								   sizeof(*ip_hdr));

		icmp_hdr->type = 0;
		icmp_hdr->code = 0;
		icmp_hdr->checksum = 0;
		icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr,
										   sizeof(*icmp_hdr)));

		uint32_t icmp_len = ntohs(ip_hdr->tot_len) -
							sizeof(*ip_hdr) -
							sizeof(*icmp_hdr);

		int8_t *icmp_body = malloc(icmp_len);
		memcpy(icmp_body, ip_hdr, icmp_len);

		ip_hdr->daddr = ip_hdr->saddr;
		ip_hdr->saddr = router_ip;
		ip_hdr->ttl = htons(MAX_TTL);
		ip_hdr->protocol = IPPROTO_ICMP;
		ip_hdr->tot_len = htons((uint16_t)icmp_len +
						  sizeof(*icmp_hdr) +
						  sizeof(*ip_hdr));
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)));

		memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost,
			  sizeof(eth_hdr->ether_shost));
		get_interface_mac(interface, eth_hdr->ether_shost);

		memcpy((char *)icmp_hdr + sizeof(*icmp_hdr), icmp_body, icmp_len);

		send_to_link(interface, (char *)eth_hdr, sizeof(*eth_hdr) +
												 sizeof(*ip_hdr) +
												 sizeof(*icmp_hdr) +
												 icmp_len);
		free(icmp_body);
	}
}

static void dr_arp_packet(struct ether_header *eth_hdr,
						  uint32_t interface,
						  uint32_t len)
{
	struct arp_header *arp_hdr = (struct arp_header *)((char *)eth_hdr +
								 sizeof(*eth_hdr));

	if (ntohs(arp_hdr->op) == 1) {
		uint32_t router_ip = dr_get_ip_from_char(get_interface_ip(interface));

		if (arp_hdr->tpa != router_ip)
			return;

		arp_hdr->op = htons(2);

		arp_hdr->tpa = arp_hdr->spa;
		arp_hdr->spa = router_ip;

		memcpy(arp_hdr->tha, arp_hdr->sha, sizeof(arp_hdr->sha));
		get_interface_mac(interface, arp_hdr->sha);

		memcpy(eth_hdr->ether_dhost, arp_hdr->tha, sizeof(arp_hdr->tha));
		get_interface_mac(interface, eth_hdr->ether_shost);

		send_to_link(interface, (char *)eth_hdr, len);
	} else {
		arp_table[arp_table_len].ip = arp_hdr->spa;
		memcpy(arp_table[arp_table_len].mac, arp_hdr->sha,
			  sizeof(arp_hdr->sha));
		++arp_table_len;

		dll_node_t *node = waiting_queue->head;
		uint32_t i = 0;

		while (node) {
			struct waiting_queue_entry *entry = (struct waiting_queue_entry *)node->data;
			struct ether_header *entry_eth_hdr = (struct ether_header *)entry->eth_hdr;

			if (entry->next_route->next_hop == arp_hdr->spa) {
				memcpy(entry_eth_hdr->ether_dhost, arp_hdr->sha,
					  sizeof(arp_hdr->sha));

				send_to_link(entry->next_route->interface,
							(char *)entry_eth_hdr, entry->len);
				dll_remove_nth_node(waiting_queue, i);
				--i;
			}
			++i;
			node = node->next;
		}
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(*rtable) * MAX_RTABLE_LEN);
	DIE(!rtable, "malloc() failed\n");
	rtable_len = read_rtable(argv[1], rtable);

	qsort(rtable, rtable_len, sizeof(rtable[0]), dr_comparator);

	arp_table = malloc (sizeof(*arp_table) * MAX_ARP_TABLE_LEN);
	DIE(!arp_table, "malloc() failed\n");

	waiting_queue = dll_create(sizeof(struct waiting_queue_entry));

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;

		switch (ntohs(eth_hdr->ether_type)) {
		case IP_ETHERTYPE:
			dr_ip_packet(eth_hdr, interface, len);
			break;
		case ARP_ETHERTYPE:
			dr_arp_packet(eth_hdr, interface, len);
			break;
		}
	}

	free(rtable);
	free(arp_table);
	dll_free(&waiting_queue);

	return 0;
}
