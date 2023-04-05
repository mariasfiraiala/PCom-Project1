#include "list.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct route_table_entry *rtable;
uint32_t rtable_len;

struct arp_entry *arp_table;
uint32_t arp_table_len;

doubly_linked_list_t *waiting_queue;

struct route_table_entry *dr_get_next_route(uint32_t ip_dest)
{
	struct route_table_entry *next_hop = NULL;
	uint32_t max_mask = 0;
	for (int i = 0; i < rtable_len; ++i) {
		if ((ip_dest & rtable[i].mask) == rtable[i].prefix) {

			if (rtable[i].mask > max_mask) {
				max_mask = rtable[i].mask;
				next_hop = &rtable[i];
			}
		}
	}

	return next_hop;
}

struct arp_entry *dr_get_arp_entry(uint32_t given_ip)
{
	for (int i = 0; i < arp_table_len; ++i)
		if (arp_table[i].ip == given_ip)
			return &arp_table[i];

	return NULL;
}

void dr_send_arp_request(struct ether_header *eth_hdr, struct route_table_entry *next_route, int interface)
{
	struct arp_header *arp_hdr = (struct arp_header *)((char *)eth_hdr + sizeof(*eth_hdr));

	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(0x0800);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);

	get_interface_mac(next_route->interface, arp_hdr->sha);

	char *router_ip_tmp = get_interface_ip(interface);
	int router_ip;

	inet_pton(AF_INET, router_ip_tmp, &router_ip);

	arp_hdr->spa = router_ip;

	memset(arp_hdr->tha, 0, sizeof(arp_hdr->tha));
	arp_hdr->tpa = next_route->next_hop;

	memset(eth_hdr->ether_dhost, 0xff, sizeof(eth_hdr->ether_dhost));
	eth_hdr->ether_type = htons(0x0806);

	send_to_link(next_route->interface, (char *)eth_hdr, sizeof(*eth_hdr) + sizeof(*arp_hdr));
}

int dr_icmp_packet(struct ether_header *eth_hdr, uint8_t type, int interface)
{
	struct iphdr *ip_hdr = (struct iphdr *)((char *)eth_hdr + sizeof(*eth_hdr));
	struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + sizeof(*ip_hdr));

	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(*icmp_hdr)));

	int8_t *icmp_body = malloc(sizeof(struct iphdr) + 8);
	memcpy(icmp_body, ip_hdr, sizeof(struct iphdr) + 8);

	char *router_ip_tmp = get_interface_ip(interface);
	int router_ip;

	inet_pton(AF_INET, router_ip_tmp, &router_ip);

	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = router_ip;
	ip_hdr->ttl = 64;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(sizeof(struct icmphdr) + 2 * sizeof(struct iphdr) + 8);
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)));

	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
	get_interface_mac(interface, eth_hdr->ether_shost);

	memcpy((char *)icmp_hdr + sizeof(*icmp_hdr), icmp_body, sizeof(struct iphdr) + 8);

	send_to_link(interface, (char *)eth_hdr, sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*icmp_hdr) + sizeof(struct iphdr) + 8);
	free(icmp_body);

	return 0;
}

int dr_ip_packet(struct iphdr *ip_hdr, int interface, size_t len)
{
	char *router_ip_tmp = get_interface_ip(interface);
	int router_ip;

	inet_pton(AF_INET, router_ip_tmp, &router_ip);

	if (ip_hdr->daddr != router_ip) {
		uint16_t received_checksum = ip_hdr->check;

		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		if (received_checksum != ip_hdr->check) {
			printf("Wrong checksum. Drop package.\n");
			return -1;
		}

		if (ip_hdr->ttl <= 1) {
			printf("TTL <= 1.\n");

			/* TODO: Implement ICMP "Time exceeded" */
			dr_icmp_packet((struct ether_header *)((char *)ip_hdr - sizeof(struct ether_header)), 11, interface);
			return -1;
		}

		--ip_hdr->ttl;
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)));

		struct route_table_entry *next_route = dr_get_next_route(ip_hdr->daddr);

		if (!next_route) {
			printf("Route for destination not found.\n");

			/* TODO: Implement ICMP "Destination unreachable" */
			dr_icmp_packet((struct ether_header *)((char *)ip_hdr - sizeof(struct ether_header)), 3, interface);
			return -1;
		}

		struct arp_entry *next_arp = dr_get_arp_entry(next_route->next_hop);
		struct ether_header *eth_hdr = (struct ether_header *)((char *)ip_hdr - sizeof(*eth_hdr));

		get_interface_mac(next_route->interface, eth_hdr->ether_shost);

		if (!next_arp) {

			/* Insert packet in queue, send ARP request for it */

			struct waiting_queue_entry *entry = malloc(sizeof(*entry));
			entry->eth_hdr = malloc(len);
			memcpy(entry->eth_hdr, eth_hdr, len);
			entry->len = len;
			entry->next_route = next_route;
			dll_add_nth_node(waiting_queue, waiting_queue->size, entry, sizeof(*entry));

			dr_send_arp_request(eth_hdr, next_route, interface);

			return 1;
		}

		memcpy(eth_hdr->ether_dhost, next_arp->mac, sizeof(next_arp->mac));

		send_to_link(next_route->interface, (char *)eth_hdr, len);
	} else {

	}

	return 0;
}

int dr_arp_packet(struct arp_header *arp_hdr, int interface, int len)
{
	if (ntohs(arp_hdr->op) == 1) {
		char *router_ip_tmp = get_interface_ip(interface);
		int router_ip;

		inet_pton(AF_INET, router_ip_tmp, &router_ip);

		if (arp_hdr->tpa != router_ip)
			return -1;

		arp_hdr->op = htons(2);

		arp_hdr->tpa = arp_hdr->spa;
		arp_hdr->spa = router_ip;

		memcpy(arp_hdr->tha, arp_hdr->sha, sizeof(arp_hdr->sha));
		get_interface_mac(interface, arp_hdr->sha);

		struct ether_header *eth_hdr = (struct ether_header *)((char *)arp_hdr - sizeof(*eth_hdr));
		memcpy(eth_hdr->ether_dhost, arp_hdr->tha, sizeof(arp_hdr->tha));
		get_interface_mac(interface, eth_hdr->ether_shost);

		send_to_link(interface, (char *)eth_hdr, len);
	} else {
		arp_table[arp_table_len].ip = arp_hdr->spa;
		memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, sizeof(arp_hdr->sha));
		++arp_table_len;

		dll_node_t *node = waiting_queue->head;
		int i = 0;
		while (node) {
			struct waiting_queue_entry *entry = (struct waiting_queue_entry *)node->data;
			if (entry->next_route->next_hop == arp_hdr->spa) {
				memcpy(((struct ether_header *)entry->eth_hdr)->ether_dhost, arp_hdr->sha, sizeof(arp_hdr->sha));

				send_to_link(entry->next_route->interface, (char *)entry->eth_hdr, entry->len);
				dll_remove_nth_node(waiting_queue, i);
				--i;
			}
			++i;
			node = node->next;
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(*rtable) * MAX_RTABLE_LEN);
	DIE(!rtable, "malloc() failed\n");
	rtable_len = read_rtable(argv[1], rtable);

	arp_table = malloc (sizeof(*arp_table) * MAX_ARP_TABLE_LEN);
	DIE(!arp_table, "malloc() failed\n");

	waiting_queue = dll_create(sizeof(struct waiting_queue_entry));

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		switch (ntohs(eth_hdr->ether_type)) {
		case 0x0800:
			dr_ip_packet((struct iphdr *)(buf + sizeof(*eth_hdr)), interface, len);
			break;
		case 0x0806:
			dr_arp_packet((struct arp_header *)(buf + sizeof(*eth_hdr)), interface, len);
			break;
		}
	}

	free(rtable);
	free(arp_table);
	dll_free(&waiting_queue);

	return 0;
}

