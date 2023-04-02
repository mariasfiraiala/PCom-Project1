#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int comparator(const void *p, const void *q)
{
	struct route_table_entry route1 = *(struct route_table_entry *)p;
	struct route_table_entry route2 = *(struct route_table_entry *)q;

	if (route1.prefix == route2.prefix)
		return route2.mask - route1.mask;

	return route2.prefix - route1.prefix;
}

struct route_table_entry *dr_get_next_route(uint32_t ip_dest, struct route_table_entry *rtable, uint32_t rtable_len)
{
	qsort(rtable, rtable_len, sizeof(rtable[0]), comparator);

	for (int i = 0; i < rtable_len; ++i)
		if (rtable[i].prefix == (ip_dest & rtable[i].mask))
			return &rtable[i];

	return NULL;
}

struct arp_entry *dr_get_arp_entry(uint32_t given_ip, struct arp_entry *arp_table, uint32_t arp_table_len)
{
	for (int i = 0; i < arp_table_len; ++i)
		if (arp_table[i].ip == given_ip)
			return &arp_table[i];
	return NULL;
}


int dr_ip_packet(struct iphdr *ip_hdr, int interface, struct route_table_entry *rtable, uint32_t rtable_len,
				struct arp_entry *arp_table, uint32_t arp_table_len, size_t len)
{
	char *router_ip_tmp = get_interface_ip(interface);
	struct sockaddr_in router_ip;

	inet_pton(AF_INET, router_ip_tmp, &router_ip);

	printf("After inet_pton()\n");

	if (ip_hdr->daddr != router_ip.sin_addr.s_addr) {
		uint16_t received_checksum = ip_hdr->check;

		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		if (received_checksum != ip_hdr->check) {
			printf("Wrong checksum. Drop package.\n");
			return -1;
		}

		printf("After checksum\n");

		if (ip_hdr->ttl <= 1) {
			printf("TTL <= 1.\n");

			/* TODO: Implement ICMP "Time exceeded" */
			return -1;
		}

		--ip_hdr->ttl;
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)));

		printf("After TTL and checksum\n");

		struct route_table_entry *next_route = dr_get_next_route(ip_hdr->daddr, rtable, rtable_len);

		if (!next_route) {
			printf("Route for destination not found.\n");

			/* TODO: Implement ICMP "Destination unreachable" */
			return -1;
		}

		struct arp_entry *next_arp = dr_get_arp_entry(ip_hdr->daddr, arp_table, arp_table_len);

		struct ether_header *eth_hdr = (struct ether_header *)(ip_hdr - sizeof(*eth_hdr));

		memcpy(eth_hdr->ether_dhost, next_arp->mac, sizeof(next_arp->mac));
		get_interface_mac(next_route->interface, eth_hdr->ether_shost);

		send_to_link(next_route->interface, (char *)eth_hdr, len);
	} else {

	}

	return 0;
}

int dr_arp_packet()
{
	return 0;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry *rtable = malloc(sizeof(*rtable) * MAX_RTABLE_LEN);
	DIE(!rtable, "malloc() failed\n");
	uint32_t rtable_len = read_rtable(argv[1], rtable);

	struct arp_entry *arp_table = malloc (sizeof(*arp_table) * MAX_RTABLE_LEN);
	DIE(!arp_table, "malloc() failed\n");
	uint32_t arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		/* TODO 0: From buf, get the headers.
				   If the packet is too short, drop it. */

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		printf("ether_type: %x\n", ntohs(eth_hdr->ether_type));

		switch (ntohs(eth_hdr->ether_type)) {
		case 0x0800:
			printf("After ether_type()\n");
			dr_ip_packet((struct iphdr *)(buf + sizeof(*eth_hdr)), interface, rtable, rtable_len, arp_table, arp_table_len, len);
			break;
		case 0x0806:
			dr_arp_packet();
			break;
		}

		printf("Doesn't recognize ether_type\n");

		/* TODO 1: Check if packet destination is the router or all the other hosts.
				   If not, drop the packet. */

		/* TODO 2: Check the packet protocol: IPv4 or ARP.
				   If the protocol doesn't fit these 2 options, drop the package. */

		

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link. */
	}
}

