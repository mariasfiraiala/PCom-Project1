Copyright 2023 Maria Sfiraiala (maria.sfiraiala@stud.acs.upb.ro)

# Dataplane Router - Project1

## Description

The project aims to implement a simple router that provides the following functionalities:

1. Sending 3 types of ICMP responses:

   1. "Destination Unreachable"
 
   1. "Time Exceeded"

   1. "Echo request" &rarr; "Echo reply"

   The first 2 are implemented using the same API, `dr_icmp_packet()` which constructs the future ICMP packet based off the type sent in the calling function.

   The "Echo request" &rarr; "Echo reply" is implemented inside the `dr_ip_packet()` when checking the destination; if the destination of the packet is the router itself, then we send an ICMP "Echo reply".

1. Targeting ARP packets for both requests and replies, written in the same function, `dr_arp_packet()`:

   1. For requests we send the MAC of the final destination back to the source.

   1. For replies we add the newly found MAC address in the ARP table and we release the packets that are waiting on this addres from the queue.

   We implemented this queue in the form of a doubly linked list (`list.h`), with its nodes containing information using this structure, making it easier to get the packets sent:

   ```C
   struct waiting_queue_entry {
        char *eth_hdr;
        int len;
        struct route_table_entry *next_route;
   };
   ```

1. Leveraging IPv4 packets following this flow:

   1. Recomputing the checksum.

   1. Checking the TTL.

   1. Getting the next best route, using the LPM aproach via a quick sort of the routing table right after it gets parsed and a binary search.

   1. Inserting a packet in the waiting queue when its MAC address isn't found in the router cache and sending an ARP request for it.

## Observations Regarding the Project

I really enjoyed working with Wireshark even though I have a weird bug when sending packets between routers.
To this very day I haven't found the real culprit, but it's fine, life moves on.

<p style="text-align: center">

     ."".    ."",
     |  |   /  /
     |  |  /  /
     |  | /  /
     |  |/  ;-._
     }  ` _/  / ;
     |  /` ) /  /
     | /  /_/\_/\
     |/  /      |
     (  ' \ '-  |
      \    `.  /
       |      |
       |      |
</p>
