//
// Created by Andrew Alston on 10/12/2021.
//

#ifndef CSID_SIM_CONSTS_H
#define CSID_SIM_CONSTS_H
#endif //CSID_SIM_CONSTS_H


#define PAYLOAD_SIZE 64
#define USID_TYPE 2
#define GSID_TYPE 3

__u8 src_mac[6] = { 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF };
__u8 dst_mac[6] = { 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6 };

typedef void*(*sid_behavior)(void *pkt, __u8 loc_size, __u8 sid_size);

#define ETH_SIZE sizeof(struct ethhdr)
#define IPV6_SIZE sizeof(struct ip6_hdr)

struct seg_list {
    struct in6_addr segment;
    struct seg_list *next;
    struct seg_list *prev;
    __u8 seg_type;
    __u8 seg_length;
    void *f_ptr;
};


struct segments {
    struct in6_addr segment;
    int num_segments;
    int segment_length; // Combined bit length of all sids
    int segment_count;
    struct seg_list *head;
    struct seg_list *tail;
};

struct __attribute__((__packed__))inner_ipv6_packet {
    struct ip6_hdr ip6;
    struct udphdr udp;
    __u8 payload[PAYLOAD_SIZE];
};

struct arguments {
    struct in6_addr src;
    struct in6_addr dst;
    struct in6_addr locator;
    struct segments segs;
};

void *process_usid(void *pkt, __u8 loc_size, __u8 sid_size);
