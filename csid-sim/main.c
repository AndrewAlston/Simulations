// CSID Simulation code

#include <getopt.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <immintrin.h>
#include "helpers.h"
#include "consts.h"

// Global in case we wanna dump hex of each packet as we go
static int dump_hex = 0;

// Random helper function just to fill in some defaults
void *fill_srh(__u8 *buffer) {
    struct ipv6_sr_hdr *srh = (void *) buffer;
    srh->nexthdr = 43;
    srh->type = 4;
    srh->flags = 0;
    return srh;
}

// Generate a random ipv6 packet
void *gen_ipv6_pkt(struct arguments *args, void *srh, int srh_len, int *packet_len) {
    struct ip6_hdr *outer;
    struct inner_ipv6_packet *inner;
    void *srh_seglist;
    struct ethhdr *eth;
    __u8 *packet = calloc(1, ETH_SIZE + IPV6_SIZE + sizeof(struct inner_ipv6_packet) + srh_len);
    eth = (void *) packet;
    outer = (struct ip6_hdr *) (packet + ETH_SIZE);
    srh_seglist = packet + ETH_SIZE + IPV6_SIZE;
    inner = (struct inner_ipv6_packet *) (packet + ETH_SIZE + IPV6_SIZE + srh_len);
    memcpy(srh_seglist, srh, srh_len);
    memcpy(&eth->h_source, &src_mac, 6);
    memcpy(&eth->h_dest, &dst_mac, 6);
    eth->h_proto = htons(0x86DD);
    memcpy(&outer->ip6_src, &args->src, 16);
    memcpy(&outer->ip6_dst, srh + (srh_len - 16), 16);
    outer->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(6 << 28);
    outer->ip6_ctlun.ip6_un1.ip6_un1_nxt = 43;
    outer->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(
            IPV6_SIZE + srh_len + sizeof(struct udphdr) + PAYLOAD_SIZE);
    inner->ip6.ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(6 << 28);
    inner->ip6.ip6_ctlun.ip6_un1.ip6_un1_nxt = 17;
    inner->ip6.ip6_ctlun.ip6_un1.ip6_un1_plen = htons(sizeof(struct udphdr) + PAYLOAD_SIZE);
    memset(inner->payload, 0xAA, 64);
    memcpy(&inner->ip6.ip6_src, &args->src, 16);
    memcpy(&inner->ip6.ip6_dst, &args->dst, 16);
    inner->udp.len = htons(sizeof(struct udphdr) + PAYLOAD_SIZE);
    inner->udp.dest = htons(12345);
    inner->udp.source = htons(54321);
    inner->udp.check = 0;
    inner->udp.check = calc_checksum(&inner->udp, inner->payload, PAYLOAD_SIZE);
    *packet_len = (int)(sizeof(*inner) + ETH_SIZE + IPV6_SIZE + srh_len);
    return packet;
}

void free_segment_tail(struct segments *seg) {
    if (seg->tail == seg->head && seg->tail != NULL) {
        free(seg->tail);
        seg->tail = seg->head = NULL;
        return;
    } else if (seg->tail != NULL) {
        seg->tail = seg->tail->prev;
        free(seg->tail->next);
        seg->tail->next = NULL;
        return;
    } else
        return;
}

void parse_segment_argument(struct segments *seg, char *seg_opt) {
    __u8 arg_count;
    __u8 segment_count = 0;
    char *segment_args[16] = {0};
    char *args[3] = {NULL, NULL, NULL};
    const char segment_delim[2] = ",";
    const char delim[2] = "_";
    char *opt = calloc(strlen(seg_opt) + 1, 1);
    memcpy(opt, seg_opt, strlen(seg_opt) + 1);
    char *ptr;
    segment_args[segment_count] = strtok(opt, segment_delim);
    while (segment_args[segment_count] != NULL) {
        segment_count++;
        segment_args[segment_count] = strtok(NULL, segment_delim);
        if (segment_count == 15)
            break;
    }
    for (int segment = 0; segment < segment_count; segment++) {
        arg_count = 0;
        args[arg_count] = strtok(segment_args[segment], delim);
        while (args[arg_count] != NULL) {
            arg_count++;
            args[arg_count] = strtok(NULL, delim);
            if (arg_count == 3) {
                break;
            }
        }
        if (arg_count > 0 && arg_count < 4) {
            if (seg->num_segments == 0 && seg->head == NULL)
                seg->head = seg->tail = calloc(1, sizeof(struct seg_list));
            else {
                seg->tail->next = calloc(1, sizeof(struct seg_list));
                seg->tail->next->prev = seg->tail;
                seg->tail = seg->tail->next;
            }
            seg->tail->seg_length = (__u8) strtol(args[0], &ptr, 10);
            if (seg->tail->seg_length != 16 && seg->tail->seg_length != 32) {
                printf("Invalid segment length, must be either 16 or 32");
                free_segment_tail(seg);
                free(opt);
                return;
            }
            seg->segment_length += seg->tail->seg_length;
            seg->segment_count++;
        }
        for (int i = 1; i < arg_count; i++) {
            switch (i) {
                case 1:
                    if (seg->tail->seg_length == 16) {
                        seg->tail->segment.__in6_u.__u6_addr16[0] = htons((__u16) strtol(args[i], &ptr, 16));
                    } else if (seg->tail->seg_length == 32) {
                        seg->tail->segment.__in6_u.__u6_addr32[0] = htonl((__u32) strtol(args[i], &ptr, 16));
                    }
                    arg_count++;
                    break;
                case 2:
                    seg->tail->seg_type = (__u8) strtol(args[i], &ptr, 10);
                    if (seg->tail->seg_type != USID_TYPE && seg->tail->seg_type != GSID_TYPE) {
                        printf("Invalid segment type %d, expected 2 [USID_TYPE] or 3 [GSID_TYPE]\n",
                               seg->tail->seg_type);
                        free_segment_tail(seg);
                        free(opt);
                        return;
                    }
                default:
                    break;
            }
        }
    }
    free(opt);
}

struct arguments *parse_args(int argc, char **argv) {
    printf("Running argument parser...\n");
    static struct option long_opts[] = {
            {"hex", no_argument, &dump_hex, 1},
            {"src",     required_argument, 0, 's'},
            {"dst",     required_argument, 0, 'd'},
            {"loc",     required_argument, 0, 'l'},
            {"segment", required_argument, 0, 'n'},
            {0, 0,                         0, 0}
    };
    int VALIDATE_SRC = 1;
    int VALIDATE_DST = 2;
    int VALIDATE_LOC = 4;
    int validator = 0;
    struct arguments *res = calloc(1, sizeof(struct arguments));
    int c;
    for (;;) {
        int option_index = 0;
        c = getopt_long(argc, argv, "s:d:l:n:b:",
                        long_opts, &option_index);
        if (c == -1) {
            break;
        }
        switch (c) {
            case 0:
                if(long_opts[option_index].flag != 0)
                    break;
            case 's':
                if (inet_pton(AF_INET6, optarg, &res->src) != 1) {
                    printf("Failed to parse source address %s\n", optarg);
                    free(res);
                    return NULL;
                }
                validator |= VALIDATE_SRC;
                break;
            case 'd':
                if (inet_pton(AF_INET6, optarg, &res->dst) != 1) {
                    printf("Failed to parse destination address %s\n", optarg);
                    free(res);
                    return NULL;
                }
                validator |= VALIDATE_DST;
                break;
            case 'l':
                if (inet_pton(AF_INET6, optarg, &res->locator) != 1) {
                    printf("Failed to parse locator %s\n", optarg);
                    free(res);
                    return NULL;
                }
                validator |= VALIDATE_LOC;
                break;
            case 'n':
                parse_segment_argument(&res->segs, optarg);
            default:
                break;
        }
    }
    if (validator != (VALIDATE_SRC | VALIDATE_DST | VALIDATE_LOC)) {
        free(res);
        return NULL;
    }
    return res;
}

struct seg6 *gen_srh_stack(struct in6_addr loc, int loc_len, struct seg_list *tail, int *sr_stack_len) {
    __u8 buffer[16384] = {0}; // Buffer for sid creation
    int offset = 0; // the offset for this SRH
    int sid_offset = 0; // the offset for the current combined SID
    int sid_count = 0; // SID count is the number of full 128 bit chunks in the SRH
    bool need_new_srh = true;
    struct seg_list *current = tail;
    struct ipv6_sr_hdr *last_header;
    int last_type = current->seg_type;
    while (current != NULL) {
        if (need_new_srh) {
            fill_srh(&buffer[offset]);
            last_header = (void *) &buffer[offset];
            offset += 8;
            sid_offset = 0;
            last_header->segments_left = 1;
            last_header->hdrlen = 2;
            last_header->first_segment = 0;
            need_new_srh = false;
        }
        switch (current->seg_type) {
            case 2:  // Generate next behavior
                if (sid_count == 0 && sid_offset == 0) {
                    memcpy(&buffer[offset], loc.__in6_u.__u6_addr8, loc_len / 8);
                    sid_count++;
                    sid_offset = loc_len / 8;
                    offset += loc_len / 8;
                }
                if (sid_offset + (current->seg_length / 8) > 16) {
                    sid_count++;
                    memcpy(&buffer[offset], loc.__in6_u.__u6_addr8, loc_len / 8);
                    sid_offset = loc_len / 8;
                    offset += loc_len / 8;
                    last_header->hdrlen += 2;
                    last_header->segments_left++;
                }
                switch (current->seg_length / 8) {
                    case 2:
                        *(__u16 *) (&buffer[offset]) = current->segment.__in6_u.__u6_addr16[0];
                        offset += 2;
                        break;
                    case 4:
                        *(__u32 *) (&buffer[offset]) = current->segment.__in6_u.__u6_addr32[0];
                        offset += 4;
                        break;
                }
                sid_offset += current->seg_length / 8;
                current->f_ptr = (void *) process_usid;
                current = current->prev;
                if (current != NULL && current->seg_type != last_type) {
                    need_new_srh = true;
                    last_type = current->seg_type;
                }
                break;
            case 3: // Generate replace behavior
                printf("Case 3...\n");
                current = current->prev;
                break;
            default:
                current = current->prev;
                break;
        }
    }
    last_header->nexthdr = 41;
    void *res = calloc(1, 8 + (sid_count * 16));
    memcpy(res, buffer, 8 + (sid_count * 16));
    *sr_stack_len = 8 + (sid_count * 16);
    return res;
}

void *process_usid(void *pkt, __u8 loc_size, __u8 sid_size) {
    struct ip6_hdr *hdr = pkt + ETH_SIZE;
    struct ipv6_sr_hdr *sr_hdr = pkt + ETH_SIZE + IPV6_SIZE;
    __u8 loc_bytes = loc_size / 8;
    __u8 *dst_loc = &hdr->ip6_dst.__in6_u.__u6_addr8[loc_bytes];

    __u8 zero_cmp[16 - loc_bytes];
    memset(zero_cmp, 0, 16 - loc_bytes);
    if (hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != 43) {
        printf("Not an SRH encapsulated packet\n");
        return pkt;
    }
    __m128i vec;
    __u8 output[16];
    if (memcmp((void *) dst_loc, zero_cmp, 16 - loc_bytes) != 0 && (sid_size == 16 || sid_size == 32)) {
        vec = _mm_loadl_epi64((void *)dst_loc);
        if(sid_size == 16) {
            vec = _mm_bsrli_si128(vec, 2);
        } else {
            vec = _mm_bsrli_si128(vec, 4);
        }
        _mm_storeu_si128((__m128i*)output, vec);
        memcpy(dst_loc, output, 16-loc_bytes);
    }
    if (memcmp(dst_loc, zero_cmp, 16 - loc_bytes) == 0) {
        struct ip6_hdr *inner_pkt = ((void *) hdr) + IPV6_SIZE + (sr_hdr->hdrlen * 8) + 8;
        __u16 inner_pkt_size = inner_pkt->ip6_ctlun.ip6_un1.ip6_un1_plen + IPV6_SIZE;
        memcpy(pkt + ETH_SIZE, (void *) inner_pkt, inner_pkt_size);
        memset(pkt + ETH_SIZE + inner_pkt_size, 0,
               (hdr->ip6_ctlun.ip6_un1.ip6_un1_plen + IPV6_SIZE - inner_pkt_size));
    }
}

int main(int argc, char **argv) {
    int srh_len;
    int packet_len;
    char orig_dst[64] = {0};
    char src[64] = {0};
    char dst[64] = {0};
    struct arguments *args = parse_args(argc, argv);
    if (args == NULL) {
        printf("Failed to parse arguments\n");
        exit(-1);
    }
    if (args->segs.head == NULL) {
        printf("No segments specified, cannot continue\n");
        exit(-1);
    }
    inet_ntop(AF_INET6, &args->src, src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &args->dst, dst, INET6_ADDRSTRLEN);
    printf("Original packet %s -> %s\n", src, dst);
    memcpy(orig_dst, dst, 64);
    void *srh_stack = gen_srh_stack(args->locator, 48, args->segs.tail, &srh_len);
    void *packet = gen_ipv6_pkt(args, srh_stack, srh_len, &packet_len);
    struct ip6_hdr *hdr = packet + ETH_SIZE;
    struct seg_list *tail = args->segs.tail;
    inet_ntop(AF_INET6, &hdr->ip6_src, src, INET6_ADDRSTRLEN);
    memcpy(orig_dst, dst, 64);
    inet_ntop(AF_INET6, &hdr->ip6_dst, dst, INET6_ADDRSTRLEN);
    printf("[%s %d bit] DA change [%s --> %s]\n",
           tail->seg_type == 2?"NEXT":"REPLACE", tail->seg_length, orig_dst, dst);
    printf("\tForwarding [%s -> %s]\n", src, dst);
    if(dump_hex == 1)
        dump_ptr(packet, packet_len);
    while (tail != NULL) {
        inet_ntop(AF_INET6, &hdr->ip6_dst, dst, INET6_ADDRSTRLEN);
        memcpy(orig_dst, dst, 64);
        if (tail->seg_type == 2) {
            ((sid_behavior) tail->f_ptr)(packet, 48, tail->seg_length);
        }
        inet_ntop(AF_INET6, &hdr->ip6_src, src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &hdr->ip6_dst, dst, INET6_ADDRSTRLEN);
        printf("[%s %d bit] DA change [%s --> %s]\n",
               tail->seg_type == 2?"NEXT":"REPLACE", tail->seg_length, orig_dst, dst);
        printf("\tForwarding [%s -> %s]\n", src, dst);
        if(dump_hex == 1)
            dump_ptr(packet, packet_len);
        tail = tail->prev;
    }
    free(packet);
    return 0;
}
