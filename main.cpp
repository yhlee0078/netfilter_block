#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */

#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

struct ipv4_hdr 
{
        uint8_t header_len : 4;
        uint8_t version : 4;
        uint8_t type_of_service;
        uint16_t total_packet_len;
        uint16_t fragment_identification;
        uint16_t flags;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t checksum;
        uint8_t src_ip[4];
        uint8_t dst_ip[4];
};

struct tcp_hdr 
{
        uint16_t src_port;
        uint16_t dst_port;
        uint32_t seq_num;
        uint32_t ack_num;
        uint8_t header_len : 4;
        uint16_t flags : 12;
        uint16_t window_size;
        uint16_t checksum;
        uint16_t urgent_ptr;
        uint8_t data[10];
};

const char* methods[] { "GET", "POST", "DELETE" };

char* target_host = NULL;
int target_host_len = 0;
int block_ed = 0;

/*
void dump(unsigned char* buf, int size) {
        int i;
        for (i = 0; i < size; i++) {
                if (i % 16 == 0)
                        printf("\n");
                printf("%02x ", buf[i]);
        }
}
*/

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb) {
        int id = 0;
        struct nfqnl_msg_packet_hdr *ph;
        struct nfqnl_msg_packet_hw *hwph;
        u_int32_t mark,ifi; 
        int ret;
        unsigned char *data;

        block_ed = 0;

        ph = nfq_get_msg_packet_hdr(tb);
        if (ph) id = ntohl(ph->packet_id);

        ret = nfq_get_payload(tb, &data);

        ipv4_hdr* ipv4_ptr = (ipv4_hdr*)data;
        int ipv4_len = ipv4_ptr->header_len * 4;
        tcp_hdr* tcp_ptr = (tcp_hdr*) ((char*)ipv4_ptr + ipv4_len);
        int tcp_len = (tcp_ptr->flags) * 4;

        // printf("length : %d\n", tcp_len);

        int header_len = ((*((char*)tcp_ptr + 12) & 0xff) >> 4) * 4;
        char* data_ptr = ((char*)tcp_ptr + header_len);

        for (int i = 0; i < 3; ++i) 
        {
                int method_len = strlen(methods[i]);

                if (strncmp(data_ptr, methods[i], method_len) == 0) 
                {
                        int url_len = strlen(target_host);

                        char* p = strstr(data_ptr, "Host");
                        if (p == NULL) continue;

                        if (strncmp(p + 6, target_host, target_host_len) == 0)
                        {
                                printf("BLOCKED!\n");
                                block_ed = 1;
                                return id;
                        }
                }
        }

        return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
        u_int32_t id = print_pkt(nfa);

        if (block_ed == 1) 
        {
                nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }

        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
        struct nfq_handle *h;
        struct nfq_q_handle *qh;
        struct nfnl_handle *nh;
        int fd;
        int rv;
        char buf[4096] __attribute__ ((aligned));

        if (argc < 2)
        {
                fprintf(stderr, "netfilter_block <host>\n");
                exit(-1);
        }

        target_host = argv[1]; // get host by argv
        target_host_len = strlen(target_host);


        printf("opening library handle\n");
        h = nfq_open();
        if (!h) {
                fprintf(stderr, "error during nfq_open()\n");
                exit(1);
        }

        printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
        if (nfq_unbind_pf(h, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_unbind_pf()\n");
                exit(1);
        }

        printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
        if (nfq_bind_pf(h, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_bind_pf()\n");
                exit(1);
        }

        printf("binding this socket to queue '0'\n");
        qh = nfq_create_queue(h,  0, &cb, NULL);
        if (!qh) {
                fprintf(stderr, "error during nfq_create_queue()\n");
                exit(1);
        }

        printf("setting copy_packet mode\n");
        if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
                fprintf(stderr, "can't set packet_copy mode\n");
                exit(1);
        }

        fd = nfq_fd(h);

        for (;;) {
                if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
                        // printf("pkt received\n");
                        nfq_handle_packet(h, buf, rv);
                        continue;
                }
                /* if your application is too slow to digest the packets that
                 * are sent from kernel-space, the socket buffer that we use
                 * to enqueue packets may fill up returning ENOBUFS. Depending
                 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
                 * the doxygen documentation of this library on how to improve
                 * this situation.
                 */
                if (rv < 0 && errno == ENOBUFS) {
                        printf("losing packets!\n");
                        continue;
                }
                perror("recv failed");
                break;
        }

        printf("unbinding from queue 0\n");
        nfq_destroy_queue(qh);

#ifdef INSANE
        /* normally, applications SHOULD NOT issue this command, since
         * it detaches other programs/sockets from AF_INET, too ! */
        printf("unbinding from AF_INET\n");
        nfq_unbind_pf(h, AF_INET);
#endif

        printf("closing library handle\n");
        nfq_close(h);

        exit(0);
}
