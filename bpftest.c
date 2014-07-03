// bpf test yea

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <poll.h>

#define MAX_PACKET_SIZE 1496

// single ethernet_frame
struct ethernet_frame
{
    unsigned char dest_addr[ 6 ];
    unsigned char src_addr[ 6 ];
    unsigned short int type;
};

int main(int argc, char *argv[]) {

    char buf[ 11 ] = { 0 };
    int bpf = 0;
    for (int i = 0; i < 99; i++) {
        sprintf( buf, "/dev/bpf%i", i );
        bpf = open( buf, O_RDWR );

        if( bpf != -1 ) break;
    }
    printf("Opened dev %s\n", buf);

    const char* interface = "en0";
    struct ifreq bound_if;
    strcpy(bound_if.ifr_name, interface);
    if(ioctl( bpf, BIOCSETIF, &bound_if ) > 0) {
        perror("ioctl BIOCSETIF");
        return(-1);
    }

    int buf_len = 1;

    // activate immediate mode (therefore, buf_len is initially set to "1")
    if (ioctl(bpf, BIOCIMMEDIATE, &buf_len) == -1) {
        perror("ioctl BIOCIMMEDIATE");
        return(errno);
    }

    // request buffer length
    if (ioctl(bpf, BIOCGBLEN, &buf_len) == -1) {
        perror("ioctl BIOCGBLEN");
        return(errno);
    }
    printf("ioctl BIOCGBLEN buf_len=%i\n", buf_len);

    // filter for cjdns ethertype (0xfc00)
    struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
        // TODO use Ethernet_TYPE_CJDNS
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xfc00, 0, 1),
        // TODO determine size?
        BPF_STMT(BPF_RET+BPF_K, MAX_PACKET_SIZE), // max cjdns frame size?
        BPF_STMT(BPF_RET+BPF_K, 0),
    };

    struct bpf_program bpf_cjdns = {
        .bf_len = (sizeof(insns) / sizeof(struct bpf_insn)),
        .bf_insns = insns,
    };

    if (ioctl(bpf, BIOCSETF, &bpf_cjdns) == -1) {
        perror("ioctl BIOCSETF");
        return(errno);
    }

    int read_bytes = 0;
    char *bpf_buf = malloc(sizeof(char) * buf_len);
    if (bpf_buf == NULL) {
        perror("bpf_buf = malloc()");
        return(errno);
    }

    struct bpf_hdr* bpf_pkt;
    struct ethernet_frame* eth_hdr;
    struct pollfd fds[] = {{ .fd = bpf, .events = POLLPRI | POLLIN, .revents = 0 }};
    int pollret;

    while(1) {
        if ((pollret = poll(fds, 1, 1000)) == 0) continue; 
        else if (pollret == -1) {
            perror("poll()");
        } else {
            printf("poll: %i\n", pollret);
        }

        memset(bpf_buf, 0, buf_len); // clear buffer
        read_bytes = read(bpf, bpf_buf, buf_len);
        if (read_bytes == -1) {
            printf("readbytes: %i\n", read_bytes);
            perror("read(bpf, bpf_buf, buf_len)");
            return(errno);
        }
        if (read_bytes > 0) {
            // read all packets that are included in bpf_buf.
            // BPF_WORDALIGN is used to proceed to the next
            // BPF packet that is available in the buffer.

            char *ptr = 0;
            while((int)ptr + sizeof(bpf_buf) < read_bytes) {
                bpf_pkt = (struct bpf_hdr*)((long)bpf_buf + (long)ptr);
                printf("header: bh_caplen = %d\n", bpf_pkt->bh_caplen);
                eth_hdr = (struct ethernet_frame*)
                    ((long)bpf_buf + (long)ptr + bpf_pkt->bh_hdrlen);
                printf("packet: from %x:%x:%x:%x:%x:%x\n",
                        eth_hdr->src_addr[0],
                        eth_hdr->src_addr[1],
                        eth_hdr->src_addr[2],
                        eth_hdr->src_addr[3],
                        eth_hdr->src_addr[4],
                        eth_hdr->src_addr[5]);

                // swap source and dest
                unsigned char dest_addr[6];

                for (int i = 0; i < 7; i++) {
                    dest_addr[i] = eth_hdr->src_addr[i];
                    eth_hdr->src_addr[i] = eth_hdr->dest_addr[i];
                    eth_hdr->dest_addr[i] = dest_addr[i];
                }

                write(bpf, (const void *)((long)bpf_buf + (long)ptr + bpf_pkt->bh_hdrlen), bpf_pkt->bh_caplen);

                ptr += BPF_WORDALIGN(bpf_pkt->bh_hdrlen + bpf_pkt->bh_caplen);
            }
        }
    }
    free(bpf_buf);
}

///Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.9.sdk/usr/include/net/bpf.h
