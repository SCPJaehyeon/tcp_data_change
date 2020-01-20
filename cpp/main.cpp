#include "header.h"
using namespace std;

static int cmp, ret1, diff; //cmp = change able, ret1 = new packet length, diff = argv[2]-argv[1]
static string from_string, toto_string; //from_string = argv[1], toto_string = argv[2]
static u_char *data1; //new packet

static struct flow atob; //for map
static map<flow, int> flowm;
static map<flow, int>::iterator flowmit;

int changer(unsigned char *data, int pay_len); //packet changer
void dump(unsigned char* buf, int size);
static u_int32_t print_pkt (struct nfq_data *tb);
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data); //return packet

int main(int argc, char** argv){
    if(argc != 3){
        Usage(argv);
        return -1;
    }
    from_string = argv[1]; //from_string > toto_string
    toto_string = argv[2];
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    unuse(nh);
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
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
    qh = nfq_create_queue(h,  0, &cb, nullptr);
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
            printf("**********************************************************\n");
            printf("Packet Received!\n");
            diff = int(toto_string.size() - from_string.size());
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);


    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}


int changer(unsigned char *data, int pay_len){ //packet check and changer
    cmp = 0;
    int cnt = 0;
    int e_size = 14;
    int ip_size = (u_int8_t(data[0]) & 0x0F) * 4;
    int tcp_size = ((u_int8_t(data[e_size+ip_size-2]) & 0xF0) >> 4) * 4;

    u_int64_t cmpsip, cmpdip;
    u_int16_t cmpsport, cmpdport;
    u_int32_t seq, ack;
    memcpy(&cmpsip, &data[SIP],4);
    memcpy(&cmpdip, &data[DIP],4);
    memcpy(&cmpsport, &data[SPORT],2);
    memcpy(&cmpdport, &data[DPORT],2);
    memcpy(&seq,&data[SEQ],4);
    memcpy(&ack,&data[ACK],4);
    seq = ntohl(seq);
    ack = ntohl(ack);

    if(diff!=0){ //if argv[2]-argv[1] != 0
        for(flowmit = flowm.begin();flowmit != flowm.end();flowmit++){
            int cmp1 = memcmp(&cmpsip, &flowmit->first.dip, 4); //first flow
            int cmp2 = memcmp(&cmpdip, &flowmit->first.sip, 4);
            int cmp3 = memcmp(&cmpsport, &flowmit->first.dport, 2);
            int cmp4 = memcmp(&cmpdport, &flowmit->first.sport, 2);
            if(cmp1==0&&cmp2==0&&cmp3==0&&cmp4==0){
                ack = ack-u_int32_t(flowmit->second);
                ack = htonl(ack);
                memcpy(&data1[ACK],&ack,4);
            }
            int cmp5 = memcmp(&cmpsip, &flowmit->first.sip, 4); //second flow
            int cmp6 = memcmp(&cmpdip, &flowmit->first.dip, 4);
            int cmp7 = memcmp(&cmpsport, &flowmit->first.sport, 2);
            int cmp8 = memcmp(&cmpdport, &flowmit->first.dport, 2);
            if(cmp5==0&&cmp6==0&&cmp7==0&&cmp8==0){
                seq = seq+u_int32_t(flowmit->second);
                seq = htonl(seq);
                memcpy(&data1[SEQ],&seq,4);
            }
        }
    }

    if(data[PROTO] == 0x06 && pay_len > 0){ //if TCP protocol and payload length > 0
        for(int i = 0;i <= pay_len;i++){
            if(data[ip_size+tcp_size+5+i] == from_string[cnt]){
                cnt += 1;
                if(cnt == int(from_string.size())){
                    if(diff != 0){
                        if(diff<0){
                            for(int c1 = 0;c1>diff;c1--){
                                for(int mv =ip_size+tcp_size+5+i+1+c1;mv<ret1;mv++){ //hex move
                                    memcpy(&data1[mv-1],&data1[mv],1);
                                }
                            }
                        }
                        u_int16_t data_len;
                        memcpy(&data_len,&data1[2],2);
                        data_len = ntohs(data_len);
                        data_len = data_len + u_int16_t(diff);
                        data_len = htons(data_len);
                        memcpy(&data1[TOTALLEN],&data_len,2); //total length plus
                        ret1 = ret1+diff; //payload length plus
                        u_char null = 0x00;
                        if(diff>0){
                            for(int c2 = 0;c2<diff;c2++){
                                for(int mv =ret1;mv>ip_size+tcp_size+5+i;mv--){
                                    if(mv==ip_size+tcp_size+5+i+1){ //hex move
                                        memcpy(&data1[mv-1],&null,1);
                                    }
                                    memcpy(&data1[mv],&data1[mv-1],1);
                                }
                            }
                        }
                        memcpy(&atob.sip, &data[SIP],4);
                        memcpy(&atob.dip, &data[DIP],4);
                        memcpy(&atob.sport, &data[SPORT],2);
                        memcpy(&atob.dport, &data[DPORT],2);
                        flowm.insert(make_pair(atob,diff));
                    }
                    cmp = 1;
                    for(int j =0;j!=cnt+diff;j++){ //change string
                        memcpy(&data1[ip_size+tcp_size+5+i-cnt+j+1],&toto_string[j],1);
                    }
                }
            }else{
                cnt = 0;
            }
        }
    }
    return cmp;
}

void dump(unsigned char* buf, int size) { //show hex
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
    printf("\n");
}

static u_int32_t print_pkt (struct nfq_data *tb) //return packet id
{
    u_int32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    ret1 = nfq_get_payload(tb, &data1); //new packet get payload ret
    cmp = changer(data, ret); //return cmp

    u_int16_t ipchecksum = ip_checksum(data1); //check checksum
    u_int16_t tcpchecksum = tcp_checksum(data1, ret1);
    data1[IPCHECKSUM] = (ipchecksum & 0xFF00)>>8;
    data1[IPCHECKSUM+1] = ipchecksum & 0x00FF;
    data1[TCPCHECKSUM] = (tcpchecksum & 0xFF00)>>8;
    data1[TCPCHECKSUM+1] = tcpchecksum & 0x00FF;

    if (ret >= 0)
        printf("payload_len=%d ", ret);

    fputc('\n', stdout);

    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data) //return packet
{
    unuse(nfmsg);
    unuse(data);
    u_int32_t id = print_pkt(nfa);
    printf("id = %d \n",id);
    printf("entering callback\n");
        if(cmp==1){
            printf("This packet is Changed! \n");
            dump(data1,ret1);
            return nfq_set_verdict(qh, id, NF_ACCEPT, u_int32_t(ret1), data1);
        }
        else {
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
        }
}
