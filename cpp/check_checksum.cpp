#include "header.h"
using namespace std;

u_int16_t ip_checksum(u_char *data){ //check ip checksum
    u_int16_t calc;
    int sum = 0;
    int i;
    data[IPCHECKSUM] = 0;
    data[IPCHECKSUM+1] = 0;
    for(i=0;i<20;i=i+2)
    {
        calc = ((data[i]<<8) & 0xFF00)+(data[i+1] & 0xFF);
        sum = sum + calc;
    }
    while(sum >> 16){
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = ~sum;

    return u_int16_t(sum);
}

u_int16_t tcp_checksum(u_char *data,int pay_len){ //check tcp checksum
    u_int16_t tcp_len = u_int16_t(pay_len-20); //tcp length = payload length - ip header
    u_int16_t calc;
    int i,j;
    int sum=0;
    data[TCPCHECKSUM] = 0;
    data[TCPCHECKSUM+1] = 0;
    u_char zero = 0x00;
    for (i=12;i<20;i=i+2){
        calc = ((data[i]<<8) & 0xFF00)+(data[i+1] & 0xFF);
        sum = sum + calc;
    }
    calc = ((zero<<8) & 0xFF00)+(data[PROTO] & 0xFF);
    sum = sum + calc;
    calc = tcp_len;
    sum = sum + calc;
    for(j=20;j<pay_len;j=j+2)
    {
        if(j+1 != pay_len){
            calc = ((data[j]<<8) & 0xFF00)+(data[j+1] & 0xFF);
            sum = sum + calc;
        }else if(j+1 == pay_len){
            calc = (data[j]<<8 & 0xFF00);
            sum = sum + calc;
        }
    }
    while(sum >> 16){
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum += (sum >> 16);
    }
    sum = ~sum;

    return u_int16_t(sum);
}
