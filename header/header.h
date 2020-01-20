#pragma once
#ifndef HEADER_H
#define HEADER_H
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <pcap.h>
#include <string>
#include <map>
#define unuse(x) (void)(x)
#define TOTALLEN    2
#define PROTO 9
#define IPCHECKSUM  10
#define SIP 12
#define DIP 16
#define SPORT   20
#define DPORT   22
#define SEQ 24
#define ACK 28
#define TCPCHECKSUM 36

struct flow{ //flow structure
    u_int64_t sip;
    u_int64_t dip;
    u_int16_t sport;
    u_int16_t dport;
    bool operator<(const flow& flow2) const{
        if(this->sip<flow2.sip||this->dip<flow2.dip||this->sport<flow2.sport||this->dport<flow2.dport){
            return true;
        }else{
            return false;
        }
    }
};


void Usage(char *argv[]); //show usage
u_short ip_checksum(u_char *data); //check ip checksum
u_short tcp_checksum(u_char *data,int pay_len); //check tcp checksum

#endif
