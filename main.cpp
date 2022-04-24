#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>

#include <signal.h>
#include <time.h>

using namespace std;

static struct option options[] =
    {
        {"interface", optional_argument, NULL, 'i'},
        {"", optional_argument, NULL, 'p'},
        {"tcp", optional_argument, NULL, 't'},
        {"udp", optional_argument, NULL, 'u'},
        {"arp", optional_argument, NULL, 'a'},
        {"icmp", optional_argument, NULL, 'c'},
        {"", optional_argument, NULL, 'n'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}

};

typedef struct flags
{
    char *inter;
    int port;
    bool tcp;
    bool udp;
    bool arp;
    bool icmp;
    bool notDef;
    int num;

} flags;

flags F;
pcap_t *handle;
string filter = "\0";

void print_help()
{
    printf("USAGE: \n");
    printf("\t./ipk-sniffer [-i rozhrani | --interface rozhrani] ");
    printf("{-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n");
}

void process_num(char *optarg)
{
    char *endPtr;
    int tmp;
    if ((tmp = strtol(optarg, &endPtr, 10)) > 0)
    {
        F.num = tmp;
    }
    else
    {
        fprintf(stderr, "ERROR - number of packets cannot be minus\n");
        exit(1);
    }

    if (*endPtr != '\0')
    {
        fprintf(stderr, "ERROR - num argument is not a full number\n");
        exit(1);
    }
}

void process_port(char *optarg)
{
    char *endPtr;
    int tmp;
    if ((tmp = strtol(optarg, &endPtr, 10)) > 0)
    {
        F.port = tmp;
    }
    else
    {
        fprintf(stderr, "ERROR - port cannot be minus\n");
        exit(1);
    }

    if (*endPtr != '\0')
    {
        fprintf(stderr, "ERROR - port is not a full number\n");
        exit(1);
    }
}

void init_flags()
{
    F.inter = NULL;
    F.port = -1;
    F.num = 1;
    F.arp = false;
    F.icmp = false;
    F.tcp = false;
    F.udp = false;
    F.notDef = false;
}

void process_args(int argc, char **argv)
{

    int opt = 0;
    int long_indx = 0;
    while ((opt = getopt_long(argc, argv, "p:i::tun:h",
                              options, &long_indx)) != -1) // set string for arguments
    {
        switch (opt)
        {
        case 'i':
            // code from https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/
            // MIT licence
            // if we have --interface

            if (!optarg && optind < argc && argv[optind][0] != '-')
            { // need to check if there is argument behind it and that argument is not another recognized argument
                F.inter = argv[optind++];
            }
            break;
            // end of code from https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/
        case 'p':
            if (optarg)
            {
                process_port(optarg);
            }
            break;
        case 't':
            F.notDef = true;
            F.tcp = true;
            break;
        case 'u':
            F.notDef = true;
            F.udp = true;
            break;
        case 'n':
            if (optarg)
            {
                process_num(optarg);
            }
            break;
        case 'a':
            F.notDef = true;
            F.arp = true;
            break;
        case 'c':
            F.notDef = true;
            F.icmp = true;
            break;
        case 'h':
            print_help();
            exit(0);
        case '?':
            exit(1);
        }
    }
}
// used code from https://www.tcpdump.org/pcap.html
/*This document is Copyright 2002 Tim Carstens. All rights reserved. Redistribution and use, with or without modification,
  are permitted provided that the following conditions are met:

    1. Redistribution must retain the above copyright notice and this list of conditions.

    2.The name of Tim Carstens may not be used to endorse or promote products derived from this document without specific prior written permission.

Insert 'wh00t' for the BSD license here wh00t*/
bool check_inter()
{
    if (!F.inter)
    { // print all interfaces
        char errbuff[PCAP_ERRBUF_SIZE];
        pcap_if_t *list;
        int tmp = pcap_findalldevs(&list, errbuff);

        if (tmp == PCAP_ERROR)
        {
            fprintf(stderr, "ERROR - could not list interfaces\n");
            exit(1);
        }

        pcap_if_t *active;

        printf("Interfaces:\n");
        for (active = list; active != NULL; active = active->next)
        {
            printf("\t%s\n", active->name);
        }
        pcap_freealldevs(list);
        return true;
    }

    return false;
}
// end of code from https://www.tcpdump.org/pcap.html

// creating filter
void create_filter()
{
    // check if port was specified in arguments
    bool havePort = (F.port == -1) ? false : true;

    if (F.notDef)
    {
        if (F.arp)
        { // if we have arp
            filter = "arp ";
            if (F.icmp || F.tcp || F.udp)
            { // must add or if we have multiple protocols
                filter = filter + "or ";
            }
        }
        if (F.icmp)
        {
            filter = filter + "icmp or icmp6 ";
            if (F.tcp || F.udp)
            { // must add or if we have multiple protocols
                filter = filter + "or ";
            }
        }
        if (F.tcp)
        {
            if (havePort)
            { // need to add port
                filter = filter + "(tcp and port " + to_string(F.port) + ") ";
            }
            else
            {
                filter = filter + "tcp ";
            }
            if (F.udp)
            { // must add or if we have multiple protocols
                filter = filter + "or ";
            }
        }
        if (F.udp)
        {
            if (havePort)
            { // need to add port
                filter = filter + "(udp and port " + to_string(F.port) + ") ";
            }
            else
            {
                filter = filter + "udp ";
            }
        }
        if (!F.tcp && !F.udp && havePort)
        {
            filter = filter + "or ";
            filter = filter + "(tcp and port " + to_string(F.port) + ") or" + "(udp and port " + to_string(F.port) + ") ";
        }
    }
    else
    {
        if (havePort)
        { // if we have port we need to catch all protocols but with that port
            filter = "(tcp and port " + to_string(F.port) + ") or ";
            filter = filter + "(udp and port " + to_string(F.port) + ") or ";
            filter = filter + "arp or icmp or icmp6";
        }
        else
        { // all protocols and all ports
            filter = "tcp or udp or arp or icmp or icmp6";
        }
    }
}

// ending program with ctrl c
void signal_catch_ctrl_c(int num)
{
    pcap_close(handle);
    exit(0);
}

// inspired by and used code from https://stackoverflow.com/questions/5438482/getting-the-current-time-as-a-yyyy-mm-dd-hh-mm-ss-string
void print_timestamp(struct pcap_pkthdr header)
{
    struct tm *timeStamp;
    char tmp[80];
    // change to tm struct
    timeStamp = localtime(&(header.ts.tv_sec));
    strftime(tmp, 80, "%Y-%m-%dT%H-%M-%S.", timeStamp); // format the output
    // print time stamp, need to print miliseconds and time zone
    printf("timestamp: %s%03i+%.02ld:00\n", tmp, int(header.ts.tv_usec) / 1000, timeStamp->tm_gmtoff / 3200);
}
// end of code from https://stackoverflow.com/questions/5438482/getting-the-current-time-as-a-yyyy-mm-dd-hh-mm-ss-string

void process_ipv4(struct iphdr *ip4Head, const u_char *packet)
{
    // print ip addresses
    printf("src IP: %s\n", inet_ntoa(*(in_addr *)&ip4Head->saddr));
    printf("des IP: %s\n", inet_ntoa(*(in_addr *)&ip4Head->daddr));

    if (ip4Head->protocol == IPPROTO_UDP)
    {
        // get udp header
        struct udphdr *udpHead = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip4Head->ihl * 4));

        printf("src port: %d\n", ntohs(udpHead->uh_sport));
        printf("dst port: %d\n", ntohs(udpHead->uh_dport));
    }
    else if (ip4Head->protocol == IPPROTO_TCP)
    {
        // get tcp header
        struct tcphdr *tcpHead = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip4Head->ihl * 4));

        printf("src port: %d\n", ntohs(tcpHead->th_sport));
        printf("dst port: %d\n", ntohs(tcpHead->th_dport));
    }
    else if (ip4Head->protocol == IPPROTO_ICMP)
    {
        printf("\n");
    }
}

void process_ipv6(struct ip6_hdr *ip6Head, const u_char *packet)
{
    // print ip addresses
    printf("src IP: %s\n", inet_ntoa(*(in_addr *)&ip6Head->ip6_src));
    printf("des IP: %s\n", inet_ntoa(*(in_addr *)&ip6Head->ip6_dst));

    if (ip6Head->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP)
    {
        // get udp header
        struct udphdr *udpHead = (struct udphdr *)(packet + sizeof(struct ether_header) + 40);

        printf("src port: %d\n", ntohs(udpHead->uh_sport));
        printf("dst port: %d\n", ntohs(udpHead->uh_dport));
    }
    else if (ip6Head->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP)
    {
        // get tcp header
        struct tcphdr *tcpHead = (struct tcphdr *)(packet + sizeof(struct ether_header) + 40);

        printf("src port: %d\n", ntohs(tcpHead->th_sport));
        printf("dst port: %d\n", ntohs(tcpHead->th_dport));
    }
    else if (ip6Head->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6)
    {

        printf("\n");
    }
}

void process_arp(ether_arp *arpHead, const u_char *packet)
{
    // print src and des ip
    printf("src IP: %s\n", inet_ntoa(*(in_addr *)&arpHead->arp_spa));
    printf("des IP: %s\n", inet_ntoa(*(in_addr *)&arpHead->arp_tpa));
}

// used code from https://www.programcreek.com/cpp/?CodeExample=hex+dump
// Example 5
// Project: NoMercy |  Author: mq1n |  File: INetworkScanner.cpp | License: GNU General Public License v3.0
void hexDump(const u_char *packet, int len)
{
    printf("\n");

    unsigned char buff[17];
    unsigned char *pc = (unsigned char *)packet;
    bool printed = false;
    bool eight = false;
    int index = -1;

    for (int i = 0; i < len; i++)
    {
        if ((i % 16) == 0)
        {
            if (i != 0)
            {
                printf("  %s\n", buff);
                printed = true;
                index = -1;
            }

            printf("0x%04x ", i);
            eight = false;
        }
        if (index == 7)
        {
            printf(" ");
            eight = true;
        }

        printf(" %02x", pc[i]);

        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
        {
            buff[i % 16] = '.';
            index++;
            printed = false;
        }
        else
        {
            buff[i % 16] = pc[i];
            index++;
            printed = false;
        }
        buff[(i % 16) + 1] = '\0';
    }
    if (!printed)
    { // on last unfinished row the buffer is not printed
        // need to print empty spaces to make it aligned
        buff[index + 1] = '\0';
        for (int i = 0; i < int(16 - strlen((const char *)buff)); i++)
        {
            printf("   ");
        }
        if (!eight)
        {
            printf(" ");
        }
        printf("  %s\n", buff);
    }
}
// end of code from https://www.programcreek.com/cpp/?CodeExample=hex+dump

// process packet
void process_packet(const u_char *packet, struct pcap_pkthdr header)
{
    print_timestamp(header);
    // get ethernet header
    struct ether_header *ethHead = (struct ether_header *)packet;
    // printing mac addresses by one byte (code inspired by https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/)
    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethHead->ether_shost[0], ethHead->ether_shost[1], ethHead->ether_shost[2], ethHead->ether_shost[3], ethHead->ether_shost[4], ethHead->ether_shost[5]);
    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethHead->ether_dhost[0], ethHead->ether_dhost[1], ethHead->ether_dhost[2], ethHead->ether_dhost[3], ethHead->ether_dhost[4], ethHead->ether_dhost[5]);

    printf("frame length: %i", header.len);
    printf(" bytes\n");

    if (ntohs(ethHead->ether_type) == ETHERTYPE_IP)
    {
        // get ip4 header
        struct iphdr *ip4Head = (struct iphdr *)(packet + sizeof(ether_header));
        process_ipv4(ip4Head, packet);
    }
    else if (ntohs(ethHead->ether_type) == ETHERTYPE_IPV6)
    {
        // get ip6 header
        struct ip6_hdr *ip6Head = (struct ip6_hdr *)(packet + sizeof(ether_header));
        process_ipv6(ip6Head, packet);
    }
    else if (ntohs(ethHead->ether_type) == ETHERTYPE_ARP)
    {
        // get arp header
        struct ether_arp *arpHead = (struct ether_arp *)(packet + sizeof(ether_header));
        process_arp(arpHead, packet);
    }
    hexDump(packet, header.len);
}

int main(int argc, char **argv)
{
    signal(SIGINT, signal_catch_ctrl_c);

    init_flags();

    process_args(argc, argv);

    if (check_inter())
    {
        return 0;
    }

    // used code from https://www.tcpdump.org/pcap.html

    /*This document is Copyright 2002 Tim Carstens. All rights reserved. Redistribution and use, with or without modification,
      are permitted provided that the following conditions are met:

        1. Redistribution must retain the above copyright notice and this list of conditions.

        2.The name of Tim Carstens may not be used to endorse or promote products derived from this document without specific prior written permission.

    Insert 'wh00t' for the BSD license here wh00t*/

    char errbuff[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    struct bpf_program fp;
    bpf_u_int32 myIp;
    bpf_u_int32 myMask;
    const u_char *packet;

    /* Find the properties for the device */
    if (pcap_lookupnet(F.inter, &myIp, &myMask, errbuff) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", F.inter, errbuff);
        myIp = 0;
        myMask = 0;
    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(F.inter, BUFSIZ, 1, 1000, errbuff);
    if (!handle)
    {
        fprintf(stderr, "ERROR - couldn't open device %s: %s\n", F.inter, errbuff);
        return 1;
    }

    /* Check if device support link-layer header type*/
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "ERROR - device %s doesn't provide Ethernet headers - not supported\n", F.inter);
        return 1;
    }

    /* Compile and apply the filter */
    create_filter();
    printf("%s\n", filter.c_str());
    if (pcap_compile(handle, &fp, filter.c_str(), 0, myIp) == -1)
    {
        fprintf(stderr, "ERROR - couldn't parse filter %s: %s\n", filter.c_str(), pcap_geterr(handle));
        return (2);
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "ERROR - couldn't install filter %s: %s\n", filter.c_str(), pcap_geterr(handle));
        return (2);
    }

    for (int i = 0; i < F.num; i++)
    {
        packet = pcap_next(handle, &header);

        process_packet(packet, header);
    }

    pcap_close(handle);

    // end of code from https://www.tcpdump.org/pcap.html
    return 0;
}