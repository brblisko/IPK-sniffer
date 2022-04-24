#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
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
                              options, &long_indx)) != -1)
    {
        switch (opt)
        {
        case 'i':

            if (!optarg && optind < argc && argv[optind][0] != '-')
            {
                F.inter = argv[optind++];
            }
            break;
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

bool check_inter()
{
    if (!F.inter)
    {
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

bool open_dev()
{
    // used code from https://www.tcpdump.org/pcap.html
    char errbuff[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;

    handle = pcap_open_live(F.inter, BUFSIZ, 1, 1000, errbuff);
    if (!handle)
    {
        fprintf(stderr, "ERROR - couldn't open device %s: %s\n", F.inter, errbuff);
        return false;
    }

    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "ERROR - device %s doesn't provide Ethernet headers - not supported\n", F.inter);
        return (2);
    }

    /* Grab a packet */
    packet = pcap_next(handle, &header);
    /* Print its length */
    printf("Jacked a packet with length of [%d]\n", header.len);
    /* And close the session */

    return true;
}

void create_filter()
{
    bool havePort = (F.port == -1) ? false : true;

    if (F.notDef)
    {
        if (F.arp)
        {
            filter = "arp ";
            if (F.icmp || F.tcp || F.udp)
            {
                filter = filter + "or ";
            }
        }
        if (F.icmp)
        {
            filter = filter + "icmp or icmp6 ";
            if (F.tcp || F.udp)
            {
                filter = filter + "or ";
            }
        }
        if (F.tcp)
        {
            if (havePort)
            {
                filter = filter + "(tcp and port " + to_string(F.port) + ") ";
            }
            else
            {
                filter = filter + "tcp ";
            }
            if (F.udp)
            {
                filter = filter + "or ";
            }
        }
        if (F.udp)
        {
            if (havePort)
            {
                filter = filter + "(udp and port " + to_string(F.port) + ") ";
            }
            else
            {
                filter = filter + "udp ";
            }
        }
    }
    else
    {
        if (havePort)
        {
            filter = "(tcp and port " + to_string(F.port) + ") or ";
            filter = filter + "(udp and port " + to_string(F.port) + ") or ";
            filter = filter + "arp or icmp or icmp6";
        }
        else
        {
            filter = "tcp or udp or arp or icmp or icmp6";
        }
    }
}

void signal_catch_ctrl_c(int num)
{
    exit(0);
}

void print_timestamp(struct pcap_pkthdr header)
{
    struct tm *timeStamp;
    char tmp[80];

    timeStamp = localtime(&(header.ts.tv_sec));
    strftime(tmp, 80, "%Y-%m-%dT%H-%M-%S.", timeStamp);

    printf("timestamp: %s%03i+%.02ld:00\n", tmp, int(header.ts.tv_usec) / 1000, timeStamp->tm_gmtoff / 3200);
}

void process_ipv4(struct iphdr *ip4Head, const u_char *packet)
{

    printf("src IP: %s\n", inet_ntoa(*(in_addr *)&ip4Head->saddr));
    printf("des IP: %s\n", inet_ntoa(*(in_addr *)&ip4Head->daddr));

    if (ip4Head->protocol == IPPROTO_UDP)
    {
        struct udphdr *udpHead = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip4Head->ihl * 4));

        printf("src port: %d\n", ntohs(udpHead->uh_sport));
        printf("dst port: %d\n", ntohs(udpHead->uh_dport));
    }
    else if (ip4Head->protocol == IPPROTO_TCP)
    {
        struct udphdr *tcpHead = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip4Head->ihl * 4));

        printf("src port: %d\n", ntohs(tcpHead->uh_sport));
        printf("dst port: %d\n", ntohs(tcpHead->uh_dport));
    }
    else if (ip4Head->protocol == IPPROTO_ICMP)
    {
        printf("\n");
    }
}

void process_ipv6(struct ip6_hdr *ip6Head, const u_char *packet)
{
    // TODO
}

void process_packet(const u_char *packet, struct pcap_pkthdr header)
{
    print_timestamp(header);

    struct ether_header *ethHead = (struct ether_header *)packet;

    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethHead->ether_shost[0], ethHead->ether_shost[1], ethHead->ether_shost[2], ethHead->ether_shost[3], ethHead->ether_shost[4], ethHead->ether_shost[5]);
    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethHead->ether_dhost[0], ethHead->ether_dhost[1], ethHead->ether_dhost[2], ethHead->ether_dhost[3], ethHead->ether_dhost[4], ethHead->ether_dhost[5]);

    printf("frame length: %i", header.len);
    printf(" bytes\n");

    if (ntohs(ethHead->ether_type) == ETHERTYPE_IP)
    {
        struct iphdr *ip4Head = (struct iphdr *)(packet + sizeof(ether_header));
        process_ipv4(ip4Head, packet);
    }
    else if (ntohs(ethHead->ether_type) == ETHERTYPE_IPV6)
    {
        struct ip6_hdr *ip6Head = (struct ip6_hdr *)(packet + sizeof(ether_header));
        process_ipv6(ip6Head, packet);
    }
    else if (ntohs(ethHead->ether_type) == ETHERTYPE_ARP)
    {
    }
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
    char errbuff[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    struct bpf_program fp;
    bpf_u_int32 myIp4;
    const u_char *packet;

    handle = pcap_open_live(F.inter, BUFSIZ, 1, 1000, errbuff);
    if (!handle)
    {
        fprintf(stderr, "ERROR - couldn't open device %s: %s\n", F.inter, errbuff);
        return 1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "ERROR - device %s doesn't provide Ethernet headers - not supported\n", F.inter);
        return 1;
    }

    create_filter();
    if (pcap_compile(handle, &fp, filter.c_str(), 0, myIp4) == -1)
    {
        fprintf(stderr, "ERROR - couldn't parse filter %s: %s\n", filter.c_str(), pcap_geterr(handle));
        return (2);
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "ERROR - couldn't install filter %s: %s\n", filter.c_str(), pcap_geterr(handle));
        return (2);
    }

    /* Grab a packet */
    for (int i = 0; i < F.num; i++)
    {
        packet = pcap_next(handle, &header);

        process_packet(packet, header);
    }

    /* And close the session */
    pcap_close(handle);

    printf("%s", filter.c_str());
    return 0;
}