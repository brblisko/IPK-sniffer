#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap/pcap.h>

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

void print_help()
{
    printf("USAGE: \n");
    printf("\t./ipk-sniffer [-i rozhrani | --interface rozhrani] ");
    printf("{-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n");
}

void process_num(flags *F, char *optarg)
{
    char *endPtr;
    int tmp;
    if ((tmp = strtol(optarg, &endPtr, 10)) > 0)
    {
        F->num = tmp;
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

void process_port(flags *F, char *optarg)
{
    char *endPtr;
    int tmp;
    if ((tmp = strtol(optarg, &endPtr, 10)) > 0)
    {
        F->port = tmp;
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

void init_flags(flags *F)
{
    F->inter = NULL;
    F->port = -1;
    F->num = -1;
    F->arp = false;
    F->icmp = false;
    F->tcp = false;
    F->udp = false;
    F->notDef = false;
}

void process_args(int argc, char **argv, flags *F)
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
                F->inter = argv[optind++];
            }
            break;
        case 'p':
            if (optarg)
            {
                process_port(F, optarg);
            }
            break;
        case 't':
            F->notDef = true;
            F->tcp = true;
            break;
        case 'u':
            F->notDef = true;
            F->udp = true;
            break;
        case 'n':
            if (optarg)
            {
                process_num(F, optarg);
            }
            break;
        case 'a':
            F->notDef = true;
            F->arp = true;
            break;
        case 'c':
            F->notDef = true;
            F->icmp = true;
            break;
        case 'h':
            print_help();
            exit(0);
        case '?':
            exit(1);
        }
    }
    F->arp = true;
}

bool check_inter(flags *F)
{
    if (!F->inter)
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

bool open_dev(flags *F, pcap_t *handle)
{
    // used code from https://www.tcpdump.org/pcap.html
    char errbuff[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;

    handle = pcap_open_live(F->inter, BUFSIZ, 1, 1000, errbuff);
    if (!handle)
    {
        fprintf(stderr, "ERROR - couldn't open device %s: %s\n", F->inter, errbuff);
        return false;
    }

    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "ERROR - device %s doesn't provide Ethernet headers - not supported\n", F->inter);
        return (2);
    }

    /* Grab a packet */
    packet = pcap_next(handle, &header);
    /* Print its length */
    printf("Jacked a packet with length of [%d]\n", header.len);
    /* And close the session */
    pcap_close(handle);

    return true;
}

void create_filter(flags *F, char *filter)
{
    bool havePort = (F->port == -1) ? false : true;

    if (F->notDef)
    {
    }
    strcpy(filter, "saveseg");
    strcat(filter, " and");
    strcat(filter, " ripbozo\n");
}

int main(int argc, char **argv)
{
    flags F;
    pcap_t *handle = NULL;
    char filter[1000] = "\0";
    printf("%s\n", filter);
    init_flags(&F);

    process_args(argc, argv, &F);

    if (check_inter(&F))
    {
        return 0;
    }

    if (!open_dev(&F, handle))
    {
        pcap_close(handle);
        return 1;
    }

    create_filter(&F, filter);

    printf("%s", filter);
    return 0;
}