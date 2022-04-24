# IPK-proj1

Ulohou projektu bolo navrhnutie a implementácia sieťového analyzátoru v C/C++/C#, ktorý je schopný na určitom sieťovom rozhraní zachytávať a filtrovať pakety

## Spustenie

Na spustenie projektu si staci stiahnut subory s kodom a Makefile. Nasledne pomocou prikazu `make` projekt prelozit s spustit ako `./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}`

### Prerekvizity

Na spravne prelozenie projektu je treba tento software.

- g++
- make
- pcap/pcap.h
- net/ethernet.h
- netinet/ip.h
- netinet/ip_icmp.h
- netinet/in.h
- netinet/tcp.h
- netinet/udp.h
- netinet/if_ether.h
- netinet/ether.h
- netinet/ip6.h

## Pouzitie

Ukážka ako projekt používať.

```
$ ./ipk-sniffer -i eth0 -p 23 --tcp -n 2
$ ./ipk-sniffer -i eth0 --udp
$ ./ipk-sniffer -i eth0 -n 10
$ ./ipk-sniffer -i eth0 -p 22 --tcp --udp --icmp --arp   .... stejné jako:
$ ./ipk-sniffer -i eth0 -p 22
$ ./ipk-sniffer -i eth0
```
