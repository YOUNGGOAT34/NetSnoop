#ifndef NETSNOOP_H
#define NETSNOOP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
/*

  get the ip header
  icmp header
  tcp header
  udp header

  declarations
*/

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>


#define IS_PRINTABLE_ASCII(c) (((c)>31) && ((c)<127))


//variable defitions
#define BUFFER_SIZE 65536
#define ALL_INTERFACES ETH_P_ALL 
#define PACKETS AF_PACKET 
#define  SA struct sockaddr
#define ETHERNET_HEADER_SIZE sizeof(struct ethhdr)

//packet header definations
#define IP struct iphdr
#define ICMP struct icmphdr
#define UDP struct udphdr
#define TCP struct tcphdr

//colors
#define RED   "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW "\033[1;33m"
#define RESET "\033[0m"
#define CYAN "\033[1;36m"
#define WHITE "\033[1;37m"

//signed data types
typedef char i8;
typedef signed short int i16;
typedef signed int i32;
typedef signed long int i64;


//unsigned data types
typedef unsigned char u8;
typedef unsigned short int u16;
typedef unsigned int u32;
typedef unsigned long int u64;



typedef enum {
  PROTO_UNKNOWN = 0,
  PROTO_ICMP = 1,
  PROTO_TCP  = 6,
  PROTO_UDP  = 17
} ProtocolType;

void error(bool with_exit,const i8*);
void capture_packets(void);
void process_packet(i8 *,ssize_t );
void showicmp(i8 *,ssize_t);
void showudp(i8 *,ssize_t);
void showipheader(IP *);
void showtcp(i8 *data,ssize_t data_size);
void hexdump(void *buff,u16 size);


#endif