#ifndef NETSNOOP_H
#define NETSNOOP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>

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


#define NUM_OF_THREADS 10

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


typedef struct{
  struct in_addr src;
  struct in_addr dst;
}src_dst_ip;

typedef enum {
  PROTO_UNKNOWN = 0,
  PROTO_ICMP = 1,
  PROTO_TCP  = 6,
  PROTO_UDP  = 17
} ProtocolType;

typedef struct {
     i32 count;
     i8 **interfaces;
}__attribute__((packed)) INTERFACES;


/*
   enumerate the arguments
*/

typedef enum{
     icmp,
     tcp,
     udp,
     NONE,
     proto_unknown
}__attribute__((packed)) Protocal;

typedef struct {
      Protocal proto;
      i8 *interface;
}__attribute__((packed)) Options;






/*
  prototypes
*/

void error(bool with_exit,const i8*);
void start_threads(Options *opts);
// void capture_packets(Options *);
void process_packet(i8 *,ssize_t,Options *);
void showicmp(i8 *,ssize_t);
void showudp(i8 *,ssize_t);
src_dst_ip *showipheader(IP *);
void showtcp(i8 *data,ssize_t data_size);
void set_signal_handler(void);
void handle_signal(__attribute__((unused)) i32 );
void hexdump(void *buff,u16 size,IP *ip_header);
const char* get_timestamp(); 

#endif