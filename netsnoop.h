#ifndef NETSNOOP_H
#define NETSNOOP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
/*

  get the ip header
  icmp header
  tcp header
  udp header

  declarations
*/

#include <netinet/ip.h>



//variable defitions
#define BUFFER_SIZE 65536
#define ALL_INTERFACES ETH_P_ALL 
#define PACKETS AF_PACKET 
#define  SA struct sockaddr

//packet header definations
#define IP struct iphdr

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

void error(bool with_exit,const i8*);
void capture_packets(void);
void process_packet(i8 *,ssize_t );
void showicmp(i8 *,ssize_t);



#endif