#include "netsnoop.h"
#include <getopt.h>

/*
 Ping flood /
 ICMP flood

*/


int main(int argc,char *argv[]){
   
   static struct option long_options[]={
         {"protocal",required_argument,0,'p'}
   };


   
       
   capture_packets();

   printf(WHITE"\n\nNetSnoop Shutting Down\n\n"RESET);
   
   return 0;
}

