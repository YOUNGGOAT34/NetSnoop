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


   Options *options=malloc(sizeof(Options));

   if(!options){
       error(true,"Failed to allocate memory for options");
   }

   i32 option;

   while(option=getopt_long(argc,argv,"p:",long_options,NULL)!=-1){
              switch(option){
                 
              }
   }

       
   capture_packets();

   printf(WHITE"\n\nNetSnoop Shutting Down\n\n"RESET);
   
   return 0;
}

