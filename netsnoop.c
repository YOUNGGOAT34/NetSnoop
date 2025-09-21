#include "netsnoop.h"

void error(bool with_exit,const i8* error_message){
    if(with_exit){
       fprintf(stderr,RED"%s:(%s)\n"RESET,error_message,strerror(errno));
       exit(EXIT_FAILURE);

    }

    fprintf(stderr,RED"%s:(%s)\n"RESET,error_message,strerror(errno));
   

}

void capture_packets(void){
  
   //a socket that will sniff on all interfaces ,and all protocals
   i32 socket_fd=socket(PACKETS,SOCK_RAW,ALL_INTERFACES);

   if(socket_fd<0){
       error(true,"Failed to create a raw socket");
   }

   i8 *packet_buffer=malloc(BUFFER_SIZE);

   if(!packet_buffer){
       error(true,"Failed to allocate memory for the packet buffer");
   }

   ssize_t  received_bytes;
   SA saddr;
   socklen_t addr_size;
   while(1){
      /* 
        receive the packet ,process it 
      */
      addr_size=sizeof(saddr);
      received_bytes=recvfrom(socket_fd,packet_buffer,BUFFER_SIZE,0,&saddr,&addr_size);

      if(received_bytes<0 || received_bytes==-1){
           error(false,"Error receiving packet");
      }

      
   }





}