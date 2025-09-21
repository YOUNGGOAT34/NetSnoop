#include "netsnoop.h"

void error(bool with_exit,const i8* error_message){
    if(with_exit){
       fprintf(stderr,RED"%s:(%s)\n"RESET,error_message,strerror(errno));
       exit(EXIT_FAILURE);

    }

    fprintf(stderr,RED"%s:(%s)\n"RESET,error_message,strerror(errno));
   

}

void capture_packets(void){
  
   i32 socket_fd=socket(PACKETS,SOCK_RAW,ALL_INTERFACES);

   if(socket_fd<0){
       error(true,"Failed to create a raw socket");
   }

   


}