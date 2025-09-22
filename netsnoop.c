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
   i32 socket_fd=socket(PACKETS,SOCK_RAW,htons(ALL_INTERFACES));

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
       
   
      
      process_packet(packet_buffer,received_bytes);


   }





}


void process_packet(i8 *data,ssize_t data_size){
   
      /*
        Extract the ip header from the received data and take action accordiing to the protocal type i.e icmp
      */
      IP *ip_header=(IP *)(data+ETHERNET_HEADER_SIZE);
      printf("%u\n",ip_header->protocol);
      switch(ip_header->protocol){
          case 1:
            printf("Here\n");
            showicmp(data,data_size);
            break;
          default:
            break;
      }


}


void showicmp(i8 *data,ssize_t data_size){
   
   IP *ip_header=(IP *)(data+ETHERNET_HEADER_SIZE);
   u16 ipheader_len=ip_header->ihl*4;
   
   ICMP *icmp=(ICMP *)(data+ipheader_len);

   showipheader(data);

   printf("\tICMP\n");

   printf("Type: %d",icmp->type);
   
   switch(icmp->type){
      case 0:  printf(" (Echo Reply)\n"); break;
      case 3:  printf(" (Destination Unreachable)\n"); break;
      case 8:  printf(" (Echo Request)\n"); break;
      case 11: printf(" (Time Exceeded)\n"); break;
      case 13: printf(" (Timestamp Request)\n"); break;
      case 14: printf(" (Timestamp Reply)\n"); break;
      default: printf("\n"); break;
   }

   printf("\tCode: %d\n", icmp->code);
   printf("\tChecksum: 0x%04x\n", ntohs(icmp->checksum));




}


void showipheader(i8 *data){
      IP *ip_header=(IP *)(data+ETHERNET_HEADER_SIZE);
       u16 ipheader_len=ip_header->ihl*4;
       
       struct in_addr src_ip,dst_ip;

       src_ip.s_addr=ip_header->saddr;
       dst_ip.s_addr=ip_header->daddr;

       printf("\t\t\n IP header: \n");
       printf("\tIP Version: %u\n",(u32)ip_header->version);
       printf("\tIP header length: %u bytes\n",ipheader_len);
       printf("\tType Of Service: %u\n",ip_header->tos);
       printf("\tIP Total length: %u\n",ntohs(ip_header->tot_len));
       printf("\tIdentification: %u\n",ntohs(ip_header->id));
       printf("\tFlags + frag offset: 0x%04x\n",ntohs(ip_header->frag_off));
       printf("\tTTL: %u\n",ip_header->ttl);
       printf("\tProtocol: %u\n",ip_header->protocol);
       printf("\tHeader checksum: 0x%04x\n",ntohs(ip_header->check));
       printf("\tSource IP: %s\n",inet_ntoa(src_ip));
       printf("\tDestination IP: %s\n",inet_ntoa(dst_ip));

}




void hexadump(void *buff,u16 size){
     const u8 *p=(const u8 *)buff;
     size_t i,j;
     
     for(i=0;i<size;i++){
         
         if((i%16)==0){
             printf("%08lx ",i);
            }
            
            if(i % 8==0 && i!=0){
                printf(" ");
            }
         

            printf(" %02x",p[i]);
            

         if((i%16)==15 || i==(size_t)size-1){
            for(j=0;j<15-(i%16);j++){
               printf(" ");
            }
            printf(" | ");
             for(j=(i-(i%16));j<=i;j++){
                if(IS_PRINTABLE_ASCII(p[j])){
                    printf("%c",p[j]);
                }else{
                    printf(".");
                }
             }
             printf("\n");

         }

     }
     printf("\n");
}