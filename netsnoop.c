#include "netsnoop.h"

FILE *logfile;
volatile sig_atomic_t keep_sniffing=1;

void handle_signal(__attribute__((unused)) i32 sig){
      keep_sniffing=0;
}

void error(bool with_exit,const i8* error_message){
    if(with_exit){
       fprintf(stderr,RED"%s:(%s)\n"RESET,error_message,strerror(errno));
       exit(EXIT_FAILURE);

    }

    fprintf(stderr,RED"%s:(%s)\n"RESET,error_message,strerror(errno));
   

}

void capture_packets(){

   logfile=fopen("log.txt","w");
    
   if(!logfile){
      error(true,"Failed to create the log file");
   }
  
   //a socket that will sniff on all interfaces ,and all protocals
   i32 socket_fd=socket(PACKETS,SOCK_RAW,htons(ALL_INTERFACES));

   if(socket_fd<0){
       error(true,"Failed to create a raw socket");
   }

   i8 *packet_buffer=malloc(BUFFER_SIZE);

   if(!packet_buffer){
       error(true,"Failed to allocate memory for the packet buffer");
   }

   signal(SIGINT,handle_signal);

   ssize_t  received_bytes;
   SA saddr;
   socklen_t addr_size;
   printf(WHITE"\nNetSnoop is Listening on all interfaces\n"RESET);
   while(keep_sniffing){
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
      switch(ip_header->protocol){
          case PROTO_ICMP:
            showicmp(data,data_size);
            break;
          case PROTO_UDP:
             showudp(data,data_size);
             break;
          case PROTO_TCP:
            showtcp(data,data_size);
            break;
          default:
            break;
      }


}


void showicmp(i8 *data,ssize_t data_size){
   
   IP *ip_header=(IP *)(data+ETHERNET_HEADER_SIZE);
   u16 ipheader_len=ip_header->ihl*4;

   ICMP *icmp=(ICMP *)(data+ETHERNET_HEADER_SIZE+ipheader_len);

   fprintf(logfile, "%s Captured ICMP Packet\n", get_timestamp());
   fprintf(logfile,"\t\n\n*************************************ICMP Packet*************************************\n");
   showipheader(ip_header);
   fprintf(logfile,"\t\t\nICMP Header \n");
   fprintf(logfile,"\tType: %d",icmp->type);
   
   switch(icmp->type){
      case 0:  fprintf(logfile," (Echo Reply)\n"); break;
      case 3:  fprintf(logfile," (Destination Unreachable)\n"); break;
      case 8:  fprintf(logfile," (Echo Request)\n"); break;
      case 11: fprintf(logfile," (Time Exceeded)\n"); break;
      case 13: fprintf(logfile," (Timestamp Request)\n"); break;
      case 14: fprintf(logfile," (Timestamp Reply)\n"); break;
      default: fprintf(logfile,"\n"); break;

   }

   fprintf(logfile,"\tCode: %d\n", icmp->code);
   fprintf(logfile,"\tChecksum: 0x%04x\n", ntohs(icmp->checksum));
   
   if(icmp->type==8 || icmp->type==0){
      fprintf(logfile,"\tID: %u\n",ntohs(icmp->un.echo.id));
      fprintf(logfile,"\tSequence: %u\n",ntohs(icmp->un.echo.sequence));
   }
   
   u8 *payload=(u8 *)(data+ETHERNET_HEADER_SIZE+ipheader_len+sizeof(ICMP));
   ssize_t payload_size=data_size-(ETHERNET_HEADER_SIZE+ipheader_len+sizeof(ICMP));

   if(payload_size>0){
       fprintf(logfile,"\tPayload (%zd): \n",payload_size);
       hexdump(payload,payload_size);


   }else{

      fprintf(logfile,"\t\t\tNo ICMP payload\n");
   }

   fprintf(logfile,"\t\n\n##############################################################################\n");

}


void showudp(i8 *data,ssize_t data_size){

   IP *ip_header=(IP *)(data+ETHERNET_HEADER_SIZE);
   u16 ip_header_len=ip_header->ihl*4;

   UDP *udp_header=(UDP *)(data+ETHERNET_HEADER_SIZE+ip_header_len);
   
   fprintf(logfile, "%s Captured UDP Packet\n", get_timestamp());
   fprintf(logfile,"\t\n\n*************************************UDP Packet*************************************\n");
   showipheader(ip_header);
   fprintf(logfile,"\t\t\nUDP Header \n");

   fprintf(logfile,"\tSource Port: %u\n",ntohs(udp_header->uh_sport));
   fprintf(logfile,"\tDestination Port: %u\n",ntohs(udp_header->uh_dport));
   fprintf(logfile,"\tUDP length: %u\n",ntohs(udp_header->len));
   fprintf(logfile,"\tUDP Checksum: 0x%04x\n",ntohs(udp_header->check));

   u8 *payload=(u8 *)(data+ETHERNET_HEADER_SIZE+ip_header_len+sizeof(UDP));
   ssize_t payload_size=data_size-(ETHERNET_HEADER_SIZE+ip_header_len+sizeof(UDP));

   if(payload_size>0){
       fprintf(logfile,"\tPayload (%zd): \n",payload_size);
       hexdump(payload,payload_size);


   }else{

      fprintf(logfile,"\t\t\tNo UDP payload\n");
   }

   fprintf(logfile,"\t\n\n##############################################################################\n");

}


void showtcp(i8 *data,ssize_t data_size){
   IP *ip_header=(IP *)(data+ETHERNET_HEADER_SIZE);
   u16 ip_header_len=ip_header->ihl*4;
   //NOTE that tcphdr might show some squiggles on some systems but it compiles fine ,nothing to worry about
   TCP *tcp_header=(TCP *)(data+ETHERNET_HEADER_SIZE+ip_header_len);
   
   fprintf(logfile, "%s Captured TCP Packet\n", get_timestamp());
   fprintf(logfile,"\t\n\n*************************************TCP Packet*************************************\n");
   showipheader(ip_header);
   fprintf(logfile,"\t\t\nTCP Header \n");


   fprintf(logfile,"\t\t\tSource Port: %u\n",ntohs(tcp_header->source));
   fprintf(logfile,"\t\t\tDestination Port: %u\n",ntohs(tcp_header->dest));
   fprintf(logfile,"\t\t\tSequence Number: %u\n",ntohl(tcp_header->seq));
   fprintf(logfile,"\t\t\tAcknowledge Number: %u\n",ntohl(tcp_header->ack_seq));
   fprintf(logfile,"\t\t\tHeader Length: %u\n",tcp_header->doff*4);
   fprintf(logfile,"\t\t\tUrgent Flag          : %d\n",(unsigned int)tcp_header->urg);
	fprintf(logfile,"\t\t\tAcknowledgement Flag : %d\n",(unsigned int)tcp_header->ack);
	fprintf(logfile,"\t\t\tPush Flag            : %d\n",(unsigned int)tcp_header->psh);
	fprintf(logfile,"\t\t\tReset Flag           : %d\n",(unsigned int)tcp_header->rst);
	fprintf(logfile,"\t\t\tSynchronise Flag     : %d\n",(unsigned int)tcp_header->syn);
	fprintf(logfile,"\t\t\tFinish Flag          : %d\n",(unsigned int)tcp_header->fin);
	fprintf(logfile,"\t\t\tWindow         : %d\n",ntohs(tcp_header->window));
	fprintf(logfile,"\t\t\tChecksum       : %d\n",ntohs(tcp_header->check));
	fprintf(logfile,"\t\t\tUrgent Pointer : %d\n",tcp_header->urg_ptr);

   u8 *payload=(u8 *)(data+ETHERNET_HEADER_SIZE+ip_header_len+sizeof(TCP));
   ssize_t payload_size=data_size-(ETHERNET_HEADER_SIZE+ip_header_len+sizeof(TCP));

   if(payload_size>0){
       fprintf(logfile,"\t\t\tPayload (%zd): \n",payload_size);
       hexdump(payload,payload_size);
       
   }else{

      fprintf(logfile,"\t\t\tNo TCP payload\n");
   }

   fprintf(logfile,"\t\n\n##############################################################################\n");

}



void showipheader(IP *ip_header){
      // IP *ip_header=(IP *)(data+ETHERNET_HEADER_SIZE);
       u16 ipheader_len=ip_header->ihl*4;
       
       struct in_addr src_ip,dst_ip;

       src_ip.s_addr=ip_header->saddr;
       dst_ip.s_addr=ip_header->daddr;

       fprintf(logfile,"\t\t\t\n IP header: \n\n");
       fprintf(logfile,"\tIP Version: %u\n",(u32)ip_header->version);
       fprintf(logfile,"\tIP header length: %u bytes\n",ipheader_len);
       fprintf(logfile,"\tType Of Service: %u\n",ip_header->tos);
       fprintf(logfile,"\tIP Total length: %u\n",ntohs(ip_header->tot_len));
       fprintf(logfile,"\tIdentification: %u\n",ntohs(ip_header->id));
       fprintf(logfile,"\tFlags + frag offset: 0x%04x\n",ntohs(ip_header->frag_off));
       fprintf(logfile,"\tTTL: %u\n",ip_header->ttl);
       fprintf(logfile,"\tProtocol: %u\n",ip_header->protocol);
       fprintf(logfile,"\tHeader checksum: 0x%04x\n",ntohs(ip_header->check));
       fprintf(logfile,"\tSource IP: %s\n",inet_ntoa(src_ip));
       fprintf(logfile,"\tDestination IP: %s\n",inet_ntoa(dst_ip));

}


void hexdump(void *buff,u16 size){
     const u8 *p=(const u8 *)buff;
     size_t i,j;
     fprintf(logfile,"\t\t\t\t\t\t");
     for(i=0;i<size;i++){
         
         if((i%16)==0){
             fprintf(logfile,"%08lx ",i);
            }
            
            if(i % 8==0 && i!=0){
                fprintf(logfile," ");
            }
         

            fprintf(logfile," %02x",p[i]);
            

         if((i%16)==15 || i==(size_t)size-1){
            for(j=0;j<15-(i%16);j++){
               fprintf(logfile," ");
            }
            fprintf(logfile," | ");
             for(j=(i-(i%16));j<=i;j++){
                if(IS_PRINTABLE_ASCII(p[j])){
                    fprintf(logfile,"%c",p[j]);
                }else{
                    fprintf(logfile,".");
                }
             }
             fprintf(logfile,"\n\t\t\t\t\t\t");
         }

     }
     fprintf(logfile,"\n");
}


const char* get_timestamp() {
   static char buffer[64];
   time_t now = time(NULL);
   struct tm *tm_info = localtime(&now);
   strftime(buffer, sizeof(buffer), "[%Y-%m-%d %H:%M:%S]", tm_info);
   return buffer;
}