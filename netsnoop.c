#include "netsnoop.h"
#include "queue.h"
#include <pthread.h>


FILE *logfile;
volatile sig_atomic_t keep_sniffing=1;                                                                                                                                                        

void handle_signal(__attribute__((unused)) i32 sig){
      keep_sniffing=0;
}


void set_signal_handler(void){
     struct sigaction sa;
     sa.sa_handler=handle_signal;
     sigemptyset(&sa.sa_mask);
     sa.sa_flags = 0;
}

void error(bool with_exit,const i8* error_message){
    if(with_exit){
       fprintf(stderr,RED"%s:(%s)\n"RESET,error_message,strerror(errno));
       exit(EXIT_FAILURE);

    }

    fprintf(stderr,RED"%s:(%s)\n"RESET,error_message,strerror(errno));
   

}


/*
   This will be thr producer
   Take a packet from the main capturing loop ,push it to the packets buffer

*/


queue *q;

pthread_mutex_t qMutex;
pthread_cond_t qCond;



void *process_packets(void *arg){

     Options *options=(Options *)arg;
     
      while(true){

         while(empty(q)){
            pthread_cond_wait(&qCond,&qMutex);
         }

         packet *_packet_=pop(q);
         
         ssize_t received_bytes=_packet_->received_bytes;
      
         process_packet(_packet_->buffer,received_bytes,options);

      }
       

}





void *capture_packets(void *arg){
 

   Options *options=(Options *)arg;

    
   q=malloc(sizeof(queue));
   memset(q,0,sizeof(queue));
   
   logfile=fopen("log.txt","w");
    
   if(!logfile){
      error(true,"Failed to create the log file");
   }
                     
   //a socket that will sniff on all interfaces ,and all protocals
   i32 socket_fd=socket(PACKETS,SOCK_RAW,htons(ALL_INTERFACES));

   if(socket_fd<0){
       error(true,"Failed to create a raw socket");
   }

   //bind this raw socket to a specific interface

   struct sockaddr_ll sll={0};

   sll.sll_family=AF_PACKET;
   sll.sll_protocol=htons(ALL_INTERFACES);

   int index = if_nametoindex(options->interface);
   if (index == 0) {
        error(false,"if_nametoindex");
        exit(1);
      }

   sll.sll_ifindex = index;

   if(bind(socket_fd,(struct sockaddr *)&sll,sizeof(sll))<0){
       error(true,"Failed to bind");
   }

   i8 *packet_buffer=malloc(BUFFER_SIZE);

   if(!packet_buffer){
       error(true,"Failed to allocate memory for the packet buffer");
   }

  
   set_signal_handler();
   
   ssize_t  received_bytes;
   SA saddr;
   socklen_t addr_size;
   printf(WHITE"\nNetSnoop is Listening on all interfaces (press ctrl+c to stop)\n"RESET);
   while(keep_sniffing){
      /* 
        receive the packet ,process it 
      */
      
      addr_size=sizeof(saddr);
      received_bytes=recvfrom(socket_fd,packet_buffer,BUFFER_SIZE,0,&saddr,&addr_size);
     
      if(received_bytes<0){
         if(errno==EINTR) continue;
           error(false,"Error receiving packet");
      }

       pthread_mutex_lock(&qMutex);
       
       while(full(q)){
            pthread_cond_wait(&qCond,&qMutex);
       }

       packet *_packet=malloc(sizeof(packet));
       _packet->buffer=packet_buffer;
       _packet->received_bytes=received_bytes;
      
       if(push(q,_packet)){
            pthread_cond_signal(&qCond);
         
       }else{
          fprintf(stderr,"Failed to add buffer to the q\n");
       }


       pthread_mutex_unlock(&qMutex);

      
       
      
   }



   fflush(logfile);

   fclose(logfile);
   free(packet_buffer);
   close(socket_fd);


    return NULL;

}



void start_threads(Options *options){

     


       pthread_mutex_init(&qMutex,NULL);
       pthread_cond_init(&qCond,NULL);
      
      pthread_t threads[NUM_OF_THREADS];
      for (i32 i=0;i<NUM_OF_THREADS;i++){
            
           if(i==0){
               pthread_create(&threads[i],NULL,&capture_packets,options);
           }else{
              
            pthread_create(&threads[i],NULL,&process_packets,options);
                
           }
      }



   pthread_mutex_destroy(&qMutex);
   pthread_cond_destroy(&qCond);
}




void process_packet(i8 *data,ssize_t data_size,Options *options){
      /*
        Extract the ip header from the received data and take action accordiing to the protocal type i.e icmp
      */
   
      if(data_size<(ssize_t)(ETHERNET_HEADER_SIZE + sizeof(IP))){
         fprintf(logfile, "%s Packet too small to contain Ethernet+IP headers (%zd bytes)\n", get_timestamp(), data_size);
         fflush(logfile);
          return;
      }

      IP *ip_header=(IP *)(data+ETHERNET_HEADER_SIZE);
      
      u16 ip_header_len=ip_header->ihl*4;

      if(ip_header->ihl<5){
          return;
      }


      if(data_size < (ssize_t)(ETHERNET_HEADER_SIZE + ip_header_len)){
         fprintf(logfile, "%s Packet truncated (not enough data for full IP header): %zd < %zu\n",
                 get_timestamp(), data_size, (size_t)(ETHERNET_HEADER_SIZE + ip_header_len));
                 fflush(logfile);
                 return;
         }


      
      
      if(options->proto==NONE){         
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
      }else{
          switch(options->proto){
               case icmp:
                     if(ip_header->protocol==PROTO_ICMP){

                        showicmp(data,data_size);
                     }
                     break;
               case tcp:
                     if(ip_header->protocol==PROTO_TCP){

                        showtcp(data,data_size);
                     }
                     break;
               case udp:
                     if(ip_header->protocol==PROTO_UDP){
                        showudp(data,data_size);
                     }
                     break;

               case NONE:
               case proto_unknown:

               default:
                     break;
               
         
          }
          
      }
      
}


void showicmp(i8 *data,ssize_t data_size){
   
   IP *ip_header=(IP *)(data+ETHERNET_HEADER_SIZE);
   u16 ip_header_len=ip_header->ihl*4;

   size_t offset=ETHERNET_HEADER_SIZE+ip_header_len;

   if(data_size<(ssize_t)(offset+sizeof(ICMP))){
      fprintf(logfile, "%s Truncated ICMP packet\n", get_timestamp());
      fflush(logfile);
      return;
   }

   ICMP *icmp=(ICMP *)(data+ETHERNET_HEADER_SIZE+ip_header_len);
  
   fprintf(logfile, "%s Captured ICMP Packet\n", get_timestamp());
   fprintf(logfile,"\t\n\n*************************************ICMP Packet*************************************\n");
   
   src_dst_ip *ips=showipheader(ip_header);

   char src_ip_str[INET_ADDRSTRLEN];
   char dst_ip_str[INET_ADDRSTRLEN];
   
   inet_ntop(AF_INET, &ips->src, src_ip_str, INET_ADDRSTRLEN);
   inet_ntop(AF_INET, &ips->dst, dst_ip_str, INET_ADDRSTRLEN);
   free(ips);

   printf("\n\n");
   printf(WHITE"%s From %s ,To %s  ICMP packet\n"RESET,get_timestamp(),src_ip_str,dst_ip_str);
   // sleep(1);
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
   
   u8 *payload=(u8 *)(data+offset+sizeof(ICMP));
   ssize_t payload_size=data_size-(offset+sizeof(ICMP));

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


   size_t offset=ETHERNET_HEADER_SIZE+ip_header_len;

   if(data_size<(ssize_t)(offset+sizeof(UDP))){
      fprintf(logfile, "%s Truncated UDP packet\n", get_timestamp());
      fflush(logfile);
      return;
   }

   UDP *udp_header=(UDP *)(data+ETHERNET_HEADER_SIZE+ip_header_len);
   
   fprintf(logfile, "%s Captured UDP Packet\n", get_timestamp());
   fprintf(logfile,"\t\n\n*************************************UDP Packet*************************************\n");
    src_dst_ip *ips=showipheader(ip_header);

    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &ips->src, src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ips->dst, dst_ip_str, INET_ADDRSTRLEN);
    free(ips);

    printf("\n\n");

    printf(WHITE"%s From %s on Port %u,To %s  on Port %u UDP packet\n"RESET,get_timestamp(),src_ip_str,ntohs(udp_header->uh_sport),dst_ip_str,ntohs(udp_header->uh_dport));
   //  sleep(1);
   fprintf(logfile,"\t\t\nUDP Header \n");

   fprintf(logfile,"\tSource Port: %u\n",ntohs(udp_header->uh_sport));
   fprintf(logfile,"\tDestination Port: %u\n",ntohs(udp_header->uh_dport));
   fprintf(logfile,"\tUDP length: %u\n",ntohs(udp_header->len));
   fprintf(logfile,"\tUDP Checksum: 0x%04x\n",ntohs(udp_header->check));

   u8 *payload=(u8 *)(data+offset+sizeof(UDP));
   ssize_t payload_size=data_size-(offset+sizeof(UDP));

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

   size_t offset=ETHERNET_HEADER_SIZE+ip_header_len;

   if(data_size<(ssize_t)(offset+sizeof(TCP))){
      fprintf(logfile, "%s Truncated TCP packet (no base tcp header)\n", get_timestamp());
      fflush(logfile);
      return;
   }

   //NOTE that tcphdr might show some squiggles on some systems but it compiles fine ,nothing to worry about
   TCP *tcp_header=(TCP *)(data+ETHERNET_HEADER_SIZE+ip_header_len);
   /*
      A TCP header must have atleast 5 (20 bytes) of size
   */
   
   u16 tcp_header_len=(tcp_header->doff)*4;

   if(tcp_header->doff<5){
      fprintf(logfile, "%s Invalid TCP header length (doff=%u)\n", get_timestamp(), (unsigned)tcp_header->doff);
      fflush(logfile);
      return;
   }




   if(data_size<(ssize_t)(offset+tcp_header_len)){
      fprintf(logfile, "%s Truncated TCP packet (not enough bytes for options): %zd < %zu\n",
      get_timestamp(), data_size, (size_t)(offset + tcp_header_len));
      fflush(logfile);
      return;
   }

   fprintf(logfile, "%s Captured TCP Packet\n", get_timestamp());
   fprintf(logfile,"\t\n\n*************************************TCP Packet*************************************\n");
    src_dst_ip *ips=showipheader(ip_header);

    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &ips->src, src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ips->dst, dst_ip_str, INET_ADDRSTRLEN);
    
    free(ips);

    printf("\n\n");
    printf(WHITE"%s From %s on Port %u,To %s  on Port %u TCP packet\n"RESET,get_timestamp(),src_ip_str,ntohs(tcp_header->source),dst_ip_str,ntohs(tcp_header->dest));

   //  sleep(1);
    
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

   u8 *payload=(u8 *)(data+offset+tcp_header_len);
   ssize_t payload_size=data_size-(offset+tcp_header_len);

   if(payload_size>0){
       fprintf(logfile,"\t\t\tPayload (%zd): \n",payload_size);
       hexdump(payload,payload_size);
       
   }else{

      fprintf(logfile,"\t\t\tNo TCP payload\n");
   }

   fprintf(logfile,"\t\n\n##############################################################################\n");

}



src_dst_ip *showipheader(IP *ip_header){
    
       u16 ipheader_len=ip_header->ihl*4;
       
       struct in_addr src_ip,dst_ip;

       src_ip.s_addr=ip_header->saddr;
       dst_ip.s_addr=ip_header->daddr;

       src_dst_ip *ips=malloc(sizeof(src_dst_ip));

       if(!ips){
           error(true,"cannot allocate memory for source and destination ips");
       }

       ips->dst.s_addr=dst_ip.s_addr;
       ips->src.s_addr=src_ip.s_addr;

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

       return ips;

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