#include "netsnoop.h"
#include "queue.h"
#include <pthread.h>


FILE *udp_logfile;
FILE *icmp_logfile;
FILE *tcp_logfile;

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
pthread_cond_t qEmptyCond;
pthread_cond_t qFullCond;



void *process_packets(void *arg){

     Options *options=(Options *)arg;
     
      while(true){

         pthread_mutex_lock(&qMutex);

         while(empty(q)){
            pthread_cond_wait(&qFullCond,&qMutex);
         }

         packet *_packet_=pop(q);
         pthread_mutex_unlock(&qMutex);
         pthread_cond_signal(&qEmptyCond);
         
         ssize_t received_bytes=_packet_->received_bytes;
      
         process_packet(_packet_->buffer,received_bytes,options);

      }
       

}



void *capture_packets(void *arg){
 

   Options *options=(Options *)arg;

    
   
   

 
                     
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


  
   set_signal_handler();
   
   ssize_t  received_bytes;
   SA saddr;
   socklen_t addr_size;
   printf(WHITE"\nNetSnoop is Listening on all interfaces (press ctrl+c to stop)\n"RESET);
   while(keep_sniffing){
      /* 
        receive the packet ,process it 
      */


   i8 *packet_buffer=malloc(BUFFER_SIZE);

   if(!packet_buffer){
       error(true,"Failed to allocate memory for the packet buffer");
   }
      
      addr_size=sizeof(saddr);
      received_bytes=recvfrom(socket_fd,packet_buffer,BUFFER_SIZE,0,&saddr,&addr_size);
     
      if(received_bytes<0){
         if(errno==EINTR) continue;
           error(false,"Error receiving packet");
      }

       pthread_mutex_lock(&qMutex);
       
       while(full(q)){
            pthread_cond_wait(&qEmptyCond,&qMutex);
       }

       packet *_packet=malloc(sizeof(packet));
       _packet->buffer=malloc(received_bytes);
       memcpy(_packet->buffer,packet_buffer,received_bytes);
       _packet->received_bytes=received_bytes;

       free(packet_buffer);

         pthread_mutex_unlock(&qMutex);
      
       if(push(q,_packet)){
            pthread_cond_signal(&qFullCond);
         
       }else{
          fprintf(stderr,"Failed to add buffer to the q\n");
       }


    

      
       
      
   }




   close(socket_fd);


    return NULL;

}



void start_threads(Options *options){

     

   icmp_logfile=fopen("icmp_log.txt","w");
   tcp_logfile=fopen("tcp_log.txt","w");
   udp_logfile=fopen("udp_log.txt","w");
    
   if(!tcp_logfile || !icmp_logfile || !udp_logfile){
      error(true,"Failed to create the log file");
      }


      q=malloc(sizeof(queue));
      initialize_queue(q);
      pthread_mutex_init(&qMutex,NULL);
      pthread_cond_init(&qEmptyCond,NULL);
      pthread_cond_init(&qFullCond,NULL);

      
      pthread_t threads[NUM_OF_THREADS];
      for (i32 i=0;i<NUM_OF_THREADS;i++){
            
           if(i==0){
               pthread_create(&threads[i],NULL,&capture_packets,options);
           }else{
              
            pthread_create(&threads[i],NULL,&process_packets,options);
                
           }
      }


      for(i32 i=0;i<NUM_OF_THREADS;i++){
           pthread_join(threads[i],NULL);
      }


   pthread_mutex_destroy(&qMutex);
   pthread_cond_destroy(&qEmptyCond);
   pthread_cond_destroy(&qFullCond);


   fflush(icmp_logfile);
   fflush(tcp_logfile);
   fflush(udp_logfile);

   fclose(icmp_logfile);
   fclose(udp_logfile);
   fclose(tcp_logfile);

}




void process_packet(i8 *data,ssize_t data_size,Options *options){
      /*
        Extract the ip header from the received data and take action accordiing to the protocal type i.e icmp
      */

      IP *ip_header=(IP *)(data+ETHERNET_HEADER_SIZE);
   
      if(data_size<(ssize_t)(ETHERNET_HEADER_SIZE + sizeof(IP))){
          switch(ip_header->protocol){
               case PROTO_ICMP:
                     fprintf(icmp_logfile, "%s Packet too small to contain Ethernet+IP headers (%zd bytes)\n", get_timestamp(), data_size);
                     fflush(icmp_logfile);
                     break;
               case PROTO_TCP:
                     fprintf(tcp_logfile, "%s Packet too small to contain Ethernet+IP headers (%zd bytes)\n", get_timestamp(), data_size);
                     fflush(tcp_logfile);
                     break;
               case PROTO_UDP:
                      fprintf(udp_logfile, "%s Packet too small to contain Ethernet+IP headers (%zd bytes)\n", get_timestamp(), data_size);
                     fflush(udp_logfile);
               break;
          }

          return;
      }

      
      
      u16 ip_header_len=ip_header->ihl*4;

      if(ip_header->ihl<5){
          return;
      }


      if(data_size < (ssize_t)(ETHERNET_HEADER_SIZE + ip_header_len)){
         switch(ip_header->protocol){
               case PROTO_ICMP:
                     fprintf(icmp_logfile, "%s Packet truncated (not enough data for full IP header): %zd < %zu\n",
                     get_timestamp(), data_size, (size_t)(ETHERNET_HEADER_SIZE + ip_header_len));
                     fflush(icmp_logfile);
                     return;
               break;
               case PROTO_TCP:
                     fprintf(tcp_logfile, "%s Packet truncated (not enough data for full IP header): %zd < %zu\n",
                     get_timestamp(), data_size, (size_t)(ETHERNET_HEADER_SIZE + ip_header_len));
                     fflush(tcp_logfile);
                     return;
               break;
               case PROTO_UDP:
                     fprintf(udp_logfile, "%s Packet truncated (not enough data for full IP header): %zd < %zu\n",
                     get_timestamp(), data_size, (size_t)(ETHERNET_HEADER_SIZE + ip_header_len));
                     fflush(udp_logfile);
                     return;
               break;
         }
    
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
      fprintf(icmp_logfile, "%s Truncated ICMP packet\n", get_timestamp());
      fflush(icmp_logfile);
      return;
   }

   ICMP *icmp=(ICMP *)(data+ETHERNET_HEADER_SIZE+ip_header_len);
  
   fprintf(icmp_logfile, "%s Captured ICMP Packet\n", get_timestamp());
   fprintf(icmp_logfile,"\t\n\n*************************************ICMP Packet*************************************\n");
   
   src_dst_ip *ips=showipheader(ip_header);

   char src_ip_str[INET_ADDRSTRLEN];
   char dst_ip_str[INET_ADDRSTRLEN];
   
   inet_ntop(AF_INET, &ips->src, src_ip_str, INET_ADDRSTRLEN);
   inet_ntop(AF_INET, &ips->dst, dst_ip_str, INET_ADDRSTRLEN);
   free(ips);

   printf("\n\n");
   printf(WHITE"%s From %s ,To %s  ICMP packet\n"RESET,get_timestamp(),src_ip_str,dst_ip_str);
   // sleep(1);
   fprintf(icmp_logfile,"\t\t\nICMP Header \n");
   fprintf(icmp_logfile,"\tType: %d",icmp->type);
   
   switch(icmp->type){
      case 0:  fprintf(icmp_logfile," (Echo Reply)\n"); break;
      case 3:  fprintf(icmp_logfile," (Destination Unreachable)\n"); break;
      case 8:  fprintf(icmp_logfile," (Echo Request)\n"); break;
      case 11: fprintf(icmp_logfile," (Time Exceeded)\n"); break;
      case 13: fprintf(icmp_logfile," (Timestamp Request)\n"); break;
      case 14: fprintf(icmp_logfile," (Timestamp Reply)\n"); break;
      default: fprintf(icmp_logfile,"\n"); break;
  
   }


   fprintf(icmp_logfile,"\tCode: %d\n", icmp->code);
   fprintf(icmp_logfile,"\tChecksum: 0x%04x\n", ntohs(icmp->checksum));
   
   if(icmp->type==8 || icmp->type==0){
      fprintf(icmp_logfile,"\tID: %u\n",ntohs(icmp->un.echo.id));
      fprintf(icmp_logfile,"\tSequence: %u\n",ntohs(icmp->un.echo.sequence));
   }
   
   u8 *payload=(u8 *)(data+offset+sizeof(ICMP));
   ssize_t payload_size=data_size-(offset+sizeof(ICMP));

   if(payload_size>0){
       fprintf(icmp_logfile,"\tPayload (%zd): \n",payload_size);
       hexdump(payload,payload_size,ip_header);


   }else{

      fprintf(icmp_logfile,"\t\t\tNo ICMP payload\n");
   }

   fprintf(icmp_logfile,"\t\n\n##############################################################################\n");



}

void showudp(i8 *data,ssize_t data_size){

   IP *ip_header=(IP *)(data+ETHERNET_HEADER_SIZE);
   u16 ip_header_len=ip_header->ihl*4;


   size_t offset=ETHERNET_HEADER_SIZE+ip_header_len;

   if(data_size<(ssize_t)(offset+sizeof(UDP))){
      fprintf(udp_logfile, "%s Truncated UDP packet\n", get_timestamp());
      fflush(udp_logfile);
      return;
   }

   UDP *udp_header=(UDP *)(data+ETHERNET_HEADER_SIZE+ip_header_len);
   
   fprintf(udp_logfile, "%s Captured UDP Packet\n", get_timestamp());
   fprintf(udp_logfile,"\t\n\n*************************************UDP Packet*************************************\n");
    src_dst_ip *ips=showipheader(ip_header);

    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &ips->src, src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ips->dst, dst_ip_str, INET_ADDRSTRLEN);
    free(ips);

    printf("\n\n");

    printf(WHITE"%s From %s on Port %u,To %s  on Port %u UDP packet\n"RESET,get_timestamp(),src_ip_str,ntohs(udp_header->uh_sport),dst_ip_str,ntohs(udp_header->uh_dport));
   //  sleep(1);
   fprintf(udp_logfile,"\t\t\nUDP Header \n");

   fprintf(udp_logfile,"\tSource Port: %u\n",ntohs(udp_header->uh_sport));
   fprintf(udp_logfile,"\tDestination Port: %u\n",ntohs(udp_header->uh_dport));
   fprintf(udp_logfile,"\tUDP length: %u\n",ntohs(udp_header->len));
   fprintf(udp_logfile,"\tUDP Checksum: 0x%04x\n",ntohs(udp_header->check));

   u8 *payload=(u8 *)(data+offset+sizeof(UDP));
   ssize_t payload_size=data_size-(offset+sizeof(UDP));

   if(payload_size>0){
       fprintf(udp_logfile,"\tPayload (%zd): \n",payload_size);
       hexdump(payload,payload_size,ip_header);


   }else{

      fprintf(udp_logfile,"\t\t\tNo UDP payload\n");
   }

   fprintf(udp_logfile,"\t\n\n##############################################################################\n");

}


void showtcp(i8 *data,ssize_t data_size){
   IP *ip_header=(IP *)(data+ETHERNET_HEADER_SIZE);
   u16 ip_header_len=ip_header->ihl*4;

   size_t offset=ETHERNET_HEADER_SIZE+ip_header_len;

   if(data_size<(ssize_t)(offset+sizeof(TCP))){
      fprintf(tcp_logfile, "%s Truncated TCP packet (no base tcp header)\n", get_timestamp());
      fflush(tcp_logfile);
      return;
   }

   //NOTE that tcphdr might show some squiggles on some systems but it compiles fine ,nothing to worry about
   TCP *tcp_header=(TCP *)(data+ETHERNET_HEADER_SIZE+ip_header_len);
   /*
      A TCP header must have atleast 5 (20 bytes) of size
   */
   
   u16 tcp_header_len=(tcp_header->doff)*4;

   if(tcp_header->doff<5){
      fprintf(tcp_logfile, "%s Invalid TCP header length (doff=%u)\n", get_timestamp(), (unsigned)tcp_header->doff);
      fflush(tcp_logfile);
      return;
   }
     fprintf(tcp_logfile, "%s Packet truncated (not enough data for full IP header): %zd < %zu\n",
                 get_timestamp(), data_size, (size_t)(ETHERNET_HEADER_SIZE + ip_header_len));
                 fflush(tcp_logfile);
                 return;



   if(data_size<(ssize_t)(offset+tcp_header_len)){
      fprintf(tcp_logfile, "%s Truncated TCP packet (not enough bytes for options): %zd < %zu\n",
      get_timestamp(), data_size, (size_t)(offset + tcp_header_len));
      fflush(tcp_logfile);
      return;
   }

   fprintf(tcp_logfile, "%s Captured TCP Packet\n", get_timestamp());
   fprintf(tcp_logfile,"\t\n\n*************************************TCP Packet*************************************\n");
    src_dst_ip *ips=showipheader(ip_header);

    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &ips->src, src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ips->dst, dst_ip_str, INET_ADDRSTRLEN);
    
    free(ips);

    printf("\n\n");
    printf(WHITE"%s From %s on Port %u,To %s  on Port %u TCP packet\n"RESET,get_timestamp(),src_ip_str,ntohs(tcp_header->source),dst_ip_str,ntohs(tcp_header->dest));

   //  sleep(1);
    
   fprintf(tcp_logfile,"\t\t\nTCP Header \n");
   

   fprintf(tcp_logfile,"\t\t\tSource Port: %u\n",ntohs(tcp_header->source));
   fprintf(tcp_logfile,"\t\t\tDestination Port: %u\n",ntohs(tcp_header->dest));
   fprintf(tcp_logfile,"\t\t\tSequence Number: %u\n",ntohl(tcp_header->seq));
   fprintf(tcp_logfile,"\t\t\tAcknowledge Number: %u\n",ntohl(tcp_header->ack_seq));
   fprintf(tcp_logfile,"\t\t\tHeader Length: %u\n",tcp_header->doff*4);
   fprintf(tcp_logfile,"\t\t\tUrgent Flag          : %d\n",(unsigned int)tcp_header->urg);
	fprintf(tcp_logfile,"\t\t\tAcknowledgement Flag : %d\n",(unsigned int)tcp_header->ack);
	fprintf(tcp_logfile,"\t\t\tPush Flag            : %d\n",(unsigned int)tcp_header->psh);
	fprintf(tcp_logfile,"\t\t\tReset Flag           : %d\n",(unsigned int)tcp_header->rst);
	fprintf(tcp_logfile,"\t\t\tSynchronise Flag     : %d\n",(unsigned int)tcp_header->syn);
	fprintf(tcp_logfile,"\t\t\tFinish Flag          : %d\n",(unsigned int)tcp_header->fin);
	fprintf(tcp_logfile,"\t\t\tWindow         : %d\n",ntohs(tcp_header->window));
	fprintf(tcp_logfile,"\t\t\tChecksum       : %d\n",ntohs(tcp_header->check));
	fprintf(tcp_logfile,"\t\t\tUrgent Pointer : %d\n",tcp_header->urg_ptr);

   u8 *payload=(u8 *)(data+offset+tcp_header_len);
   ssize_t payload_size=data_size-(offset+tcp_header_len);

   if(payload_size>0){
       fprintf(tcp_logfile,"\t\t\tPayload (%zd): \n",payload_size);
       hexdump(payload,payload_size,ip_header);
       
   }else{

      fprintf(tcp_logfile,"\t\t\tNo TCP payload\n");
   }

   fprintf(tcp_logfile,"\t\n\n##############################################################################\n");

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

       switch(ip_header->protocol){
            case PROTO_ICMP:
                     fprintf(icmp_logfile,"\t\t\t\n IP header: \n\n");
                     fprintf(icmp_logfile,"\tIP Version: %u\n",(u32)ip_header->version);
                     fprintf(icmp_logfile,"\tIP header length: %u bytes\n",ipheader_len);
                     fprintf(icmp_logfile,"\tType Of Service: %u\n",ip_header->tos);
                     fprintf(icmp_logfile,"\tIP Total length: %u\n",ntohs(ip_header->tot_len));
                     fprintf(icmp_logfile,"\tIdentification: %u\n",ntohs(ip_header->id));
                     fprintf(icmp_logfile,"\tFlags + frag offset: 0x%04x\n",ntohs(ip_header->frag_off));
                     fprintf(icmp_logfile,"\tTTL: %u\n",ip_header->ttl);
                     fprintf(icmp_logfile,"\tProtocol: %u\n",ip_header->protocol);
                     fprintf(icmp_logfile,"\tHeader checksum: 0x%04x\n",ntohs(ip_header->check));
                     fprintf(icmp_logfile,"\tSource IP: %s\n",inet_ntoa(src_ip));
                     fprintf(icmp_logfile,"\tDestination IP: %s\n",inet_ntoa(dst_ip));
                     break;
            case PROTO_TCP:
                     fprintf(icmp_logfile,"\t\t\t\n IP header: \n\n");
                     fprintf(tcp_logfile,"\tIP Version: %u\n",(u32)ip_header->version);
                     fprintf(tcp_logfile,"\tIP header length: %u bytes\n",ipheader_len);
                     fprintf(tcp_logfile,"\tType Of Service: %u\n",ip_header->tos);
                     fprintf(tcp_logfile,"\tIP Total length: %u\n",ntohs(ip_header->tot_len));
                     fprintf(tcp_logfile,"\tIdentification: %u\n",ntohs(ip_header->id));
                     fprintf(tcp_logfile,"\tFlags + frag offset: 0x%04x\n",ntohs(ip_header->frag_off));
                     fprintf(tcp_logfile,"\tTTL: %u\n",ip_header->ttl);
                     fprintf(tcp_logfile,"\tProtocol: %u\n",ip_header->protocol);
                     fprintf(tcp_logfile,"\tHeader checksum: 0x%04x\n",ntohs(ip_header->check));
                     fprintf(tcp_logfile,"\tSource IP: %s\n",inet_ntoa(src_ip));
                     fprintf(tcp_logfile,"\tDestination IP: %s\n",inet_ntoa(dst_ip));
                     break;
            case PROTO_UDP:
                     fprintf(udp_logfile,"\t\t\t\n IP header: \n\n");
                     fprintf(udp_logfile,"\tIP Version: %u\n",(u32)ip_header->version);
                     fprintf(udp_logfile,"\tIP header length: %u bytes\n",ipheader_len);
                     fprintf(udp_logfile,"\tType Of Service: %u\n",ip_header->tos);
                     fprintf(udp_logfile,"\tIP Total length: %u\n",ntohs(ip_header->tot_len));
                     fprintf(udp_logfile,"\tIdentification: %u\n",ntohs(ip_header->id));
                     fprintf(udp_logfile,"\tFlags + frag offset: 0x%04x\n",ntohs(ip_header->frag_off));
                     fprintf(udp_logfile,"\tTTL: %u\n",ip_header->ttl);
                     fprintf(udp_logfile,"\tProtocol: %u\n",ip_header->protocol);
                     fprintf(udp_logfile,"\tHeader checksum: 0x%04x\n",ntohs(ip_header->check));
                     fprintf(udp_logfile,"\tSource IP: %s\n",inet_ntoa(src_ip));
                     fprintf(udp_logfile,"\tDestination IP: %s\n",inet_ntoa(dst_ip));
                     break;
       }



       return ips;

}


void hexdump(void *buff,u16 size,IP *ip_header){
     const u8 *p=(const u8 *)buff;
     size_t i,j;
     switch(ip_header->protocol){
           case PROTO_ICMP:
                  fprintf(icmp_logfile,"\t\t\t\t\t\t");
                  for(i=0;i<size;i++){
         
                        if((i%16)==0){
                           fprintf(icmp_logfile,"%08lx ",i);
                           }
            
                           if(i % 8==0 && i!=0){
                              fprintf(icmp_logfile," ");
                           }
         

                           fprintf(icmp_logfile," %02x",p[i]);
            

                        if((i%16)==15 || i==(size_t)size-1){
                           for(j=0;j<15-(i%16);j++){
                              fprintf(icmp_logfile," ");
                         }
                           fprintf(icmp_logfile," | ");
                           for(j=(i-(i%16));j<=i;j++){
                              if(IS_PRINTABLE_ASCII(p[j])){
                                 fprintf(icmp_logfile,"%c",p[j]);
                              }else{
                                 fprintf(icmp_logfile,".");
                              }
                           }
                           fprintf(icmp_logfile,"\n\t\t\t\t\t\t");
                      }

                   }
                  fprintf(icmp_logfile,"\n");

                  break;
           case PROTO_TCP:
                       fprintf(tcp_logfile,"\t\t\t\t\t\t");
                       for(i=0;i<size;i++){
         
                        if((i%16)==0){
                           fprintf(tcp_logfile,"%08lx ",i);
                           }
            
                           if(i % 8==0 && i!=0){
                              fprintf(tcp_logfile," ");
                           }
         

                           fprintf(tcp_logfile," %02x",p[i]);
            

                        if((i%16)==15 || i==(size_t)size-1){
                           for(j=0;j<15-(i%16);j++){
                              fprintf(tcp_logfile," ");
                           }
                           fprintf(tcp_logfile," | ");
                           for(j=(i-(i%16));j<=i;j++){
                              if(IS_PRINTABLE_ASCII(p[j])){
                                 fprintf(tcp_logfile,"%c",p[j]);
                              }else{
                                 fprintf(tcp_logfile,".");
                              }
                            }
                            fprintf(tcp_logfile,"\n\t\t\t\t\t\t");
                      }

                  }
                  fprintf(tcp_logfile,"\n");
           break;
           case PROTO_UDP:
               fprintf(udp_logfile,"\t\t\t\t\t\t");
               for(i=0;i<size;i++){
         
                     if((i%16)==0){
                        fprintf(udp_logfile,"%08lx ",i);
                        }
            
                        if(i % 8==0 && i!=0){
                           fprintf(udp_logfile," ");
                        }
         

                        fprintf(udp_logfile," %02x",p[i]);
            

                     if((i%16)==15 || i==(size_t)size-1){
                        for(j=0;j<15-(i%16);j++){
                           fprintf(udp_logfile," ");
                        }
                        fprintf(udp_logfile," | ");
                        for(j=(i-(i%16));j<=i;j++){
                           if(IS_PRINTABLE_ASCII(p[j])){
                               fprintf(udp_logfile,"%c",p[j]);
                           }else{
                              fprintf(udp_logfile,".");
                            }
                        }
                         fprintf(udp_logfile,"\n\t\t\t\t\t\t");
                     }

                        }
                        fprintf(udp_logfile,"\n");
                            break;
                  }
     
}


const char* get_timestamp() {
   static char buffer[64];
   time_t now = time(NULL);
   struct tm *tm_info = localtime(&now);
   strftime(buffer, sizeof(buffer), "[%Y-%m-%d %H:%M:%S]", tm_info);
   return buffer;
}