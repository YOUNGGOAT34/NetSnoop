#include "main.h"

/*
 Ping flood /
 ICMP flood

*/


//Incase the user passes the protocal in uppercase ,I wanna convert it to lower case before enumerating it
Protocal parse_protocal(const i8 *str){
   
      i8 lower[5];
      i32 i = 0;
  
      while (str[i] && i < 4) {
          lower[i] = tolower((u8)str[i]);
          i++;
      }
      lower[i] = '\0';
  
      if (strcmp(lower, "tcp") == 0) return tcp;
      if (strcmp(lower, "udp") == 0) return udp;
      if (strcmp(lower, "icmp") == 0) return icmp;
  
      return proto_unknown;
  
}



INTERFACES *get_all_interfaces(void){
     INTERFACES *interfaces=malloc(sizeof(INTERFACES));

     struct ifaddrs *interface_list_head,*current_interface_in_list;

     interfaces->count=0;
     interfaces->interfaces=NULL;

     if(getifaddrs(&interface_list_head)==-1){
          return NULL;
     }

     
     for(current_interface_in_list=interface_list_head;current_interface_in_list!=NULL;current_interface_in_list=current_interface_in_list->ifa_next){
             if(current_interface_in_list->ifa_addr==NULL) continue;
             i32 duplicate=0;
             for(int i=0;i<interfaces->count;i++){
                 
                 if(strcmp(current_interface_in_list->ifa_name,interfaces->interfaces[i])==0){
                     duplicate+=1;
                     break;
                 }
             }

             if(duplicate) continue;


             if (strncmp(current_interface_in_list->ifa_name, "veth", 4) == 0) continue;
             if (strncmp(current_interface_in_list->ifa_name, "docker", 6) == 0) continue;
             if (strncmp(current_interface_in_list->ifa_name, "br-", 3) == 0) continue;


             interfaces->interfaces=realloc(interfaces->interfaces,sizeof(i8 *)*(interfaces->count+1));

             if(!interfaces->interfaces){
                  for(int i=0;i<interfaces->count;i++){
                      free(interfaces->interfaces[i]);
                  }

                  free(interfaces->interfaces);
                  free(interfaces);
                  freeifaddrs(interface_list_head);
                  
                  return NULL;
             }

             interfaces->interfaces[interfaces->count] = strdup(current_interface_in_list->ifa_name);
             if (!interfaces->interfaces[interfaces->count]) {
               for(int i=0;i<interfaces->count;i++){
                  free(interfaces->interfaces[i]);
              }

              free(interfaces->interfaces);
              free(interfaces);
              freeifaddrs(interface_list_head);
              
              return NULL;

             }

             interfaces->count+=1;

           }


     freeifaddrs(interface_list_head);
     return interfaces;
}



int main(int argc,char *argv[]){
   
   static struct option long_options[]={
         {"protocal",required_argument,0,'p'},
         {"interface",required_argument,0,'i'}
   };


   INTERFACES *interfaces=get_all_interfaces();
   
   Options *options=malloc(sizeof(Options));
   
   if(!options){
       error(true,"Failed to allocate memory for options");
   }

   i32 option;
   options->proto=NONE;

   //by default the first interface(except the loop back ) is selected

   for(int i=0;i<interfaces->count;i++){
        if(strcmp(interfaces->interfaces[i],"lo")!=0){
           options->interface=interfaces->interfaces[i];
           break;
        }
   }


   while((option=getopt_long(argc,argv,"p:i:",long_options,NULL))!=-1){
              switch(option){
                    
                   case 'p':
                        options->proto=parse_protocal(optarg);
                        break;
                   case 'i':
                   options->interface=optarg;
                   break;
                   default:
                     break;
                 
              }
   }

  
   
   capture_packets(options);
   free(options);

   printf(WHITE"\n\nNetSnoop Shutting Down\n\n"RESET);
   
   return 0;
}

