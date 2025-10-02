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


int main(int argc,char *argv[]){
   
   static struct option long_options[]={
         {"protocal",required_argument,0,'p'}
   };


   Options *options=malloc(sizeof(Options));

   if(!options){
       error(true,"Failed to allocate memory for options");
   }

   i32 option;
   
   
   options->proto=NONE;

   while((option=getopt_long(argc,argv,"p:",long_options,NULL))!=-1){
              switch(option){
                    
                   case 'p':
                        options->proto=parse_protocal(optarg);
                        break;

                   default:
                     break;
                 
              }
   }

    
      
   capture_packets(options);

   printf(WHITE"\n\nNetSnoop Shutting Down\n\n"RESET);
   
   return 0;
}

