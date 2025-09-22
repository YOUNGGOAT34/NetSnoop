

#include "hexdump.h"

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