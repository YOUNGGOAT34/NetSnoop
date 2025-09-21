#include "netsnoop.h"

void error(bool with_exit,const i8* error_message){
    if(with_exit){
       fprintf(stderr,"%s:(%s)\n",error_message,strerror(errno));
       exit(EXIT_FAILURE);

    }

    fprintf(stderr,"%s:(%s)\n",error_message,strerror(errno));
   

}