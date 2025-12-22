#include "queue.h"


void initialize_queue(queue *q){
      q->back=-1;
      q->front=-1;
}

bool push(queue *q,packet *buffer){
     if(full(q)){
       return false;
     }

     if(q->front==-1){
          q->front=0;
          q->back=0;
     }else{

        q->back=(q->back+1)%QUEUE_SIZE;
     }


     q->packet[q->back]=buffer;

     return true;

}


packet* pop(queue *q){
       if(empty(q)){
          return NULL;
       }

       packet *buffer=q->packet[q->front];
       if(q->back==q->front){
           q->front=-1;
           q->back=-1;
       }else{

          q->front=(q->front+1)%QUEUE_SIZE;
       }
       return buffer;

}


bool empty(queue *q){
    return q->front==-1;
}

bool full(queue *q){
     return (q->front==(q->back+1)%QUEUE_SIZE);
}