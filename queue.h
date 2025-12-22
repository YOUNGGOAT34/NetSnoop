#ifndef QUEUE_H
#define QUEUE_H

#include "netsnoop.h"

#define QUEUE_SIZE 250


typedef struct{
    ssize_t received_bytes;
    i8 *buffer;
}packet;


typedef struct{

     i32 front;
     i32 back;
     packet *packet[QUEUE_SIZE];

}queue;


void initialize_queue(queue *q);
bool push(queue *,packet *);
packet* pop(queue *);
bool empty(queue *);
bool full(queue *q);



#endif