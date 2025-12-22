#ifndef QUEUE_H
#define QUEUE_H

#include "netsnoop.h"

#define QUEUE_SIZE 250


typedef struct{

     i32 front;
     i32 back;
     i8 *buffer[QUEUE_SIZE];

}queue;


void initialize_queue(queue *q);
bool push(queue *,i8 *);
i8* pop(queue *);
bool empty(queue *);
bool full(queue *q);



#endif