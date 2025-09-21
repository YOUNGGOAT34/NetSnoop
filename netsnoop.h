#ifndef NETSNOOP_H
#define NETSNOOP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#define BUFFER_SIZE 65536

//signed data types
typedef char i8;
typedef signed short int i16;
typedef signed int i32;
typedef signed long int i64;


//unsigned data types
typedef unsigned char u8;
typedef unsigned short int u16;
typedef unsigned int u32;
typedef unsigned long int u64;

void error(bool with_exit,const i8*);



#endif