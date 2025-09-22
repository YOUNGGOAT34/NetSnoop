#ifndef HEXDUMP_H
#define HEXDUMP_H
#include "netsnoop.h"


#define IS_PRINTABLE_ASCII(c) (((c)>31) && ((c)<127))

void hexadump(void *buff,u16 size);
#endif