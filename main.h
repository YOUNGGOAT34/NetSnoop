#ifndef MAIN_H
#define MAIN_H

#include "netsnoop.h"
#include <getopt.h>
#include <ifaddrs.h>



Protocal parse_protocal(const i8 *);
INTERFACES *get_all_interfaces(void);


#endif