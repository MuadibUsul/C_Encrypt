#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdint.h>

int time_stamp(){
    struct timeval tv;
    gettimeofday(&tv,NULL);
    int time = tv.tv_sec;
    return time;
}