#include <stdio.h>
#include <stdlib.h>
#include "common.h"

volatile int counter = 0;
int loops;

void *worker(void *arg){
  int i;
  for(i=0; i<loops; i++){
    counter++;
  }

  return null;
}
