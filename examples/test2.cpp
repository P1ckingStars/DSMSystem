
#include "dsm_lock.hpp"
#include "queue.hpp"
#include "threadlib/cpu.h"
#include "threadlib/cv.h"
#include "threadlib/mutex.h"
#include "threadlib/thread.h"
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <unistd.h>

mutex bufferMutex;
cv bufferNotEmpty;
cv bufferNotFull;
Queue<int> buffer;
const size_t bufferSize = 10;
bool x = 1;

void producer(void *arg) {
  char stack_top = 0;
  printf("PRODUCER STACK %lx\n", (intptr_t)&stack_top);
  while (x) {
    dsm::sync();
    printf("x %lx has been set to %d\n", (intptr_t)&x, x);
  }
}

void consumer(void *arg) {
  char stack_top = 0;
  printf("CONSUMER STACK %lx\n", (intptr_t)&stack_top);
  x = 0;
  for (int i = 0; i < 10000000; i++) {
    char buffer[256];
    int len = snprintf(buffer, sizeof(buffer),
                       "working %lx, progress: %d/10000000\n", (intptr_t)&i, i);
    write(STDOUT_FILENO, buffer, len);
  }
}

void dsm_main1(void *arg) {
  printf("---------------run user code now-------------\n");
  thread prod(producer, nullptr);
  thread cons1(consumer, nullptr);
  thread cons2(consumer, nullptr);
  prod.join();
  cons1.join();
  cons2.join();
  printf("complete!!!\n");
}
