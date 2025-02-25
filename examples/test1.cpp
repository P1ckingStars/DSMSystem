#include "dsm_lock.hpp"
#include "queue.hpp"
#include "threadlib/cpu.h"
#include "threadlib/cv.h"
#include "threadlib/mutex.h"
#include "threadlib/thread.h"
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <unistd.h>

using std::cout;
using std::endl;

mutex bufferMutex;
cv bufferNotEmpty;
cv bufferNotFull;
Queue<int> buffer;
const size_t bufferSize = 10;
bool x = 1;

void producer(void *arg) {
  while (x) {
    dsm::sync();
    printf("x %lx has been set to %d\n", (intptr_t)&x, x);
    sleep(1);
  }
  sleep(1);
  for (int i = 0; i < 50; ++i) {
    cout << "lock status: " << bufferMutex.status() << endl;
    bufferMutex.lock();
    cout << "Produced: " << i << endl;
    while (buffer.size() == bufferSize) {
      bufferNotFull.wait(bufferMutex);
    }
    buffer.enqueue(i);
    cout << "Produced: " << i << endl;
    bufferNotEmpty.signal();
    bufferMutex.unlock();
  }
}

void consumer(void *arg) {
  printf("start consumer\n");
  x = 0;
  printf("x %lx has been set to %d\n", (intptr_t)&x, x);
  while (true) {
    bufferMutex.lock();
    while (buffer.isEmpty()) {
      printf("wait on mutex %lx\n", (intptr_t)&bufferMutex);
      bufferNotEmpty.wait(bufferMutex);
    }
    int item = buffer.front();
    buffer.dequeue();
    cout << "Consumed: " << item << endl;
    bufferNotFull.signal();
    bufferMutex.unlock();
  }
}

void dsm_main1(void *arg) {
  printf("---------------run user code now-------------\n");
  thread prod(producer, nullptr);
  thread cons(consumer, nullptr);
  prod.join();
  cons.join(); // In a real scenario, you might need a way to stop the consumer
               // thread gracefully.
  printf("complete!!!\n");
}
