#include "dsm_lock.hpp"
#include "queue.hpp"
#include "threadlib/cpu.h"
#include "threadlib/cv.h"
#include "threadlib/mutex.h"
#include "threadlib/thread.h"
#include <cstdio>
#include <iostream>

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
    thread::yield();
  }
  for (int i = 0; i < 50; ++i) {
    bufferMutex.lock();
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
  while (true) {
    bufferMutex.lock();
    while (buffer.isEmpty()) {
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
