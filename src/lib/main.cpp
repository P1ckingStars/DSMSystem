#include "debug.hpp"
#include "dsm_node.hpp"
#include <alloca.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <malloc.h>
#include <memory>
#include <sched.h>
#include <signal.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <unistd.h>

using namespace dsm;

int dsm_main(char *mem_region, size_t length, int argc, char *argv[]);

extern char __bss_start;

int main(int argc, char *argv[]) {
  int a;
  printf("stack begin at %lx\n", (intptr_t)&a);
  printf("mem region begin at %lx\n", (intptr_t)&__bss_start);
  char *mem_region = (char *)&__bss_start;
  char *mem_end =
      (char *)PAGE_ALIGNED_ADDR(((intptr_t)&__bss_start + 25000 * PAGE_SIZE));
  brk(mem_end);
  pid_t child;
  size_t size = mem_end - mem_region;
  printf("mem size %lx\n", size);
  bool is_master = atoi(argv[1]) == 0;
  int pages = atoi(argv[2]);
  int x = 1;
  if ((child = fork()) == 0) {
    ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
    printf("wait on x: %lx, %d\n", (intptr_t)(&x), x);
    while (x)
      ;
    printf("start dsm main\n");
    int res = dsm_main(mem_region, size, argc, argv);
  } else {
    if (is_master) {
      printf("create master\n");
      NodeAddr addr;
      addr.ip = string(argv[3]);
      addr.port = stoi(argv[4]);
      dsm_init_master(child, addr, mem_region, size, &x);
    } else {
      printf("create node\n");
      NodeAddr addr;
      addr.ip = string(argv[3]);
      addr.port = stoi(argv[4]);
      NodeAddr dst_addr;
      dst_addr.ip = string(argv[5]);
      dst_addr.port = stoi(argv[6]);
      dsm_init_node(child, addr, dst_addr, mem_region, size, &x);
    }
  }
  while (1)
    ;
  return 0;
}
