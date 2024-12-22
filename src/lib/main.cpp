#include "dsm_node.hpp"
#include <alloca.h>
#include <signal.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <malloc.h>
#include <memory>
#include <sched.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include "debug.hpp"

using namespace dsm;

int dsm_main(char * mem_region, size_t length, int argc, char * argv[]);

int x = 1;

int main(int argc, char * argv[]) {
    int x;
    printf("stack begin at %lx\n", (intptr_t)&x);
    bool is_master = atoi(argv[1]) == 0;
    int pages = atoi(argv[2]);
    char * mem_region = (char *)aligned_alloc(PAGE_SIZE, PAGE_SIZE * pages);
    pid_t child;
    if ((child = fork()) == 0) {
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        printf("wait\n");
        while(x);
        printf("start dsm main\n");
        int res = dsm_main(mem_region, PAGE_SIZE * pages, argc, argv);
        return 0;
    }
    if (is_master) {
        printf("create master\n");
        NodeAddr addr;
        addr.ip = string(argv[3]);
        addr.port = stoi(argv[4]);
        dsm_init_master(child, addr, mem_region, PAGE_SIZE * pages);
    } else {
        printf("create node\n");
        NodeAddr addr;
        addr.ip = string(argv[3]);
        addr.port = stoi(argv[4]);
        NodeAddr dst_addr;
        dst_addr.ip = string(argv[5]);
        dst_addr.port = stoi(argv[6]);
        dsm_init_node(child, addr, dst_addr, mem_region, PAGE_SIZE * pages);
    }
    while(1);
    return 0;
}









