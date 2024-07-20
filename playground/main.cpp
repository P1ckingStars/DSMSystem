#include <cstdlib>
#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <unistd.h>

#define handle_error(msg)                                                      \
do {                                                                         \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
} while (0)

char *buffer;

#define PAGE_SIZE 4096
#define FLOOR(addr) ((addr) / PAGE_SIZE * PAGE_SIZE)

static void handler(int sig, siginfo_t *si, void *unused) {
    ucontext_t * ctx = (ucontext_t *)unused;
    int flag = (ctx->uc_mcontext.gregs[REG_ERR] & 2);
    printf("Got SIGSEGV with status %d at address: 0x%lx\n", flag, (long)si->si_addr);
    
    mprotect((void *)FLOOR((intptr_t)si->si_addr), PAGE_SIZE, PROT_READ | PROT_WRITE);
}

int main(int argc, char *argv[]) {
    char *p;
    int pagesize;
    struct sigaction sa;

    char * heap_mem = (char *)malloc(PAGE_SIZE * 10);

    printf("Start of heap mem:        0x%lx\n page size: %d\n", (long)heap_mem, pagesize);

    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
        handle_error("sigaction");

    pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize == -1)
        handle_error("sysconf");

    /* Allocate a buffer aligned on a page boundary;
     initial protection is PROT_READ | PROT_WRITE */

    buffer = (char *)memalign(pagesize, 4 * pagesize);
    if (buffer == NULL)
        handle_error("memalign");

    printf("Start of region:        0x%lx\n page size: %d\n", (long)buffer, pagesize);

    if (mprotect(buffer + pagesize, pagesize, PROT_NONE) == -1)
        handle_error("mprotect");

    for (p = buffer; p < buffer + 4 * pagesize;)
        char a = *(p++); 
        //*(p++) = 'a';

    printf("Loop completed\n"); /* Should never happen */
    exit(EXIT_SUCCESS);
}
