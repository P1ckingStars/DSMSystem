#include "fault.hpp"
#include "dsm_node.hpp"
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <thread>
#include <unistd.h>
#include <vector>




int faultfd_init(void *mem_addr, size_t length) {
  int uffd;
  void *region;

  // open the userfault fd
  uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  if (uffd == -1) {
    perror("syscall/userfaultfd");
    exit(1);
  }

  // enable for api version and check features
  struct uffdio_api uffdio_api;
  uffdio_api.api = UFFD_API;
  uffdio_api.features = 0;
  if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1) {
    perror("ioctl/uffdio_api");
    exit(1);
  }

  if (uffdio_api.api != UFFD_API) {
    fprintf(stderr, "unsupported userfaultfd api\n");
    exit(1);
  }

  // allocate a memory region to be managed by userfaultfd
  region = mmap(NULL, length, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (region == MAP_FAILED) {
    perror("mmap");
    exit(1);
  }

  // register the pages in the region for missing callbacks
  struct uffdio_register uffdio_register;
  uffdio_register.range.start = (unsigned long)region;
  uffdio_register.range.len = length;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
  if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
    perror("ioctl/uffdio_register");
    exit(1);
  }

  if ((uffdio_register.ioctls & UFFD_API_RANGE_IOCTLS) !=
      UFFD_API_RANGE_IOCTLS) {
    fprintf(stderr, "unexpected userfaultfd ioctl set\n");
    // exit(1);
  }
  return uffd;
}

void *page_fault_service(void *args) {
  prctl(PR_SET_PDEATHSIG, 9);
  int uffd = *(int *)args;
  char buf[PAGE_SIZE];

  for (;;) {
    struct uffd_msg msg;

    struct pollfd pollfd[1];
    pollfd[0].fd = uffd;
    pollfd[0].events = POLLIN;

    // wait for a userfaultfd event to occur
    int pollres = poll(pollfd, 1, 2000);

    switch (pollres) {
    case -1:
      perror("poll/userfaultfd");
      continue;
    case 0:
      continue;
    case 1:
      break;
    default:
      fprintf(stderr, "unexpected poll result\n");
      exit(1);
    }

    if (pollfd[0].revents & POLLERR) {
      fprintf(stderr, "pollerr\n");
      exit(1);
    }

    if (!pollfd[0].revents & POLLIN) {
      continue;
    }
    int readres = read(uffd, &msg, sizeof(msg));
    if (readres == -1) {
      if (errno == EAGAIN)
        continue;
      perror("read/userfaultfd");
      exit(1);
    }

    if (readres != sizeof(msg)) {
      fprintf(stderr, "invalid msg size\n");
      exit(1);
    }

    printf("fault detected");

    // handle the page fault by copying a page worth of bytes
    if (msg.event & UFFD_EVENT_PAGEFAULT) {

      bool write_fault = msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP;
      char *addr = (char *)msg.arg.pagefault.address;
      bool err = write_fault ? dsm::dsm_singleton->grant_write(addr)
                             : dsm::dsm_singleton->grant_read(addr);
      if (err) {
        printf("unknown error when resolving page fault\n");
        exit(-1);
      }
    }
    printf("fault resolved");
  }
  return NULL;
}

void *page_manage_service(void *args) {
  dsm::dsm_kernel_ipc_region *ipc = (dsm::dsm_kernel_ipc_region *)args;
  ipc->run_ipc_server();
  return nullptr;
}
