#ifndef DSM_IPC_HPP
#define DSM_IPC_HPP

#include <cstdint>
#include <cstring>
#include <sys/mman.h>

#define PAGE_SIZE 4096

inline bool
xchgb(volatile bool *addr, bool newval)
{   
  bool result;
  asm volatile("lock; xchgb %0, %1" :
               "+m" (*addr), "=a" (result) :
               "1" (newval) :
               "cc");
  return result;
}

struct IpcRegion {
    
    char download_page[PAGE_SIZE];
    char upload_page[PAGE_SIZE];
    struct ipc_mutex {
        bool state = 0;
        void lock() {
            while (xchgb(&state, 1));
        }
        void unlock() {
            state = 0;
        }
    };

    #define REQ_NONE 0
    #define REQ_GRANT_WRITE 1
    #define REQ_GRANT_READ  2
    #define REQ_RSPS_READ   3
    #define REQ_RSPS_WRITE  4
    #define MAX_REQ_QUEUE   4
    
    #define STATE_FREE          0
    #define STATE_UNRESOLVE     1
    #define STATE_PAGE_COPIED   2
    #define STATE_MPROTECT_SET  3
    #define STATE_RESOLVED      4

    struct request {
        uint8_t status;
        uint8_t req;
        char * addr;
        ipc_mutex mu;
    };

    request dsm_page_req;
    request page_fault_req;
    /*
     * mprotect
     * process copy page
     * page sent to remote
     * */
    bool grant_write(char *addr);
    bool grant_read(char *addr);
    bool response(char *addr, char * dst, uint8_t req_type);
    bool response_read(char * dst, char *addr);
    bool response_write(char *addr, char * dst);
    void run_thread_ipc_server();
    void run_dsm_ipc_server(void * arg);
};




#endif 













