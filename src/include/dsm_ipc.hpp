#ifndef DSM_IPC_HPP
#define DSM_IPC_HPP

#include "dsm_node.hpp"
#include <cstdint>
#include <cstring>

class IpcRegion{
    
    char download_page[PAGE_SIZE];
    char upload_page[PAGE_SIZE];

    #define REQ_NONE 0
    #define REQ_GRANT_WRITE 1
    #define REQ_GRANT_READ  2
    #define REQ_RSPS_READ   3
    #define REQ_RSPS_WRITE  4
    #define MAX_REQ_QUEUE   20
    
    #define STATE_FREE      0
    #define STATE_UNRESOLVE 1
    #define STATE_RESOLVED  2

    struct request {
        uint8_t status;
        uint8_t req;
        char * addr;
    };

    request dsm_req_queue[MAX_REQ_QUEUE];
    int head;
    int tail;
    request page_fault_req;

    bool grant_write(char *addr) {
        return true;
    }
    bool grant_read(char *addr) {
        return true;
    }
    bool response_read(char *addr) {
        
        return true;
    }
    bool response_write(char *addr) {

        return true;
    }

    void run_thread_ipc_server() {
        while (1) {
            if (head == tail) continue;
            if (dsm_req_queue[head].req == REQ_RSPS_READ) {
                memcpy(this->upload_page, dsm_req_queue[head].addr, PAGE_SIZE);
                dsm_req_queue[head].status = STATE_RESOLVED;
            } else /* page_fault_req.req == REQ_RSPS_WRITE */ {
                memcpy(this->upload_page, dsm_req_queue[head].addr, PAGE_SIZE);
                dsm_req_queue[head].status = STATE_RESOLVED;
            }
            head = (head + 1) % MAX_REQ_QUEUE;
        }
    }
    void run_dsm_ipc_server(dsm::DSMNode * node) {
        while (1) {
            if (page_fault_req.status == STATE_UNRESOLVE) {
                if (page_fault_req.req == REQ_GRANT_READ) {
                    node->grant_read(page_fault_req.addr);
                }
                else /* page_fault_req.req == REQ_GRANT_WRITE */ {
                    node->grant_write(page_fault_req.addr);
                }
                page_fault_req.status = STATE_FREE;
            }
        }
    }
};




#endif 













