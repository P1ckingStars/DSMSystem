#include "dsm_ipc.hpp"
#include "dsm_node.hpp"
#include <cstring>


    bool IpcRegion::grant_write(char *addr) {
        page_fault_req.addr = addr;
        page_fault_req.req = REQ_GRANT_WRITE;
        page_fault_req.status = STATE_UNRESOLVE;
        while (page_fault_req.status != STATE_PAGE_COPIED);
        mprotect((void *)FLOOR((intptr_t)addr), PAGE_SIZE, PROT_READ | PROT_WRITE);
        memcpy((void *)FLOOR((intptr_t)addr), download_page, PAGE_SIZE);
        page_fault_req.status = STATE_MPROTECT_SET;
        while (page_fault_req.status != STATE_RESOLVED);
        page_fault_req.status = STATE_FREE;
        return true;
    }
    bool IpcRegion::grant_read(char *addr) {
        page_fault_req.addr = addr;
        page_fault_req.req = REQ_GRANT_READ;
        page_fault_req.status = STATE_UNRESOLVE;
        while (page_fault_req.status != STATE_PAGE_COPIED);
        mprotect((void *)FLOOR((intptr_t)addr), PAGE_SIZE, PROT_READ | PROT_WRITE);
        memcpy((void *)FLOOR((intptr_t)addr), download_page, PAGE_SIZE);
        mprotect((void *)FLOOR((intptr_t)addr), PAGE_SIZE, PROT_READ);
        page_fault_req.status = STATE_MPROTECT_SET;
        while (page_fault_req.status != STATE_RESOLVED);
        page_fault_req.status = STATE_FREE;
        return true;
    }
    bool IpcRegion::response(char *addr, char * dst, uint8_t req_type) {
        dsm_page_req.mu.lock();
        while (dsm_page_req.status != STATE_FREE);
        dsm_page_req.status = STATE_UNRESOLVE;
        dsm_page_req.addr = addr;
        dsm_page_req.req = req_type;
        dsm_page_req.mu.unlock();
        while (dsm_page_req.status != STATE_RESOLVED);
        memcpy(dst, addr, PAGE_SIZE);
        dsm_page_req.status = STATE_FREE;
        return true;
    }
    bool IpcRegion::response_read(char * dst, char *addr) {
        return response(dst, addr, REQ_RSPS_READ);
    }
    bool IpcRegion::response_write(char *addr, char * dst) {
        return response(dst, addr, REQ_RSPS_WRITE);
    }

    void IpcRegion::run_thread_ipc_server() {
        while (1) {
            if (dsm_page_req.status != STATE_UNRESOLVE) continue;
            if (page_fault_req.req == REQ_RSPS_WRITE) {
                mprotect(dsm_page_req.addr, PAGE_SIZE, PROT_READ);
            }
            memcpy(this->upload_page, dsm_page_req.addr, PAGE_SIZE);
            dsm_page_req.status = STATE_RESOLVED;
        }
    }
    void IpcRegion::run_dsm_ipc_server(void * arg) {
        dsm::DSMNode * node = (dsm::DSMNode *)arg;
        while (1) {
            if (page_fault_req.status == STATE_UNRESOLVE) {
                if (page_fault_req.req == REQ_GRANT_READ) {
                    node->grant_read(page_fault_req.addr);
                }
                else /* page_fault_req.req == REQ_GRANT_WRITE */ {
                    node->grant_write(page_fault_req.addr);
                }
            }
        }
    }
