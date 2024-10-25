#ifndef FAULT_HPP
#define FAULT_HPP

#include <cstddef>
void *page_fault_service(void *args);
void *page_manage_service(void *args);

int faultfd_init(void *mem_addr, size_t length);



#endif
