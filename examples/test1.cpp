
#include <cstdint>
#include <cstdlib>
#include <stdio.h>
#include "simple_mutex.hpp"

int dsm_main(char * mem_region, size_t length, int argc, char * argv[]) {
    printf("start dsm main %lx!!!\n", (uint64_t)mem_region);
    bool is_master = atoi(argv[1]) == 0;
    if (is_master) {
        mem_region[0] = 1;
        while (mem_region[1] == 0) {
            mem_region[0] = 1;
        }
    } else {
        mem_region[1] = 1;
        while (mem_region[0] == 0) {
            mem_region[1] = 1;
        }
    }
    printf("barrier complete!!!\n");
    SimpleMutex * mu = (SimpleMutex *)(&mem_region[5000]);
    for (int i = 0; i < 300; i++) {
        printf("singleton: %lx\n", (intptr_t)DSMSync::singleton());
         DSMSync::singleton()->lock(mu);
        printf("mutex2: %d\n", *mu);
        ((int *)mem_region)[20]++;
        printf("count = %d\n", ((int *)mem_region)[20]);
        DSMSync::singleton()->unlock(mu);
        printf("mutex3: %d\n", *mu);
    }
    printf("complete!!!\n");
    return 0;
}
