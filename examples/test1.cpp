
#include <cstdlib>
#include <stdio.h>

int dsm_main(char * mem_region, size_t length, int argc, char * argv[]) {
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
    printf("complete!!!\n");
    return 0;
}
