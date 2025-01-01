
#include <cstdint>
#include <cstdlib>
#include <stdio.h>
#include <sys/mman.h>

int var;
int mu;
int p;

int dsm_main(char * mem_region, size_t length, int argc, char * argv[]) {
    printf("---------------run user code now-------------\n");
    bool is_master = atoi(argv[1]) == 0;
    char *x_part = (char *)&var;
    int k = x_part[2];
    printf("write %lx!!!\n", (intptr_t)&x_part[1]);
    if (is_master) {
        x_part[0] = 1;
        while (x_part[1] == 0) {
            x_part[0] = 1;
        }
    } else {
        x_part[1] = 1;
        while (x_part[0] == 0) {
            x_part[1] = 1;
        }
    }
    printf("barrier complete!!!\n");
    for (int i = 0; i < 300; i++) {
        printf("mutex2: %d\n", mu);
        p++;
        printf("count = %d\n", p);
        printf("mutex3: %d\n", mu);
    }
    printf("complete!!!\n");
    while(1);
    return 0;
}
