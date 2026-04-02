#include "platform_compat.h"
#include <stdio.h>

int main() {
    printf("Platform compatibility test\n");
    
    /* Test Windows socket initialization */
    if (platform_socket_init() != 0) {
        fprintf(stderr, "Socket init failed\n");
        return 1;
    }
    
    printf("Socket initialized successfully\n");
    
    platform_socket_cleanup();
    return 0;
}
