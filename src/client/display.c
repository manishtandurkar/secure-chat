#include <stdio.h>
#include <string.h>
#include <time.h>
#include "common.h"

void display_message(const char *sender, const char *text, uint8_t priority) {
    time_t now = time(NULL);
    char tbuf[20];
    struct tm *tm_info = localtime(&now);
    strftime(tbuf, sizeof(tbuf), "%H:%M:%S", tm_info);

    const char *prio_str = "";
    if (priority == PRIORITY_CRITICAL) prio_str = "[CRITICAL] ";
    else if (priority == PRIORITY_URGENT) prio_str = "[URGENT] ";

    printf("[%s] %s<%s> %s\n", tbuf, prio_str, sender, text);
    fflush(stdout);
}

void display_system(const char *msg) {
    printf("[SERVER] %s\n", msg);
    fflush(stdout);
}

void display_users(const char *user_list) {
    printf("[USERS] %s\n", user_list);
    fflush(stdout);
}
