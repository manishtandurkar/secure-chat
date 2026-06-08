#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "priority_queue.h"
#include "common.h"
#include "platform_compat.h"

void input_enqueue(const char *text, uint8_t priority) {
    QueuedMessage msg = {0};
    msg.priority = priority;
    msg.payload_len = strlen(text);
    if (msg.payload_len >= sizeof(msg.payload)) msg.payload_len = sizeof(msg.payload) - 1;
    memcpy(msg.payload, text, msg.payload_len);
    msg.enqueue_time_ms = get_time_ms();
    pq_enqueue(&msg);
}

/* Forward declaration from client.c */
int client_request_user_list_g(void);

void *input_thread_func(void *arg) {
    (void)arg;
    char line[MAX_MSG_LEN];
    while (fgets(line, sizeof(line), stdin)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[--len] = '\0';
        if (len == 0) continue;

        /* Special commands */
        if (strcmp(line, "/users") == 0) {
            client_request_user_list_g();
            continue;
        }

        uint8_t priority = PRIORITY_NORMAL;
        char *msg = line;

        if (strncmp(line, "!urgent ", 8) == 0) {
            priority = PRIORITY_URGENT;
            msg = line + 8;
        } else if (strncmp(line, "!critical ", 10) == 0) {
            priority = PRIORITY_CRITICAL;
            msg = line + 10;
        }

        /* Parse @recipient message → "recipient\nmessage"
           @all message  → "\nmessage" (broadcast) */
        char formatted[MAX_MSG_LEN];
        if (msg[0] == '@') {
            char *space = strchr(msg + 1, ' ');
            if (space) {
                size_t rlen = (size_t)(space - (msg + 1));
                if (rlen >= MAX_USERNAME_LEN) rlen = MAX_USERNAME_LEN - 1;
                if (rlen == 3 && memcmp(msg + 1, "all", 3) == 0) {
                    /* @all → empty recipient = broadcast */
                    formatted[0] = '\n';
                    strncpy(formatted + 1, space + 1, sizeof(formatted) - 2);
                    formatted[sizeof(formatted) - 1] = '\0';
                } else {
                    memcpy(formatted, msg + 1, rlen);
                    formatted[rlen] = '\n';
                    strncpy(formatted + rlen + 1, space + 1, sizeof(formatted) - rlen - 2);
                    formatted[sizeof(formatted) - 1] = '\0';
                }
                input_enqueue(formatted, priority);
            } else {
                printf("Usage: @recipient message  or  @all message\n");
            }
        } else {
            printf("Usage: @recipient message  or  @all message\n");
        }
    }
    return NULL;
}
