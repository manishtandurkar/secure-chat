/**
 * Input Handler - Parse user commands and enqueue messages
 * Supports: /msg, /join, /leave, /priority, /quit
 */

#include "client.h"
#include "priority_queue.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* Parse and handle user input */
int handle_input(const char *input, ClientState *client) {
    if (!input || strlen(input) == 0) {
        return 0;
    }

    /* Command: /quit */
    if (strcmp(input, "/quit") == 0) {
        printf("[*] Quitting...\n");
        client->running = 0;
        return 1;
    }

    /* Command: /join <room> */
    if (strncmp(input, "/join ", 6) == 0) {
        const char *room = input + 6;
        while (isspace(*room)) room++;
        
        if (strlen(room) == 0 || strlen(room) >= MAX_ROOM_NAME_LEN) {
            printf("[!] Invalid room name\n");
            return 0;
        }

        strncpy(client->current_room, room, MAX_ROOM_NAME_LEN - 1);
        client->current_room[MAX_ROOM_NAME_LEN - 1] = '\0';
        printf("[*] Joined room: %s\n", client->current_room);
        return 0;
    }

    /* Command: /leave */
    if (strcmp(input, "/leave") == 0) {
        if (strlen(client->current_room) > 0) {
            printf("[*] Left room: %s\n", client->current_room);
            client->current_room[0] = '\0';
        } else {
            printf("[*] Not in a room\n");
        }
        return 0;
    }

    /* Command: /help */
    if (strcmp(input, "/help") == 0) {
        printf("\nAvailable commands:\n");
        printf("  /join <room>  - Join a chat room\n");
        printf("  /leave        - Leave current room\n");
        printf("  /quit         - Exit the client\n");
        printf("  /help         - Show this help\n");
        printf("\n");
        return 0;
    }

    /* Regular message - will be handled by send_thread */
    return 0;
}

/* Validate username (alphanumeric, underscore, hyphen only) */
int validate_username(const char *username) {
    if (!username || strlen(username) == 0 || strlen(username) >= MAX_USERNAME_LEN) {
        return 0;
    }

    for (size_t i = 0; i < strlen(username); i++) {
        char c = username[i];
        if (!isalnum(c) && c != '_' && c != '-') {
            return 0;
        }
    }

    return 1;
}

/* Sanitize input (remove control characters) */
void sanitize_input(char *input) {
    for (size_t i = 0; i < strlen(input); i++) {
        if (iscntrl(input[i]) && input[i] != '\n' && input[i] != '\t') {
            input[i] = ' ';
        }
    }
}
