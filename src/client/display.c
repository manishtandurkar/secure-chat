/**
 * Display Module - Format and render incoming messages
 * Shows timestamps, sender info, priority indicators
 */

#include "client.h"
#include <stdio.h>
#include <time.h>
#include <string.h>

/* ANSI color codes (optional, can disable for plain terminals) */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_GRAY    "\033[90m"

/* Get current timestamp string */
void get_timestamp(char *buf, size_t buf_len) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buf, buf_len, "%H:%M:%S", tm_info);
}

/* Display incoming chat message with formatting */
void display_chat_message(const char *sender, const char *message, uint8_t priority) {
    char timestamp[16];
    get_timestamp(timestamp, sizeof(timestamp));

    const char *priority_icon = "";
    const char *priority_color = COLOR_RESET;

    switch (priority) {
        case PRIORITY_CRITICAL:
            priority_icon = "🔴";
            priority_color = COLOR_RED;
            break;
        case PRIORITY_URGENT:
            priority_icon = "🟡";
            priority_color = COLOR_YELLOW;
            break;
        default:
            priority_icon = "";
            priority_color = COLOR_RESET;
            break;
    }

    printf("%s[%s]%s %s%s%s %s%s%s: %s\n",
           COLOR_GRAY, timestamp, COLOR_RESET,
           priority_color, priority_icon, COLOR_RESET,
           COLOR_BLUE, sender, COLOR_RESET,
           message);
    fflush(stdout);
}

/* Display system message */
void display_system_message(const char *message) {
    char timestamp[16];
    get_timestamp(timestamp, sizeof(timestamp));

    printf("%s[%s] [SYSTEM]%s %s\n",
           COLOR_GRAY, timestamp, COLOR_RESET,
           message);
    fflush(stdout);
}

/* Display error message */
void display_error_message(const char *message) {
    char timestamp[16];
    get_timestamp(timestamp, sizeof(timestamp));

    printf("%s[%s] %s[ERROR]%s %s\n",
           COLOR_GRAY, timestamp,
           COLOR_RED, COLOR_RESET,
           message);
    fflush(stdout);
}

/* Display connection status */
void display_status(const char *status) {
    printf("%s>>> %s%s\n", COLOR_GREEN, status, COLOR_RESET);
    fflush(stdout);
}

/* Display welcome banner */
void display_welcome(const char *username) {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════╗\n");
    printf("║        Adaptive Secure Communication System            ║\n");
    printf("║                                                        ║\n");
    printf("║  Connected as: %-36s ║\n", username);
    printf("║  Type /help for commands                               ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n");
    printf("\n");
    fflush(stdout);
}

/* Clear line (for input prompt refresh) */
void clear_line(void) {
    printf("\r\033[K");
    fflush(stdout);
}

/* Display offline queue count */
void display_offline_count(int count) {
    if (count > 0) {
        printf("%s[*] You have %d offline message(s)%s\n", 
               COLOR_YELLOW, count, COLOR_RESET);
        fflush(stdout);
    }
}

/* Display adaptive mode change */
void display_mode_change(const char *old_mode, const char *new_mode) {
    printf("%s[*] Security mode changed: %s → %s%s\n",
           COLOR_YELLOW, old_mode, new_mode, COLOR_RESET);
    fflush(stdout);
}
