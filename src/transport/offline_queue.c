#define _POSIX_C_SOURCE 200809L
#include "platform_compat.h"
#include "offline_queue.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef PLATFORM_WINDOWS
#include <direct.h>
#include <io.h>
#define mkdir(path, mode) _mkdir(path)
#define stat _stat
#define S_ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)
typedef struct _finddata_t DIR_ENTRY;
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#endif

#define QUEUE_DIR "data/offline_queue"

/* Ensure queue directory exists with correct permissions */
static int ensure_queue_dir(void) {
    struct stat st = {0};
    
    if (stat(QUEUE_DIR, &st) == -1) {
        mkdir(QUEUE_DIR, 0700);
    }
    
    return SUCCESS;
}

/* Store encrypted message for offline user */
int queue_store(const char *username,
                const void *ciphertext, size_t len,
                const uint8_t msg_id[MSG_ID_LEN]) {
    if (!username || !ciphertext || !msg_id) {
        return ERROR_GENERAL;
    }
    
    ensure_queue_dir();
    
    /* Create user subdirectory */
    char user_dir[512];
    snprintf(user_dir, sizeof(user_dir), "%s/%s", QUEUE_DIR, username);
    
    struct stat st = {0};
    if (stat(user_dir, &st) == -1) {
        mkdir(user_dir, 0700);
    }
    
    /* Generate filename with timestamp and message ID */
    char filename[1024];
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t timestamp_ms = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    
    snprintf(filename, sizeof(filename), "%s/%lu_", user_dir, timestamp_ms);
    
    /* Append hex message ID */
    char *ptr = filename + strlen(filename);
    for (int i = 0; i < MSG_ID_LEN; i++) {
        sprintf(ptr + i * 2, "%02x", msg_id[i]);
    }
    
    /* Write ciphertext to file */
    FILE *f = fopen(filename, "wb");
    if (!f) {
        return ERROR_GENERAL;
    }
    
    fwrite(ciphertext, 1, len, f);
    fclose(f);
    
    chmod(filename, 0600);
    
    return SUCCESS;
}

/* Count pending messages */
int queue_count(const char *username) {
    if (!username) {
        return 0;
    }
    
    char user_dir[512];
    snprintf(user_dir, sizeof(user_dir), "%s/%s", QUEUE_DIR, username);
    
    DIR *dir = opendir(user_dir);
    if (!dir) {
        return 0;
    }
    
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] != '.') {
            count++;
        }
    }
    
    closedir(dir);
    return count;
}

/* Drain queued messages */
int queue_drain(const char *username,
                int (*send_fn)(const void *payload, size_t len, void *ctx),
                void *ctx) {
    if (!username || !send_fn) {
        return ERROR_GENERAL;
    }
    
    char user_dir[512];
    snprintf(user_dir, sizeof(user_dir), "%s/%s", QUEUE_DIR, username);
    
    DIR *dir = opendir(user_dir);
    if (!dir) {
        return 0;
    }
    
    int delivered = 0;
    struct dirent *entry;
    char filepath[1024];
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        
        snprintf(filepath, sizeof(filepath), "%s/%s", user_dir, entry->d_name);
        
        /* Read file */
        FILE *f = fopen(filepath, "rb");
        if (!f) {
            continue;
        }
        
        fseek(f, 0, SEEK_END);
        long file_size = ftell(f);
        fseek(f, 0, SEEK_SET);
        
        uint8_t *payload = malloc(file_size);
        if (!payload) {
            fclose(f);
            continue;
        }
        
        fread(payload, 1, file_size, f);
        fclose(f);
        
        /* Send via callback */
        if (send_fn(payload, file_size, ctx) == SUCCESS) {
            unlink(filepath); /* Delete on successful delivery */
            delivered++;
        }
        
        free(payload);
    }
    
    closedir(dir);
    return delivered;
}

/* Clear all queued messages */
int queue_clear(const char *username) {
    if (!username) {
        return ERROR_GENERAL;
    }
    
    char user_dir[512];
    snprintf(user_dir, sizeof(user_dir), "%s/%s", QUEUE_DIR, username);
    
    DIR *dir = opendir(user_dir);
    if (!dir) {
        return SUCCESS;
    }
    
    struct dirent *entry;
    char filepath[1024];
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        
        snprintf(filepath, sizeof(filepath), "%s/%s", user_dir, entry->d_name);
        unlink(filepath);
    }
    
    closedir(dir);
    rmdir(user_dir);
    
    return SUCCESS;
}
