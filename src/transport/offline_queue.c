#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include "offline_queue.h"
#include "common.h"
#include "platform_compat.h"

#define QUEUE_BASE_DIR "data/offline_queue"

static int ensure_dir(const char *path, mode_t mode) {
    struct stat st;
    if (stat(path, &st) == 0) return 0;
    if (mkdir(path, mode) < 0 && errno != EEXIST) {
        perror(path);
        return -1;
    }
    return 0;
}

static int get_user_dir(const char *username, char *path_out, size_t len) {
    /* Sanitize username — allow only [a-zA-Z0-9_-] */
    for (const char *p = username; *p; p++) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return -1;
    }
    snprintf(path_out, len, "%s/%s", QUEUE_BASE_DIR, username);
    return 0;
}

int queue_store(const char *username,
                const void *ciphertext, size_t len,
                const uint8_t msg_id[MSG_ID_LEN]) {
    if (ensure_dir(QUEUE_BASE_DIR, 0700) < 0) return -1;

    char udir[256];
    if (get_user_dir(username, udir, sizeof(udir)) < 0) return -1;
    if (ensure_dir(udir, 0700) < 0) return -1;

    /* Count existing — enforce OFFLINE_QUEUE_MAX */
    if (queue_count(username) >= OFFLINE_QUEUE_MAX) return -1;

    /* Filename: <timestamp_ms>_<msg_id_hex> */
    char hex[MSG_ID_LEN * 2 + 1];
    for (int i = 0; i < MSG_ID_LEN; i++)
        snprintf(hex + i * 2, 3, "%02x", msg_id[i]);

    char fname[512];
    snprintf(fname, sizeof(fname), "%s/%llu_%s",
             udir, (unsigned long long)get_time_ms(), hex);

    FILE *f = fopen(fname, "wb");
    if (!f) { perror(fname); return -1; }
    chmod(fname, 0600);

    uint32_t ulen = (uint32_t)len;
    fwrite(&ulen, 4, 1, f);
    fwrite(ciphertext, 1, len, f);
    fclose(f);
    return 0;
}

int queue_count(const char *username) {
    char udir[256];
    if (get_user_dir(username, udir, sizeof(udir)) < 0) return 0;

    DIR *d = opendir(udir);
    if (!d) return 0;

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        count++;
    }
    closedir(d);
    return count;
}

int queue_drain(const char *username,
                int (*send_fn)(const void *payload, size_t len, void *ctx),
                void *ctx) {
    char udir[256];
    if (get_user_dir(username, udir, sizeof(udir)) < 0) return -1;

    DIR *d = opendir(udir);
    if (!d) return 0;

    /* Collect and sort filenames (ordering by timestamp prefix) */
    char names[OFFLINE_QUEUE_MAX][256];
    int  count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && count < OFFLINE_QUEUE_MAX) {
        if (ent->d_name[0] == '.') continue;
        snprintf(names[count], sizeof(names[count]), "%s", ent->d_name);
        count++;
    }
    closedir(d);

    /* Simple sort by name (timestamp prefix ensures correct order) */
    for (int i = 0; i < count - 1; i++)
        for (int j = i + 1; j < count; j++)
            if (strcmp(names[i], names[j]) > 0) {
                char tmp[256];
                memcpy(tmp, names[i], 256);
                memcpy(names[i], names[j], 256);
                memcpy(names[j], tmp, 256);
            }

    int delivered = 0;
    for (int i = 0; i < count; i++) {
        char fpath[512];
        snprintf(fpath, sizeof(fpath), "%s/%s", udir, names[i]);

        FILE *f = fopen(fpath, "rb");
        if (!f) continue;

        uint32_t ulen = 0;
        if (fread(&ulen, 4, 1, f) != 1 || ulen > MSG_PADDED_SIZE + 64) {
            fclose(f);
            continue;
        }

        uint8_t *buf = malloc(ulen);
        if (!buf) { fclose(f); continue; }

        if (fread(buf, 1, ulen, f) == ulen) {
            if (send_fn(buf, ulen, ctx) >= 0) {
                unlink(fpath);
                delivered++;
            }
        }
        free(buf);
        fclose(f);
    }

    return delivered;
}

int queue_clear(const char *username) {
    char udir[256];
    if (get_user_dir(username, udir, sizeof(udir)) < 0) return -1;

    DIR *d = opendir(udir);
    if (!d) return 0;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char fpath[512];
        snprintf(fpath, sizeof(fpath), "%s/%s", udir, ent->d_name);
        unlink(fpath);
    }
    closedir(d);
    rmdir(udir);
    return 0;
}
