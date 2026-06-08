#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "server.h"
#include "tls_layer.h"
#include "common.h"

#define MAX_ROOMS     32
#define MAX_ROOM_MEMBERS 50

typedef struct {
    char name[MAX_ROOM_NAME_LEN];
    char members[MAX_ROOM_MEMBERS][MAX_USERNAME_LEN];
    int  member_count;
} Room;

static Room    rooms[MAX_ROOMS];
static int     room_count = 0;
static pthread_mutex_t room_lock = PTHREAD_MUTEX_INITIALIZER;

static Room *find_room(const char *name) {
    for (int i = 0; i < room_count; i++)
        if (strcmp(rooms[i].name, name) == 0) return &rooms[i];
    return NULL;
}

int room_join(const char *room, const char *username) {
    pthread_mutex_lock(&room_lock);

    Room *r = find_room(room);
    if (!r) {
        if (room_count >= MAX_ROOMS) {
            pthread_mutex_unlock(&room_lock);
            return -1;
        }
        r = &rooms[room_count++];
        memset(r, 0, sizeof(*r));
        strncpy(r->name, room, MAX_ROOM_NAME_LEN - 1);
    }

    /* Check already member */
    for (int i = 0; i < r->member_count; i++)
        if (strcmp(r->members[i], username) == 0) {
            pthread_mutex_unlock(&room_lock);
            return 0;
        }

    if (r->member_count >= MAX_ROOM_MEMBERS) {
        pthread_mutex_unlock(&room_lock);
        return -1;
    }

    strncpy(r->members[r->member_count++], username, MAX_USERNAME_LEN - 1);
    pthread_mutex_unlock(&room_lock);
    return 0;
}

int room_leave(const char *room, const char *username) {
    pthread_mutex_lock(&room_lock);

    Room *r = find_room(room);
    if (!r) { pthread_mutex_unlock(&room_lock); return -1; }

    for (int i = 0; i < r->member_count; i++) {
        if (strcmp(r->members[i], username) == 0) {
            r->members[i][0] = '\0';
            /* Compact */
            for (int j = i; j < r->member_count - 1; j++)
                memcpy(r->members[j], r->members[j+1], MAX_USERNAME_LEN);
            r->member_count--;
            break;
        }
    }

    pthread_mutex_unlock(&room_lock);
    return 0;
}

void room_broadcast(const char *room, const char *sender,
                    const void *payload, size_t len, SSL_CTX *ctx) {
    (void)ctx;
    pthread_mutex_lock(&room_lock);

    Room *r = find_room(room);
    if (!r) { pthread_mutex_unlock(&room_lock); return; }

    for (int i = 0; i < r->member_count; i++) {
        if (strcmp(r->members[i], sender) == 0) continue;
        ClientEntry *entry = client_table_find(r->members[i]);
        if (entry && entry->ssl && entry->active) {
            uint32_t plen_net = htonl((uint32_t)len);
            tls_send(entry->ssl, &plen_net, 4);
            tls_send(entry->ssl, payload, (int)len);
        }
    }

    pthread_mutex_unlock(&room_lock);
}
