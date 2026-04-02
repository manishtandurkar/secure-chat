#include "server.h"
#include <string.h>
#include <stdio.h>

#define MAX_ROOMS 50

typedef struct {
    char room_name[MAX_ROOM_NAME_LEN];
    char members[MAX_CLIENTS][MAX_USERNAME_LEN];
    int member_count;
} ChatRoom;

static ChatRoom rooms[MAX_ROOMS];
static int room_count = 0;

/* Find or create room */
static ChatRoom *find_or_create_room(const char *room_name) {
    /* Find existing room */
    for (int i = 0; i < room_count; i++) {
        if (strcmp(rooms[i].room_name, room_name) == 0) {
            return &rooms[i];
        }
    }
    
    /* Create new room */
    if (room_count >= MAX_ROOMS) {
        return NULL;
    }
    
    ChatRoom *room = &rooms[room_count++];
    strncpy(room->room_name, room_name, MAX_ROOM_NAME_LEN - 1);
    room->member_count = 0;
    
    return room;
}

/* Add user to room */
int room_add_member(const char *room_name, const char *username) {
    if (!room_name || !username) {
        return ERROR_GENERAL;
    }
    
    ChatRoom *room = find_or_create_room(room_name);
    if (!room) {
        return ERROR_GENERAL;
    }
    
    /* Check if already member */
    for (int i = 0; i < room->member_count; i++) {
        if (strcmp(room->members[i], username) == 0) {
            return SUCCESS; /* Already in room */
        }
    }
    
    /* Add member */
    if (room->member_count >= MAX_CLIENTS) {
        return ERROR_GENERAL; /* Room full */
    }
    
    strncpy(room->members[room->member_count++], username, MAX_USERNAME_LEN - 1);
    return SUCCESS;
}

/* Remove user from room */
int room_remove_member(const char *room_name, const char *username) {
    if (!room_name || !username) {
        return ERROR_GENERAL;
    }
    
    /* Find room */
    ChatRoom *room = NULL;
    for (int i = 0; i < room_count; i++) {
        if (strcmp(rooms[i].room_name, room_name) == 0) {
            room = &rooms[i];
            break;
        }
    }
    
    if (!room) {
        return SUCCESS; /* Room doesn't exist */
    }
    
    /* Remove member */
    for (int i = 0; i < room->member_count; i++) {
        if (strcmp(room->members[i], username) == 0) {
            /* Shift remaining members */
            for (int j = i; j < room->member_count - 1; j++) {
                strcpy(room->members[j], room->members[j + 1]);
            }
            room->member_count--;
            return SUCCESS;
        }
    }
    
    return SUCCESS;
}

/* Get room members (returns count, fills members array) */
int room_get_members(const char *room_name, char members[][MAX_USERNAME_LEN], int max_members) {
    if (!room_name || !members) {
        return 0;
    }
    
    /* Find room */
    for (int i = 0; i < room_count; i++) {
        if (strcmp(rooms[i].room_name, room_name) == 0) {
            int count = rooms[i].member_count < max_members ? rooms[i].member_count : max_members;
            for (int j = 0; j < count; j++) {
                strncpy(members[j], rooms[i].members[j], MAX_USERNAME_LEN - 1);
            }
            return count;
        }
    }
    
    return 0;
}
