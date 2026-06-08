#ifndef INTRUSION_H
#define INTRUSION_H

#include "adaptive_engine.h"

void ids_record_auth_fail(const char *ip_str, Metrics *metrics);
void ids_record_replay(const char *ip_str, Metrics *metrics);
int  ids_is_blocked(const char *ip_str);
void ids_expire_blocks(void);
void ids_log_event(const char *event_type, const char *ip_str);
void ids_init(void);

#endif /* INTRUSION_H */
