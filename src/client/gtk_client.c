/*
 * GTK3 GUI client — requires libgtk-3-dev
 * Build: make gtk-client   Run: ./bin/client_gtk
 */
#ifdef HAVE_GTK

#include <gtk/gtk.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "client.h"
#include "priority_queue.h"
#include "message.h"
#include "common.h"
#include "platform_compat.h"

/* ── Globals ──────────────────────────────────────────────────── */
static ClientContext g_ctx             = {0};
static GtkWidget    *g_window          = NULL;
static GtkWidget    *g_text_view       = NULL;
static GtkWidget    *g_entry           = NULL;
static GtkWidget    *g_to_button       = NULL;
static GtkWidget    *g_all_check       = NULL;
static GtkWidget    *g_users_check_box = NULL;
static GtkWidget    *g_users_list      = NULL;
static GtkWidget    *g_status_bar      = NULL;
static GtkWidget    *g_radio_normal    = NULL;
static GtkWidget    *g_radio_urgent    = NULL;
static GtkWidget    *g_radio_critical  = NULL;
static GtkWidget    *g_to_hint         = NULL;
static GtkWidget    *g_direct_entry    = NULL;  /* manual offline username entry */

/* ── Helpers ──────────────────────────────────────────────────── */
static gboolean on_delete_event(GtkWidget *w, GdkEvent *e, gpointer d) {
    (void)w; (void)e; (void)d;
    gtk_main_quit();
    return FALSE;
}

/* ── Chat text view ───────────────────────────────────────────── */
static void chat_scroll_to_bottom(void) {
    GtkAdjustment *adj = gtk_scrolled_window_get_vadjustment(
        GTK_SCROLLED_WINDOW(gtk_widget_get_parent(g_text_view)));
    gtk_adjustment_set_value(adj, gtk_adjustment_get_upper(adj));
}

/* Append a chat line with rich formatting (must run on GTK main thread) */
/* Append a gray italic system notice: ── text ── */
static void chat_system(const char *msg) {
    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(g_text_view));
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buf, &end);
    char line[512];
    snprintf(line, sizeof(line), "── %s ──\n", msg);
    gtk_text_buffer_insert_with_tags_by_name(buf, &end, line, -1, "sys", NULL);
    chat_scroll_to_bottom();
}

static gboolean system_idle(gpointer data) {
    chat_system((char *)data);
    g_free(data);
    return G_SOURCE_REMOVE;
}

static void on_system_cb(const char *msg) {
    gdk_threads_add_idle(system_idle, g_strdup(msg));
}

static void chat_append(const char *sender, const char *text,
                        uint8_t priority, uint8_t flags, gboolean is_self) {
    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(g_text_view));
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buf, &end);

    /* Mark the line start — iters are invalidated by insertions, marks are not */
    GtkTextMark *line_mark = gtk_text_buffer_create_mark(buf, NULL, &end, TRUE);

    /* Timestamp */
    time_t now = time(NULL);
    char tbuf[12];
    strftime(tbuf, sizeof(tbuf), "[%H:%M:%S] ", localtime(&now));
    gtk_text_buffer_insert_with_tags_by_name(buf, &end, tbuf, -1, "ts", NULL);

    /* Priority badge */
    if (priority == PRIORITY_CRITICAL)
        gtk_text_buffer_insert_with_tags_by_name(buf, &end, "CRITICAL ", -1, "critical", NULL);
    else if (priority == PRIORITY_URGENT)
        gtk_text_buffer_insert_with_tags_by_name(buf, &end, "URGENT ", -1, "urgent", NULL);

    /* Offline replay badge */
    if (flags & MSG_FLAG_IS_OFFLINE_REPLAY)
        gtk_text_buffer_insert_with_tags_by_name(buf, &end, "[queued] ", -1, "queued", NULL);

    /* Sender */
    const char *stag = is_self ? "self" : "other";
    gtk_text_buffer_insert_with_tags_by_name(buf, &end, sender, -1, stag, NULL);
    gtk_text_buffer_insert(buf, &end, ":  ", -1);

    /* Message body */
    gtk_text_buffer_insert(buf, &end, text, -1);
    gtk_text_buffer_insert(buf, &end, "\n", -1);

    /* Apply priority color across the entire line using the mark */
    if (priority == PRIORITY_CRITICAL || priority == PRIORITY_URGENT) {
        GtkTextIter line_start;
        gtk_text_buffer_get_iter_at_mark(buf, &line_start, line_mark);
        gtk_text_buffer_get_end_iter(buf, &end);
        const char *ptag = (priority == PRIORITY_CRITICAL) ? "critical" : "urgent";
        gtk_text_buffer_apply_tag_by_name(buf, ptag, &line_start, &end);
    }
    gtk_text_buffer_delete_mark(buf, line_mark);

    chat_scroll_to_bottom();
}

/* Idle struct for cross-thread message delivery */
typedef struct { char sender[MAX_USERNAME_LEN + 32]; char text[MAX_MSG_LEN]; uint8_t priority; uint8_t flags; } MsgData;

static gboolean message_idle(gpointer data) {
    MsgData *md = (MsgData *)data;
    chat_append(md->sender, md->text, md->priority, md->flags, FALSE);
    g_free(md);
    return G_SOURCE_REMOVE;
}

static void on_message_cb(const char *sender, const char *text,
                           uint8_t priority, uint8_t flags) {
    MsgData *md = g_new(MsgData, 1);
    strncpy(md->sender, sender, sizeof(md->sender) - 1);
    strncpy(md->text,   text,   sizeof(md->text)   - 1);
    md->priority = priority;
    md->flags    = flags;
    gdk_threads_add_idle(message_idle, md);
}

/* ── "To" dropdown label sync ─────────────────────────────────── */
static void sync_to_label(void) {
    if (!g_to_button) return;

    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(g_all_check))) {
        gtk_button_set_label(GTK_BUTTON(g_to_button), "To: Everyone (All)");
        return;
    }

    GList *kids = gtk_container_get_children(GTK_CONTAINER(g_users_check_box));
    GString *names = g_string_new("To: ");
    gboolean any = FALSE;
    for (GList *l = kids; l; l = l->next) {
        GtkWidget *w = GTK_WIDGET(l->data);
        if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w))) {
            if (any) g_string_append(names, ", ");
            g_string_append(names, gtk_button_get_label(GTK_BUTTON(w)));
            any = TRUE;
        }
    }
    g_list_free(kids);

    if (!any) g_string_append(names, "— select recipients —");
    gtk_button_set_label(GTK_BUTTON(g_to_button), names->str);
    g_string_free(names, TRUE);
}

static void on_recipient_toggled(GtkToggleButton *btn, gpointer data) {
    (void)btn; (void)data;
    sync_to_label();
}

/* When "Everyone" is checked, uncheck all individual users */
static void on_all_toggled(GtkToggleButton *btn, gpointer data) {
    (void)data;
    if (gtk_toggle_button_get_active(btn)) {
        GList *kids = gtk_container_get_children(GTK_CONTAINER(g_users_check_box));
        for (GList *l = kids; l; l = l->next)
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(l->data), FALSE);
        g_list_free(kids);
    }
    sync_to_label();
}

/* ── Send ─────────────────────────────────────────────────────── */
static void on_send_clicked(GtkButton *btn, gpointer data) {
    (void)btn; (void)data;
    const char *text = gtk_entry_get_text(GTK_ENTRY(g_entry));
    if (!text || !text[0]) return;

    uint8_t priority = PRIORITY_NORMAL;
    if (g_radio_critical && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(g_radio_critical)))
        priority = PRIORITY_CRITICAL;
    else if (g_radio_urgent && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(g_radio_urgent)))
        priority = PRIORITY_URGENT;

    /* Direct entry overrides dropdown — allows sending to offline users */
    const char *direct = gtk_entry_get_text(GTK_ENTRY(g_direct_entry));
    if (direct && direct[0]) {
        client_send_chat_message_ex(&g_ctx, direct, text, priority);
        char echo_label[MAX_USERNAME_LEN + 8];
        snprintf(echo_label, sizeof(echo_label), "You → %s", direct);
        chat_append(echo_label, text, priority, 0, TRUE);
        gtk_entry_set_text(GTK_ENTRY(g_direct_entry), "");
        gtk_entry_set_text(GTK_ENTRY(g_entry), "");
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(g_radio_normal), TRUE);
        gtk_widget_grab_focus(g_entry);
        return;
    }

    /* Require at least one recipient selected in dropdown */
    gboolean all_checked = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(g_all_check));
    if (!all_checked) {
        GList *kids = gtk_container_get_children(GTK_CONTAINER(g_users_check_box));
        gboolean any = FALSE;
        for (GList *l = kids; l; l = l->next)
            if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(l->data))) { any = TRUE; break; }
        g_list_free(kids);
        if (!any) {
            gtk_label_set_markup(GTK_LABEL(g_to_hint),
                "<span foreground='red'>Select a recipient, check Everyone (All), or type a username directly</span>");
            return;
        }
    }
    gtk_label_set_text(GTK_LABEL(g_to_hint), "");

    /* Build display label for echo ("You → bob" or "You → All") */
    char echo_label[MAX_USERNAME_LEN * 4];

    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(g_all_check))) {
        client_send_chat_message_ex(&g_ctx, "", text, priority);
        snprintf(echo_label, sizeof(echo_label), "You → All");
    } else {
        GList *kids = gtk_container_get_children(GTK_CONTAINER(g_users_check_box));
        GString *names = g_string_new("You → ");
        gboolean first = TRUE;
        for (GList *l = kids; l; l = l->next) {
            GtkWidget *w = GTK_WIDGET(l->data);
            if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w))) {
                const char *name = gtk_button_get_label(GTK_BUTTON(w));
                client_send_chat_message_ex(&g_ctx, name, text, priority);
                if (!first) g_string_append(names, ", ");
                g_string_append(names, name);
                first = FALSE;
            }
        }
        g_list_free(kids);
        strncpy(echo_label, names->str, sizeof(echo_label) - 1);
        echo_label[sizeof(echo_label) - 1] = '\0';
        g_string_free(names, TRUE);
    }

    /* Echo sent message in own chat view */
    chat_append(echo_label, text, priority, 0, TRUE);

    gtk_entry_set_text(GTK_ENTRY(g_entry), "");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(g_radio_normal), TRUE);
    gtk_widget_grab_focus(g_entry);
}

static void on_entry_activate(GtkEntry *e, gpointer d) {
    (void)e; (void)d;
    on_send_clicked(NULL, NULL);
}

static void on_refresh_users(GtkButton *btn, gpointer data) {
    (void)btn; (void)data;
    client_request_user_list(&g_ctx);
}

/* ── Users list update (called from recv thread via idle) ─────── */
typedef struct { char *list; char *me; } UsersIdleData;

static gboolean update_users_idle(gpointer data) {
    UsersIdleData *ud = (UsersIdleData *)data;

    /* ── Rebuild right-panel display list ── */
    GList *kids = gtk_container_get_children(GTK_CONTAINER(g_users_list));
    for (GList *l = kids; l; l = l->next)
        gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(kids);

    /* ── Rebuild checkbox box in popover ── */
    kids = gtk_container_get_children(GTK_CONTAINER(g_users_check_box));
    for (GList *l = kids; l; l = l->next)
        gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(kids);

    char *copy = g_strdup(ud->list);
    char *token = strtok(copy, ",");
    while (token) {
        /* Skip self in both panels */
        if (ud->me && strcmp(token, ud->me) == 0) {
            token = strtok(NULL, ",");
            continue;
        }

        /* Right panel label */
        GtkWidget *lbl = gtk_label_new(token);
        gtk_label_set_xalign(GTK_LABEL(lbl), 0.0f);
        gtk_list_box_insert(GTK_LIST_BOX(g_users_list), lbl, -1);

        /* Recipient checkbox in dropdown */
        if (TRUE) {
            GtkWidget *chk = gtk_check_button_new_with_label(token);
            g_signal_connect(chk, "toggled", G_CALLBACK(on_recipient_toggled), NULL);
            gtk_box_pack_start(GTK_BOX(g_users_check_box), chk, FALSE, FALSE, 0);
        }

        token = strtok(NULL, ",");
    }
    g_free(copy);

    gtk_widget_show_all(g_users_list);
    gtk_widget_show_all(g_users_check_box);

    sync_to_label();

    g_free(ud->list);
    g_free(ud->me);
    g_free(ud);
    return G_SOURCE_REMOVE;
}

static void on_users_cb(const char *list) {
    UsersIdleData *ud = g_new(UsersIdleData, 1);
    ud->list = g_strdup(list);
    ud->me   = g_strdup(g_ctx.username);
    gdk_threads_add_idle(update_users_idle, ud);
}

/* ── Build main chat window ───────────────────────────────────── */
static void build_chat_window(const char *username) {
    g_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    char title[64];
    snprintf(title, sizeof(title), "Secure Chat — %s", username);
    gtk_window_set_title(GTK_WINDOW(g_window), title);
    gtk_window_set_default_size(GTK_WINDOW(g_window), 960, 620);
    g_signal_connect(g_window, "delete-event", G_CALLBACK(on_delete_event), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_container_set_border_width(GTK_CONTAINER(g_window), 6);
    gtk_container_add(GTK_CONTAINER(g_window), vbox);

    /* "Logged in as: alice" */
    char me_text[MAX_USERNAME_LEN + 32];
    snprintf(me_text, sizeof(me_text), "Logged in as:  <b>%s</b>", username);
    g_status_bar = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(g_status_bar), me_text);
    gtk_label_set_xalign(GTK_LABEL(g_status_bar), 0.0f);
    gtk_box_pack_start(GTK_BOX(vbox), g_status_bar, FALSE, FALSE, 2);

    gtk_box_pack_start(GTK_BOX(vbox),
                       gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 0);

    /* Main area: chat + right panel */
    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, TRUE, TRUE, 0);

    /* Chat text view */
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    g_text_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(g_text_view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(g_text_view), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(g_text_view), 6);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(g_text_view), 6);
    gtk_container_add(GTK_CONTAINER(scroll), g_text_view);

    /* Text tags for rich formatting */
    GtkTextBuffer *tbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(g_text_view));
    gtk_text_buffer_create_tag(tbuf, "ts",
        "foreground", "#888888", "font", "monospace 9", NULL);
    gtk_text_buffer_create_tag(tbuf, "self",
        "foreground", "#2e7d32", "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(tbuf, "other",
        "foreground", "#1565c0", "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(tbuf, "urgent",
        "foreground", "#e65100", "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(tbuf, "critical",
        "foreground", "#b71c1c", "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(tbuf, "queued",
        "foreground", "#888888", "style", PANGO_STYLE_ITALIC, NULL);
    gtk_text_buffer_create_tag(tbuf, "sys",
        "foreground", "#888888", "style", PANGO_STYLE_ITALIC, NULL);
    gtk_box_pack_start(GTK_BOX(hbox), scroll, TRUE, TRUE, 0);

    /* Right panel: online users display */
    GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_size_request(right, 160, -1);
    gtk_box_pack_start(GTK_BOX(hbox), right, FALSE, FALSE, 0);

    GtkWidget *ul = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(ul), "<b>Online Users</b>");
    gtk_box_pack_start(GTK_BOX(right), ul, FALSE, FALSE, 0);

    GtkWidget *users_scroll = gtk_scrolled_window_new(NULL, NULL);
    g_users_list = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(g_users_list), GTK_SELECTION_NONE);
    gtk_container_add(GTK_CONTAINER(users_scroll), g_users_list);
    gtk_box_pack_start(GTK_BOX(right), users_scroll, TRUE, TRUE, 0);

    GtkWidget *refresh_btn = gtk_button_new_with_label("Refresh");
    g_signal_connect(refresh_btn, "clicked", G_CALLBACK(on_refresh_users), NULL);
    gtk_box_pack_start(GTK_BOX(right), refresh_btn, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(vbox),
                       gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 0);

    /* "To" row: MenuButton with checkbox popover */
    GtkWidget *to_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(vbox), to_row, FALSE, FALSE, 2);

    GtkWidget *to_lbl = gtk_label_new("To:");
    gtk_box_pack_start(GTK_BOX(to_row), to_lbl, FALSE, FALSE, 4);

    g_to_button = gtk_menu_button_new();
    gtk_button_set_label(GTK_BUTTON(g_to_button), "To: — select recipients —");
    gtk_widget_set_hexpand(g_to_button, TRUE);
    gtk_box_pack_start(GTK_BOX(to_row), g_to_button, TRUE, TRUE, 0);

    /* Build the popover */
    GtkWidget *popover   = gtk_popover_new(g_to_button);
    GtkWidget *pop_box   = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_container_set_border_width(GTK_CONTAINER(pop_box), 8);
    gtk_widget_set_size_request(pop_box, 200, -1);
    gtk_container_add(GTK_CONTAINER(popover), pop_box);

    g_all_check = gtk_check_button_new_with_label("Everyone (All)");
    g_signal_connect(g_all_check, "toggled", G_CALLBACK(on_all_toggled), NULL);
    gtk_box_pack_start(GTK_BOX(pop_box), g_all_check, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(pop_box),
                       gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 2);

    g_users_check_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_box_pack_start(GTK_BOX(pop_box), g_users_check_box, FALSE, FALSE, 0);

    gtk_widget_show_all(pop_box);
    gtk_menu_button_set_popover(GTK_MENU_BUTTON(g_to_button), popover);

    /* Direct entry for offline/unlisted users */
    g_direct_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(g_direct_entry), "or type username directly");
    gtk_widget_set_size_request(g_direct_entry, 180, -1);
    gtk_box_pack_start(GTK_BOX(to_row), g_direct_entry, FALSE, FALSE, 0);

    /* Hint label shown when Send is clicked with no recipient */
    g_to_hint = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(g_to_hint), 0.0f);
    gtk_box_pack_start(GTK_BOX(vbox), g_to_hint, FALSE, FALSE, 0);

    /* Priority radio buttons */
    GtkWidget *prio_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(vbox), prio_row, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(prio_row), gtk_label_new("Priority:"), FALSE, FALSE, 4);

    g_radio_normal = gtk_radio_button_new_with_label(NULL, "Normal");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(g_radio_normal), TRUE);
    gtk_box_pack_start(GTK_BOX(prio_row), g_radio_normal, FALSE, FALSE, 0);

    g_radio_urgent = gtk_radio_button_new_with_label_from_widget(
        GTK_RADIO_BUTTON(g_radio_normal), "Urgent");
    gtk_box_pack_start(GTK_BOX(prio_row), g_radio_urgent, FALSE, FALSE, 0);

    g_radio_critical = gtk_radio_button_new_with_label_from_widget(
        GTK_RADIO_BUTTON(g_radio_normal), "Critical");
    gtk_box_pack_start(GTK_BOX(prio_row), g_radio_critical, FALSE, FALSE, 0);

    /* Message entry + Send */
    GtkWidget *msg_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(vbox), msg_row, FALSE, FALSE, 4);

    g_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(g_entry), "Type a message…");
    g_signal_connect(g_entry, "activate", G_CALLBACK(on_entry_activate), NULL);
    gtk_box_pack_start(GTK_BOX(msg_row), g_entry, TRUE, TRUE, 0);

    GtkWidget *send_btn = gtk_button_new_with_label("Send");
    g_signal_connect(send_btn, "clicked", G_CALLBACK(on_send_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(msg_row), send_btn, FALSE, FALSE, 0);

    gtk_widget_show_all(g_window);
    gtk_widget_grab_focus(g_entry);

    /* Fetch user list on connect and every 5 seconds after */
    client_request_user_list(&g_ctx);
    g_timeout_add_seconds(5, (GSourceFunc)client_request_user_list, &g_ctx);
}

/* ── Login window ─────────────────────────────────────────────── */
static void on_connect_clicked(GtkButton *btn, gpointer data) {
    (void)btn;
    GtkWidget **fields    = (GtkWidget **)data;
    GtkWidget *host_entry  = fields[0];
    GtkWidget *port_entry  = fields[1];
    GtkWidget *user_entry  = fields[2];
    GtkWidget *err_label   = fields[3];
    GtkWidget *login_win   = fields[4];

    const char *host     = gtk_entry_get_text(GTK_ENTRY(host_entry));
    const char *port_str = gtk_entry_get_text(GTK_ENTRY(port_entry));
    const char *username = gtk_entry_get_text(GTK_ENTRY(user_entry));

    if (!username || username[0] == '\0') {
        gtk_label_set_text(GTK_LABEL(err_label), "Username cannot be empty.");
        return;
    }
    if (!host || host[0] == '\0') host = "localhost";
    int port = (port_str && port_str[0]) ? atoi(port_str) : SERVER_PORT;

    gtk_label_set_text(GTK_LABEL(err_label), "Connecting…");
    while (gtk_events_pending()) gtk_main_iteration();

    memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.message_callback = on_message_cb;
    g_ctx.system_callback  = on_system_cb;
    g_ctx.users_callback   = on_users_cb;

    if (client_connect(&g_ctx, host, port, username) != 0) {
        const char *reason = g_ctx.connect_error[0]
                             ? g_ctx.connect_error
                             : "Connection failed. Is the server running?";
        gtk_label_set_text(GTK_LABEL(err_label), reason);
        return;
    }

    char saved[MAX_USERNAME_LEN];
    strncpy(saved, username, MAX_USERNAME_LEN - 1);
    saved[MAX_USERNAME_LEN - 1] = '\0';

    gtk_widget_destroy(login_win);
    build_chat_window(saved);
}

static void show_login_window(void) {
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(win), "Secure Chat — Connect");
    gtk_window_set_default_size(GTK_WINDOW(win), 380, 260);
    gtk_window_set_resizable(GTK_WINDOW(win), FALSE);
    gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER);
    g_signal_connect(win, "delete-event", G_CALLBACK(on_delete_event), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 20);
    gtk_container_add(GTK_CONTAINER(win), vbox);

    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<b><big>Secure Chat</big></b>");
    gtk_box_pack_start(GTK_BOX(vbox), title, FALSE, FALSE, 4);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_box_pack_start(GTK_BOX(vbox), grid, FALSE, FALSE, 0);

    GtkWidget *host_lbl = gtk_label_new("Host:");
    gtk_label_set_xalign(GTK_LABEL(host_lbl), 1.0f);
    GtkWidget *host_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(host_entry), "localhost");
    gtk_widget_set_hexpand(host_entry, TRUE);
    gtk_grid_attach(GTK_GRID(grid), host_lbl,   0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), host_entry, 1, 0, 1, 1);

    GtkWidget *port_lbl = gtk_label_new("Port:");
    gtk_label_set_xalign(GTK_LABEL(port_lbl), 1.0f);
    GtkWidget *port_entry = gtk_entry_new();
    char port_default[8];
    snprintf(port_default, sizeof(port_default), "%d", SERVER_PORT);
    gtk_entry_set_text(GTK_ENTRY(port_entry), port_default);
    gtk_grid_attach(GTK_GRID(grid), port_lbl,   0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), port_entry, 1, 1, 1, 1);

    GtkWidget *user_lbl = gtk_label_new("Username:");
    gtk_label_set_xalign(GTK_LABEL(user_lbl), 1.0f);
    GtkWidget *user_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(user_entry), "e.g. alice");
    gtk_grid_attach(GTK_GRID(grid), user_lbl,   0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), user_entry, 1, 2, 1, 1);

    GtkWidget *err_label = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(err_label), 0.5f);
    gtk_box_pack_start(GTK_BOX(vbox), err_label, FALSE, FALSE, 0);

    GtkWidget *connect_btn = gtk_button_new_with_label("Connect");
    gtk_box_pack_start(GTK_BOX(vbox), connect_btn, FALSE, FALSE, 4);

    static GtkWidget *fields[5];
    fields[0] = host_entry;
    fields[1] = port_entry;
    fields[2] = user_entry;
    fields[3] = err_label;
    fields[4] = win;

    g_signal_connect(connect_btn, "clicked", G_CALLBACK(on_connect_clicked), fields);
    g_signal_connect(user_entry,  "activate", G_CALLBACK(on_connect_clicked), fields);

    gtk_widget_show_all(win);
    gtk_widget_grab_focus(user_entry);
    gtk_editable_select_region(GTK_EDITABLE(host_entry), 0, 0);
    gtk_editable_select_region(GTK_EDITABLE(port_entry), 0, 0);
}

/* ── Entry point ──────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);
    show_login_window();
    gtk_main();
    if (g_ctx.running)
        client_disconnect(&g_ctx);
    return 0;
}

#else
#include <stdio.h>
int main(void) {
    fprintf(stderr, "GTK client not built — recompile with: make gtk-client\n");
    return 1;
}
#endif /* HAVE_GTK */
