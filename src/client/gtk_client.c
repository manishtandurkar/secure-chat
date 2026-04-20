#define _POSIX_C_SOURCE 200809L

#include <gtk/gtk.h>
#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

typedef struct {
    GtkWidget *window;
    GtkWidget *host_entry;
    GtkWidget *port_entry;
    GtkWidget *username_entry;
    GtkWidget *recipient_entry;
    GtkWidget *message_entry;
    GtkWidget *priority_combo;
    GtkWidget *broadcast_check;
    GtkWidget *connect_button;
    GtkWidget *send_button;
    GtkWidget *status_label;
    GtkWidget *log_view;
    GtkTextBuffer *log_buffer;
    GtkWidget *users_listbox;
    GtkWidget *refresh_users_button;
    GtkWidget *users_count_label;
    ClientState client;
    gboolean connected;
} GtkClientApp;

typedef struct {
    GtkClientApp *app;
    char *line;
} LogEvent;

static void scroll_log_to_end(GtkTextView *view);
static gboolean request_user_list_timer(gpointer data);

static void clear_users_list(GtkClientApp *app) {
    GList *children = gtk_container_get_children(GTK_CONTAINER(app->users_listbox));
    for (GList *it = children; it != NULL; it = it->next) {
        gtk_widget_destroy(GTK_WIDGET(it->data));
    }
    g_list_free(children);
}

static void update_users_count(GtkClientApp *app, int count) {
    char text[64];
    snprintf(text, sizeof(text), "Online users: %d", count);
    gtk_label_set_text(GTK_LABEL(app->users_count_label), text);
}

static void on_user_row_selected(GtkListBox *box, GtkListBoxRow *row, gpointer user_data) {
    (void)box;
    GtkClientApp *app = (GtkClientApp *)user_data;
    if (!row) {
        return;
    }

    GtkWidget *child = gtk_bin_get_child(GTK_BIN(row));
    if (!GTK_IS_LABEL(child)) {
        return;
    }

    const char *username = gtk_label_get_text(GTK_LABEL(child));
    if (username && strlen(username) > 0) {
        gtk_entry_set_text(GTK_ENTRY(app->recipient_entry), username);
    }
}

static void populate_users_list(GtkClientApp *app, const char *csv_users) {
    clear_users_list(app);

    if (!csv_users || strlen(csv_users) == 0) {
        update_users_count(app, 0);
        return;
    }

    char *copy = g_strdup(csv_users);
    if (!copy) {
        return;
    }

    int count = 0;
    char *token = strtok(copy, ",");
    while (token) {
        while (*token == ' ') {
            token++;
        }
        if (*token != '\0') {
            GtkWidget *row_label = gtk_label_new(token);
            gtk_widget_set_halign(row_label, GTK_ALIGN_START);
            gtk_list_box_insert(GTK_LIST_BOX(app->users_listbox), row_label, -1);
            count++;
        }
        token = strtok(NULL, ",");
    }

    g_free(copy);
    gtk_widget_show_all(app->users_listbox);
    update_users_count(app, count);
}

static void append_log_line(GtkClientApp *app, const char *line) {
    GtkTextIter end_iter;
    gtk_text_buffer_get_end_iter(app->log_buffer, &end_iter);
    gtk_text_buffer_insert(app->log_buffer, &end_iter, line, -1);
    gtk_text_buffer_insert(app->log_buffer, &end_iter, "\n", -1);
}

static gboolean append_log_idle(gpointer data) {
    LogEvent *event = (LogEvent *)data;

    if (strncmp(event->line, "[USERS] ", 8) == 0) {
        populate_users_list(event->app, event->line + 8);
    }

    append_log_line(event->app, event->line);
    scroll_log_to_end(GTK_TEXT_VIEW(event->app->log_view));
    g_free(event->line);
    g_free(event);
    return G_SOURCE_REMOVE;
}

static void gtk_log_callback(const char *line, void *user_data) {
    LogEvent *event = g_malloc(sizeof(*event));
    event->app = (GtkClientApp *)user_data;
    event->line = g_strdup(line);
    g_idle_add(append_log_idle, event);
}

static void set_status(GtkClientApp *app, const char *status) {
    gtk_label_set_text(GTK_LABEL(app->status_label), status);
    append_log_line(app, status);
    scroll_log_to_end(GTK_TEXT_VIEW(app->log_view));
}

static void pump_events(void) {
    while (gtk_events_pending()) {
        gtk_main_iteration();
    }
}

static void scroll_log_to_end(GtkTextView *view) {
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(view);
    GtkTextIter end_iter;
    gtk_text_buffer_get_end_iter(buffer, &end_iter);
    gtk_text_view_scroll_to_iter(view, &end_iter, 0.0, FALSE, 0.0, 0.0);
}

static void on_send_clicked(GtkButton *button, gpointer user_data) {
    (void)button;
    GtkClientApp *app = (GtkClientApp *)user_data;
    const char *message = gtk_entry_get_text(GTK_ENTRY(app->message_entry));
    const char *recipient = gtk_entry_get_text(GTK_ENTRY(app->recipient_entry));
    gboolean broadcast = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->broadcast_check));

    gchar *priority_text = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(app->priority_combo));
    uint8_t priority = PRIORITY_NORMAL;
    if (priority_text) {
        if (strcmp(priority_text, "URGENT") == 0) {
            priority = PRIORITY_URGENT;
        } else if (strcmp(priority_text, "CRITICAL") == 0) {
            priority = PRIORITY_CRITICAL;
        }
        g_free(priority_text);
    }

    if (!app->connected) {
        set_status(app, "[!] Not connected yet");
        pump_events();
        return;
    }

    if (!message || strlen(message) == 0) {
        return;
    }

    if (!broadcast && (!recipient || strlen(recipient) == 0)) {
        set_status(app, "[!] Enter recipient or click from Online Users");
        pump_events();
        return;
    }

    char directed[MAX_MSG_LEN];
    if (broadcast) {
        snprintf(directed, sizeof(directed), "@all %s", message);
    } else {
        snprintf(directed, sizeof(directed), "@%s %s", recipient, message);
    }

    if (client_send_chat_message_ex(&app->client, directed, priority) == 0) {
        char line[512];
        if (broadcast) {
            snprintf(line, sizeof(line), "[YOU -> ALL][%s] %s",
                     (priority == PRIORITY_CRITICAL) ? "CRITICAL" :
                     (priority == PRIORITY_URGENT) ? "URGENT" : "NORMAL",
                     message);
        } else {
            snprintf(line, sizeof(line), "[YOU -> %s][%s] %s", recipient,
                     (priority == PRIORITY_CRITICAL) ? "CRITICAL" :
                     (priority == PRIORITY_URGENT) ? "URGENT" : "NORMAL",
                     message);
        }
        append_log_line(app, line);
        gtk_entry_set_text(GTK_ENTRY(app->message_entry), "");
        scroll_log_to_end(GTK_TEXT_VIEW(app->log_view));
        pump_events();
    } else {
        set_status(app, "[!] Failed to send message");
        pump_events();
    }
}

static void on_quick_action_clicked(GtkButton *button, gpointer user_data) {
    GtkClientApp *app = (GtkClientApp *)user_data;
    const char *action = gtk_button_get_label(button);

    if (strcmp(action, "Emergency Broadcast") == 0) {
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app->broadcast_check), TRUE);
        gtk_combo_box_set_active(GTK_COMBO_BOX(app->priority_combo), 2);
        gtk_entry_set_text(GTK_ENTRY(app->message_entry), "Emergency alert: check in immediately.");
    } else if (strcmp(action, "Status Check") == 0) {
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app->broadcast_check), FALSE);
        gtk_combo_box_set_active(GTK_COMBO_BOX(app->priority_combo), 1);
        gtk_entry_set_text(GTK_ENTRY(app->message_entry), "Status check: please confirm availability.");
    } else if (strcmp(action, "Team Sync") == 0) {
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(app->broadcast_check), TRUE);
        gtk_combo_box_set_active(GTK_COMBO_BOX(app->priority_combo), 0);
        gtk_entry_set_text(GTK_ENTRY(app->message_entry), "Team sync in 5 minutes.");
    }

    gtk_widget_grab_focus(app->message_entry);
}

static void on_refresh_users_clicked(GtkButton *button, gpointer user_data) {
    (void)button;
    GtkClientApp *app = (GtkClientApp *)user_data;

    if (!app->connected) {
        return;
    }

    if (client_request_user_list(&app->client) != 0) {
        set_status(app, "[!] Failed to refresh users");
    }
}

static gboolean start_backend(GtkClientApp *app, const char *host, int port, const char *username) {
    client_set_log_callback(gtk_log_callback, app);

    set_status(app, "Starting client backend...");
    pump_events();

    if (tls_init() != SUCCESS) {
        set_status(app, "[ERROR] Failed to initialize OpenSSL");
        return FALSE;
    }

    if (client_init(&app->client, host, port, username) != 0) {
        set_status(app, "[ERROR] Client initialization failed");
        return FALSE;
    }

    if (perform_dh_exchange(&app->client) != 0) {
        set_status(app, "[ERROR] DH exchange failed");
        client_cleanup(&app->client);
        return FALSE;
    }

    if (authenticate_with_server(&app->client) != 0) {
        set_status(app, "[ERROR] Authentication failed");
        client_cleanup(&app->client);
        return FALSE;
    }

    app->connected = TRUE;

    if (pthread_create(&app->client.recv_thread, NULL, recv_thread_func, &app->client) != 0) {
        set_status(app, "[ERROR] Failed to start receive thread");
        client_cleanup(&app->client);
        app->connected = FALSE;
        return FALSE;
    }

    pthread_detach(app->client.recv_thread);
    gtk_widget_set_sensitive(app->send_button, TRUE);
    gtk_widget_set_sensitive(app->refresh_users_button, TRUE);
    gtk_widget_set_sensitive(app->connect_button, FALSE);

    char welcome[128];
    snprintf(welcome, sizeof(welcome), "Connected as %s", username);
    set_status(app, welcome);

    (void)client_request_user_list(&app->client);
    g_timeout_add_seconds(3, request_user_list_timer, app);
    return TRUE;
}

static gboolean request_user_list_timer(gpointer data) {
    GtkClientApp *app = (GtkClientApp *)data;

    if (!app->connected || !app->client.running) {
        return G_SOURCE_REMOVE;
    }

    (void)client_request_user_list(&app->client);
    return G_SOURCE_CONTINUE;
}

static void on_connect_clicked(GtkButton *button, gpointer user_data) {
    (void)button;
    GtkClientApp *app = (GtkClientApp *)user_data;

    const char *host = gtk_entry_get_text(GTK_ENTRY(app->host_entry));
    const char *port_text = gtk_entry_get_text(GTK_ENTRY(app->port_entry));
    const char *username = gtk_entry_get_text(GTK_ENTRY(app->username_entry));

    if (!host || strlen(host) == 0 || !port_text || strlen(port_text) == 0 || !username || strlen(username) == 0) {
        set_status(app, "[!] Host, port, and username are required");
        return;
    }

    int port = atoi(port_text);
    if (port <= 0) {
        set_status(app, "[!] Invalid port number");
        return;
    }

    gtk_widget_set_sensitive(app->connect_button, FALSE);
    set_status(app, "Connecting...");
    pump_events();

    if (!start_backend(app, host, port, username)) {
        gtk_widget_set_sensitive(app->connect_button, TRUE);
        gtk_widget_set_sensitive(app->send_button, FALSE);
        gtk_widget_set_sensitive(app->refresh_users_button, FALSE);
    }
}

static void on_message_activate(GtkEntry *entry, gpointer user_data) {
    (void)entry;
    on_send_clicked(NULL, user_data);
}

static void on_window_destroy(GtkWidget *widget, gpointer user_data) {
    (void)widget;
    GtkClientApp *app = (GtkClientApp *)user_data;

    app->client.running = 0;
    app->connected = FALSE;
    if (app->client.tcp_socket >= 0) {
        shutdown(app->client.tcp_socket, SHUT_RDWR);
    }

    client_cleanup(&app->client);
    gtk_main_quit();
}

static GtkWidget *create_labeled_entry(GtkGrid *grid, const char *label, int row, const char *default_text) {
    GtkWidget *lbl = gtk_label_new(label);
    GtkWidget *entry = gtk_entry_new();

    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0f);
    if (default_text) {
        gtk_entry_set_text(GTK_ENTRY(entry), default_text);
    }

    gtk_grid_attach(grid, lbl, 0, row, 1, 1);
    gtk_grid_attach(grid, entry, 1, row, 1, 1);
    return entry;
}

int main(int argc, char *argv[]) {
    GtkClientApp app;
    memset(&app, 0, sizeof(app));
    app.client.tcp_socket = -1;
    app.client.udp_socket = -1;

    gtk_init(&argc, &argv);

    app.window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app.window), "Adaptive Secure Communication System");
    gtk_window_set_default_size(GTK_WINDOW(app.window), 980, 680);
    gtk_container_set_border_width(GTK_CONTAINER(app.window), 16);

    g_signal_connect(app.window, "destroy", G_CALLBACK(on_window_destroy), &app);

    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_container_add(GTK_CONTAINER(app.window), outer);

    GtkWidget *title = gtk_label_new("Adaptive Secure Communication System");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(title), "title-1");
    gtk_box_pack_start(GTK_BOX(outer), title, FALSE, FALSE, 0);

    GtkWidget *subtitle = gtk_label_new("Secure directed messaging with live online-user selection");
    gtk_widget_set_halign(subtitle, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(outer), subtitle, FALSE, FALSE, 0);

    GtkWidget *config_frame = gtk_frame_new("Connection");
    gtk_box_pack_start(GTK_BOX(outer), config_frame, FALSE, FALSE, 0);

    GtkWidget *config_grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(config_grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(config_grid), 8);
    gtk_container_set_border_width(GTK_CONTAINER(config_grid), 12);
    gtk_container_add(GTK_CONTAINER(config_frame), config_grid);

    app.host_entry = create_labeled_entry(GTK_GRID(config_grid), "Host", 0, "localhost");
    app.port_entry = create_labeled_entry(GTK_GRID(config_grid), "Port", 1, "8080");
    app.username_entry = create_labeled_entry(GTK_GRID(config_grid), "Username", 2, "alice");
    app.recipient_entry = create_labeled_entry(GTK_GRID(config_grid), "To", 3, "bob");

    GtkWidget *priority_label = gtk_label_new("Priority");
    gtk_label_set_xalign(GTK_LABEL(priority_label), 0.0f);
    gtk_grid_attach(GTK_GRID(config_grid), priority_label, 0, 4, 1, 1);

    app.priority_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app.priority_combo), "NORMAL");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app.priority_combo), "URGENT");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app.priority_combo), "CRITICAL");
    gtk_combo_box_set_active(GTK_COMBO_BOX(app.priority_combo), 0);
    gtk_grid_attach(GTK_GRID(config_grid), app.priority_combo, 1, 4, 1, 1);

    app.broadcast_check = gtk_check_button_new_with_label("Broadcast to all online users");
    gtk_grid_attach(GTK_GRID(config_grid), app.broadcast_check, 0, 5, 2, 1);

    app.connect_button = gtk_button_new_with_label("Connect");
    gtk_grid_attach(GTK_GRID(config_grid), app.connect_button, 0, 6, 1, 1);
    g_signal_connect(app.connect_button, "clicked", G_CALLBACK(on_connect_clicked), &app);

    app.refresh_users_button = gtk_button_new_with_label("Refresh Users");
    gtk_widget_set_sensitive(app.refresh_users_button, FALSE);
    gtk_grid_attach(GTK_GRID(config_grid), app.refresh_users_button, 1, 6, 1, 1);
    g_signal_connect(app.refresh_users_button, "clicked", G_CALLBACK(on_refresh_users_clicked), &app);

    GtkWidget *quick_frame = gtk_frame_new("Quick Actions");
    gtk_box_pack_start(GTK_BOX(outer), quick_frame, FALSE, FALSE, 0);

    GtkWidget *quick_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(quick_box), 8);
    gtk_container_add(GTK_CONTAINER(quick_frame), quick_box);

    GtkWidget *btn_emergency = gtk_button_new_with_label("Emergency Broadcast");
    GtkWidget *btn_status = gtk_button_new_with_label("Status Check");
    GtkWidget *btn_sync = gtk_button_new_with_label("Team Sync");

    gtk_box_pack_start(GTK_BOX(quick_box), btn_emergency, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(quick_box), btn_status, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(quick_box), btn_sync, FALSE, FALSE, 0);

    g_signal_connect(btn_emergency, "clicked", G_CALLBACK(on_quick_action_clicked), &app);
    g_signal_connect(btn_status, "clicked", G_CALLBACK(on_quick_action_clicked), &app);
    g_signal_connect(btn_sync, "clicked", G_CALLBACK(on_quick_action_clicked), &app);

    GtkWidget *center = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_box_pack_start(GTK_BOX(outer), center, TRUE, TRUE, 0);

    GtkWidget *users_frame = gtk_frame_new("Online Users");
    gtk_box_pack_start(GTK_BOX(center), users_frame, FALSE, FALSE, 0);
    gtk_widget_set_size_request(users_frame, 220, -1);

    GtkWidget *users_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(users_box), 8);
    gtk_container_add(GTK_CONTAINER(users_frame), users_box);

    app.users_count_label = gtk_label_new("Online users: 0");
    gtk_widget_set_halign(app.users_count_label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(users_box), app.users_count_label, FALSE, FALSE, 0);

    GtkWidget *users_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(users_scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(users_box), users_scroll, TRUE, TRUE, 0);

    app.users_listbox = gtk_list_box_new();
    gtk_container_add(GTK_CONTAINER(users_scroll), app.users_listbox);
    g_signal_connect(app.users_listbox, "row-selected", G_CALLBACK(on_user_row_selected), &app);

    GtkWidget *log_frame = gtk_frame_new("Conversation Log");
    gtk_box_pack_start(GTK_BOX(center), log_frame, TRUE, TRUE, 0);

    GtkWidget *scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_set_border_width(GTK_CONTAINER(scrolled), 8);
    gtk_container_add(GTK_CONTAINER(log_frame), scrolled);

    GtkWidget *text_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text_view), GTK_WRAP_WORD_CHAR);
    gtk_container_add(GTK_CONTAINER(scrolled), text_view);
    app.log_view = text_view;
    app.log_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));

    GtkWidget *compose_frame = gtk_frame_new("Message");
    gtk_box_pack_start(GTK_BOX(outer), compose_frame, FALSE, FALSE, 0);

    GtkWidget *compose_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(compose_box), 12);
    gtk_container_add(GTK_CONTAINER(compose_frame), compose_box);

    app.message_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app.message_entry), "Type message and press Enter");
    gtk_box_pack_start(GTK_BOX(compose_box), app.message_entry, TRUE, TRUE, 0);
    g_signal_connect(app.message_entry, "activate", G_CALLBACK(on_message_activate), &app);

    app.send_button = gtk_button_new_with_label("Send");
    gtk_widget_set_sensitive(app.send_button, FALSE);
    gtk_box_pack_start(GTK_BOX(compose_box), app.send_button, FALSE, FALSE, 0);
    g_signal_connect(app.send_button, "clicked", G_CALLBACK(on_send_clicked), &app);

    app.status_label = gtk_label_new("Ready");
    gtk_widget_set_halign(app.status_label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(outer), app.status_label, FALSE, FALSE, 0);

    gtk_widget_show_all(app.window);
    gtk_widget_set_sensitive(app.send_button, FALSE);
    gtk_widget_set_sensitive(app.refresh_users_button, FALSE);

    gtk_main();
    return 0;
}
