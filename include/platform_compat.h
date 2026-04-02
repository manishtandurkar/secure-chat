/**
 * platform_compat.h - Cross-platform compatibility layer for socket operations
 * 
 * Provides unified socket API for Windows (Winsock2) and Linux (POSIX).
 * Handles platform-specific differences in socket types, functions, and headers.
 * 
 * Usage: Include this header BEFORE any other socket-related headers.
 */

#ifndef PLATFORM_COMPAT_H
#define PLATFORM_COMPAT_H

/* ===================================================================
 * Platform Detection
 * =================================================================== */

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    #define PLATFORM_WINDOWS
#elif defined(__linux__)
    #define PLATFORM_LINUX
#elif defined(__unix__) || defined(__APPLE__)
    #define PLATFORM_UNIX
#else
    #error "Unsupported platform"
#endif

/* ===================================================================
 * Windows-Specific Includes and Definitions
 * =================================================================== */

#ifdef PLATFORM_WINDOWS

/* Winsock2 must be included before windows.h to avoid conflicts */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#include <process.h>

/* Link against Winsock library */
#pragma comment(lib, "ws2_32.lib")

/* Socket type mapping */
typedef SOCKET socket_t;
#define INVALID_SOCKET_VALUE INVALID_SOCKET
#define SOCKET_ERROR_VALUE SOCKET_ERROR

/* Function name mappings */
#define socket_close(s) closesocket(s)
#define socket_errno WSAGetLastError()
#define socket_would_block(err) ((err) == WSAEWOULDBLOCK)
#define socket_in_progress(err) ((err) == WSAEINPROGRESS)
#define socket_interrupted(err) ((err) == WSAEINTR)

/* Error code mappings */
#define ERRNO_WOULDBLOCK WSAEWOULDBLOCK
#define ERRNO_INPROGRESS WSAEINPROGRESS
#define ERRNO_EINTR WSAEINTR
#define ERRNO_ECONNREFUSED WSAECONNREFUSED
#define ERRNO_ETIMEDOUT WSAETIMEDOUT
#define ERRNO_EADDRINUSE WSAEADDRINUSE

/* POSIX-like function mappings */
#define close(fd) _close(fd)
#define read(fd, buf, len) _read(fd, buf, len)
#define write(fd, buf, len) _write(fd, buf, len)
#define getpid() _getpid()
#define snprintf _snprintf

/* socklen_t is defined in ws2tcpip.h on newer Windows, but provide fallback */
#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

/* Windows doesn't have these POSIX signal macros */
#ifndef SIGPIPE
#define SIGPIPE 13
#endif

/* Windows doesn't have fork() - provide compile-time error */
#define fork() fork_not_supported_on_windows_use_threads_instead()
static inline int fork_not_supported_on_windows_use_threads_instead(void) {
    fprintf(stderr, "ERROR: fork() is not supported on Windows. Use CreateThread or _beginthread.\n");
    exit(1);
    return -1;
}

/* Windows doesn't have these wait-related functions */
#define waitpid(pid, status, options) waitpid_not_supported_on_windows()
static inline int waitpid_not_supported_on_windows(void) {
    fprintf(stderr, "ERROR: waitpid() is not supported on Windows.\n");
    return -1;
}

#ifndef WNOHANG
#define WNOHANG 1
#endif

/* Windows doesn't have sigaction */
struct sigaction {
    void (*sa_handler)(int);
    int sa_flags;
    int sa_mask;
};
#define SA_RESTART 0
#define sigaction(sig, act, oact) signal(sig, (act)->sa_handler)
#define sigemptyset(set) (*(set) = 0)

/* Windows doesn't have sys/wait.h signal constants */
#ifndef SIGCHLD
#define SIGCHLD 0
#endif

/* Initialize Winsock (call once at program start) */
static inline int platform_socket_init(void) {
    WSADATA wsa_data;
    int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", result);
        return -1;
    }
    return 0;
}

/* Cleanup Winsock (call once at program exit) */
static inline void platform_socket_cleanup(void) {
    WSACleanup();
}

/* Set socket to non-blocking mode (Windows version) */
static inline int platform_set_nonblocking(socket_t sockfd) {
    u_long mode = 1;
    return ioctlsocket(sockfd, FIONBIO, &mode);
}

/* ===================================================================
 * Linux/UNIX-Specific Includes and Definitions
 * =================================================================== */

#else /* PLATFORM_LINUX or PLATFORM_UNIX */

/* POSIX socket headers */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

/* Socket type mapping */
typedef int socket_t;
#define INVALID_SOCKET_VALUE (-1)
#define SOCKET_ERROR_VALUE (-1)

/* Function name mappings */
#define socket_close(s) close(s)
#define socket_errno errno
#define socket_would_block(err) ((err) == EWOULDBLOCK || (err) == EAGAIN)
#define socket_in_progress(err) ((err) == EINPROGRESS)
#define socket_interrupted(err) ((err) == EINTR)

/* Error code mappings */
#define ERRNO_WOULDBLOCK EWOULDBLOCK
#define ERRNO_INPROGRESS EINPROGRESS
#define ERRNO_EINTR EINTR
#define ERRNO_ECONNREFUSED ECONNREFUSED
#define ERRNO_ETIMEDOUT ETIMEDOUT
#define ERRNO_EADDRINUSE EADDRINUSE

/* No initialization needed on POSIX systems */
static inline int platform_socket_init(void) {
    return 0;
}

/* No cleanup needed on POSIX systems */
static inline void platform_socket_cleanup(void) {
}

/* Set socket to non-blocking mode (POSIX version) */
static inline int platform_set_nonblocking(socket_t sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

#endif /* PLATFORM_WINDOWS */

/* ===================================================================
 * Common Helper Functions
 * =================================================================== */

/* Check if socket descriptor is valid */
static inline int socket_is_valid(socket_t sockfd) {
    return sockfd != INVALID_SOCKET_VALUE;
}

/* Safe socket close that checks for validity first */
static inline void socket_safe_close(socket_t sockfd) {
    if (socket_is_valid(sockfd)) {
        socket_close(sockfd);
    }
}

/* Get last socket error as string (cross-platform) */
static inline const char* socket_strerror(int err) {
#ifdef PLATFORM_WINDOWS
    static char buf[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   buf, sizeof(buf), NULL);
    return buf;
#else
    return strerror(err);
#endif
}

/* Print last socket error to stderr */
static inline void socket_perror(const char *msg) {
    int err = socket_errno;
#ifdef PLATFORM_WINDOWS
    fprintf(stderr, "%s: %s (error code: %d)\n", msg, socket_strerror(err), err);
#else
    fprintf(stderr, "%s: %s\n", msg, strerror(err));
#endif
}

#endif /* PLATFORM_COMPAT_H */
