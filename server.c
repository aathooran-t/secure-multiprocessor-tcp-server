#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <ctype.h>
#include <openssl/sha.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 55000
#define SERVER_SID "SA01"

#define PROJECT_NAME "SecureAuthServer"
#define BASE_DIR "/srv/secure_auth_server"
#define LOG_FILE "/srv/secure_auth_server/server.log"
#define LOCKOUT_DIR "/srv/secure_auth_server/lockouts"
#define RATELIMIT_DIR "/srv/secure_auth_server/ratelimits"

#define MAX_PAYLOAD 4096
#define INPUT_BUF 8192
#define BACKLOG 10

#define TOKEN_TIMEOUT 300

#define MAX_FAILED_LOGINS 3
#define LOCKOUT_SECONDS 60

#define MAX_REQUESTS 5
#define WINDOW_SECONDS 10

typedef struct {
    int logged_in;
    char username[64];
    char token[65];
    time_t last_activity;
} Session;

void reap_children(int sig) {
    int saved_errno = errno;
    (void)sig;

    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }

    errno = saved_errno;
}

int send_all(int sockfd, const char *data, size_t len) {
    size_t total = 0;

    while (total < len) {
        ssize_t n = send(sockfd, data + total, len - total, 0);
        if (n <= 0) return -1;
        total += (size_t)n;
    }

    return 0;
}

int send_ok(int connfd, int code, const char *message) {
    char reply[1024];
    snprintf(reply, sizeof(reply), "OK %d SID:%s %s\n", code, SERVER_SID, message);
    return send_all(connfd, reply, strlen(reply));
}

int send_err(int connfd, int code, const char *message) {
    char reply[1024];
    snprintf(reply, sizeof(reply), "ERR %d SID:%s %s\n", code, SERVER_SID, message);
    return send_all(connfd, reply, strlen(reply));
}

void current_timestamp(char *buf, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

void ensure_base_dirs(void) {
    mkdir("/srv", 0777);
    mkdir(BASE_DIR, 0777);
    mkdir(LOCKOUT_DIR, 0777);
    mkdir(RATELIMIT_DIR, 0777);
}

void write_log_entry(const char *client_ip,
                     int client_port,
                     pid_t pid,
                     const char *username,
                     const char *command,
                     const char *result) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) return;

    char ts[64];
    current_timestamp(ts, sizeof(ts));

    fprintf(fp,
            "[%s] %s:%d PID:%d USER:%s CMD:%s RESULT:%s\n",
            ts,
            client_ip ? client_ip : "-",
            client_port,
            (int)pid,
            (username && username[0]) ? username : "-",
            (command && command[0]) ? command : "-",
            (result && result[0]) ? result : "-");

    fclose(fp);
}

void generate_salt(char *salt_out, size_t len) {
    static const char chars[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";

    size_t chars_len = strlen(chars);

    for (size_t i = 0; i < len - 1; i++) {
        salt_out[i] = chars[rand() % chars_len];
    }

    salt_out[len - 1] = '\0';
}

void hash_password(const char *salt, const char *password, char *hash_out) {
    char combined[256];
    unsigned char digest[SHA256_DIGEST_LENGTH];

    snprintf(combined, sizeof(combined), "%s%s", salt, password);
    SHA256((unsigned char *)combined, strlen(combined), digest);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_out + (i * 2), "%02x", digest[i]);
    }

    hash_out[SHA256_DIGEST_LENGTH * 2] = '\0';
}

void generate_token(char *token_out, size_t len) {
    static const char chars[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";

    size_t chars_len = strlen(chars);

    for (size_t i = 0; i < len - 1; i++) {
        token_out[i] = chars[rand() % chars_len];
    }

    token_out[len - 1] = '\0';
}

int valid_username(const char *username) {
    size_t n = strlen(username);

    if (n < 3 || n > 32) return 0;

    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)username[i];
        if (!(isalnum(c) || c == '_')) {
            return 0;
        }
    }

    return 1;
}

void sanitize_name(const char *input, char *output, size_t size) {
    size_t j = 0;
    for (size_t i = 0; input[i] != '\0' && j < size - 1; i++) {
        unsigned char c = (unsigned char)input[i];
        if (isalnum(c) || c == '_' || c == '-') {
            output[j++] = (char)c;
        } else {
            output[j++] = '_';
        }
    }
    output[j] = '\0';
}

void build_user_dir(const char *username, char *out, size_t size) {
    snprintf(out, size, "%s/%s", BASE_DIR, username);
}

void build_auth_file(const char *username, char *out, size_t size) {
    snprintf(out, size, "%s/%s/auth.txt", BASE_DIR, username);
}

void build_lockout_file(const char *username, char *out, size_t size) {
    char safe_user[128];
    sanitize_name(username, safe_user, sizeof(safe_user));
    snprintf(out, size, "%s/%s.lock", LOCKOUT_DIR, safe_user);
}

void build_ratelimit_file(const char *client_ip, char *out, size_t size) {
    char safe_ip[128];
    sanitize_name(client_ip, safe_ip, sizeof(safe_ip));
    snprintf(out, size, "%s/%s.rate", RATELIMIT_DIR, safe_ip);
}

int user_exists(const char *username) {
    char auth_path[256];
    build_auth_file(username, auth_path, sizeof(auth_path));
    return access(auth_path, F_OK) == 0;
}

int register_user(const char *username, const char *password) {
    if (!valid_username(username)) return -2;
    if (user_exists(username)) return -1;

    char salt[17];
    char hash[128];
    char auth_path[256];
    char user_dir[256];

    generate_salt(salt, sizeof(salt));
    hash_password(salt, password, hash);

    ensure_base_dirs();
    build_user_dir(username, user_dir, sizeof(user_dir));

    if (mkdir(user_dir, 0777) < 0 && errno != EEXIST) {
        perror("mkdir user_dir");
        return -3;
    }

    build_auth_file(username, auth_path, sizeof(auth_path));

    FILE *fp = fopen(auth_path, "w");
    if (!fp) {
        perror("fopen auth_path");
        return -3;
    }

    fprintf(fp, "%s:%s:%s\n", username, salt, hash);
    fclose(fp);

    return 0;
}

int verify_login(const char *username, const char *password) {
    char auth_path[256];
    build_auth_file(username, auth_path, sizeof(auth_path));

    FILE *fp = fopen(auth_path, "r");
    if (!fp) return 0;

    char line[512];
    char stored_user[64], salt[64], stored_hash[128];
    char computed_hash[128];

    if (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%63[^:]:%63[^:]:%127s", stored_user, salt, stored_hash) == 3) {
            fclose(fp);

            if (strcmp(stored_user, username) != 0) {
                return 0;
            }

            hash_password(salt, password, computed_hash);
            return strcmp(stored_hash, computed_hash) == 0;
        }
    }

    fclose(fp);
    return 0;
}

int is_account_locked(const char *username) {
    char path[256];
    build_lockout_file(username, path, sizeof(path));

    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    int failed_attempts = 0;
    long lock_until = 0;

    if (fscanf(fp, "%d %ld", &failed_attempts, &lock_until) != 2) {
        fclose(fp);
        return 0;
    }

    fclose(fp);

    time_t now = time(NULL);
    return lock_until > now;
}

void record_failed_login(const char *username) {
    char path[256];
    build_lockout_file(username, path, sizeof(path));

    int failed_attempts = 0;
    long lock_until = 0;

    FILE *fp = fopen(path, "r");
    if (fp) {
        fscanf(fp, "%d %ld", &failed_attempts, &lock_until);
        fclose(fp);
    }

    time_t now = time(NULL);

    if (lock_until > now) {
        return;
    }

    failed_attempts++;

    if (failed_attempts >= MAX_FAILED_LOGINS) {
        lock_until = now + LOCKOUT_SECONDS;
        failed_attempts = 0;
    } else {
        lock_until = 0;
    }

    fp = fopen(path, "w");
    if (!fp) return;

    fprintf(fp, "%d %ld\n", failed_attempts, lock_until);
    fclose(fp);
}

void clear_failed_login(const char *username) {
    char path[256];
    build_lockout_file(username, path, sizeof(path));

    FILE *fp = fopen(path, "w");
    if (!fp) return;

    fprintf(fp, "0 0\n");
    fclose(fp);
}

int token_expired(Session *session) {
    time_t now = time(NULL);
    return (now - session->last_activity) > TOKEN_TIMEOUT;
}

int require_token(Session *session, const char *token) {
    if (!session->logged_in) return 0;
    if (strcmp(session->token, token) != 0) return 0;

    if (token_expired(session)) {
        session->logged_in = 0;
        session->username[0] = '\0';
        session->token[0] = '\0';
        return 0;
    }

    session->last_activity = time(NULL);
    return 1;
}

int check_rate_limit(const char *client_ip) {
    char path[256];
    build_ratelimit_file(client_ip, path, sizeof(path));

    long window_start = 0;
    int request_count = 0;
    time_t now = time(NULL);

    FILE *fp = fopen(path, "r");
    if (fp) {
        fscanf(fp, "%ld %d", &window_start, &request_count);
        fclose(fp);
    }

    if (window_start == 0 || (now - window_start) > WINDOW_SECONDS) {
        window_start = now;
        request_count = 1;
    } else {
        if (request_count >= MAX_REQUESTS) {
            return 0;
        }
        request_count++;
    }

    fp = fopen(path, "w");
    if (!fp) return 1;

    fprintf(fp, "%ld %d\n", window_start, request_count);
    fclose(fp);

    return 1;
}

void process_command(int connfd,
                     const char *payload,
                     Session *session,
                     const char *client_ip,
                     int client_port) {
    char cmd[32], arg1[128], arg2[128];
    memset(cmd, 0, sizeof(cmd));
    memset(arg1, 0, sizeof(arg1));
    memset(arg2, 0, sizeof(arg2));

    if (!check_rate_limit(client_ip)) {
        write_log_entry(client_ip, client_port, getpid(), session->username, "RATE_LIMIT", "EXCEEDED");
        send_err(connfd, 429, "Rate limit exceeded");
        return;
    }

    int parts = sscanf(payload, "%31s %127s %127s", cmd, arg1, arg2);

    if (parts <= 0) {
        write_log_entry(client_ip, client_port, getpid(), session->username, "EMPTY", "EMPTY_COMMAND");
        send_err(connfd, 400, "Empty command");
        return;
    }

    if (strcmp(cmd, "REGISTER") == 0) {
        if (parts != 3) {
            write_log_entry(client_ip, client_port, getpid(), "-", "REGISTER", "BAD_USAGE");
            send_err(connfd, 400, "Usage: REGISTER <user> <pass>");
            return;
        }

        int r = register_user(arg1, arg2);

        if (r == 0) {
            write_log_entry(client_ip, client_port, getpid(), arg1, "REGISTER", "USER_REGISTERED");
            send_ok(connfd, 201, "User registered");
        } else if (r == -1) {
            write_log_entry(client_ip, client_port, getpid(), arg1, "REGISTER", "USER_EXISTS");
            send_err(connfd, 409, "User already exists");
        } else if (r == -2) {
            write_log_entry(client_ip, client_port, getpid(), "-", "REGISTER", "INVALID_USERNAME");
            send_err(connfd, 400, "Invalid username");
        } else {
            write_log_entry(client_ip, client_port, getpid(), arg1, "REGISTER", "REGISTER_ERROR");
            send_err(connfd, 500, "Could not register user");
        }
        return;
    }

    if (strcmp(cmd, "LOGIN") == 0) {
        if (parts != 3) {
            write_log_entry(client_ip, client_port, getpid(), "-", "LOGIN", "BAD_USAGE");
            send_err(connfd, 400, "Usage: LOGIN <user> <pass>");
            return;
        }

        if (is_account_locked(arg1)) {
            write_log_entry(client_ip, client_port, getpid(), arg1, "LOGIN", "ACCOUNT_LOCKED");
            send_err(connfd, 423, "Account locked");
            return;
        }

        if (!verify_login(arg1, arg2)) {
            record_failed_login(arg1);
            write_log_entry(client_ip, client_port, getpid(), arg1, "LOGIN", "INVALID_CREDENTIALS");
            send_err(connfd, 401, "Invalid credentials");
            return;
        }

        clear_failed_login(arg1);

        session->logged_in = 1;
        strncpy(session->username, arg1, sizeof(session->username) - 1);
        session->username[sizeof(session->username) - 1] = '\0';
        generate_token(session->token, sizeof(session->token));
        session->last_activity = time(NULL);

        char msg[256];
        snprintf(msg, sizeof(msg), "Login successful TOKEN:%s", session->token);

        write_log_entry(client_ip, client_port, getpid(), arg1, "LOGIN", "LOGIN_SUCCESS");
        send_ok(connfd, 200, msg);
        return;
    }

    if (strcmp(cmd, "LOGOUT") == 0) {
        if (parts != 2) {
            write_log_entry(client_ip, client_port, getpid(), session->username, "LOGOUT", "BAD_USAGE");
            send_err(connfd, 400, "Usage: LOGOUT <token>");
            return;
        }

        if (!require_token(session, arg1)) {
            write_log_entry(client_ip, client_port, getpid(), "-", "LOGOUT", "UNAUTHORIZED");
            send_err(connfd, 403, "Unauthorized or expired token");
            return;
        }

        write_log_entry(client_ip, client_port, getpid(), session->username, "LOGOUT", "LOGOUT_SUCCESS");

        session->logged_in = 0;
        session->username[0] = '\0';
        session->token[0] = '\0';

        send_ok(connfd, 200, "Logout successful");
        return;
    }

    if (strcmp(cmd, "WHOAMI") == 0) {
        if (parts != 2) {
            write_log_entry(client_ip, client_port, getpid(), session->username, "WHOAMI", "BAD_USAGE");
            send_err(connfd, 400, "Usage: WHOAMI <token>");
            return;
        }

        if (!require_token(session, arg1)) {
            write_log_entry(client_ip, client_port, getpid(), "-", "WHOAMI", "UNAUTHORIZED");
            send_err(connfd, 403, "Unauthorized or expired token");
            return;
        }

        char msg[256];
        snprintf(msg, sizeof(msg), "You are %s", session->username);

        write_log_entry(client_ip, client_port, getpid(), session->username, "WHOAMI", "SUCCESS");
        send_ok(connfd, 200, msg);
        return;
    }

    write_log_entry(client_ip, client_port, getpid(), session->username, cmd, "UNKNOWN_COMMAND");
    send_err(connfd, 400, "Unknown command");
}

void handle_client(int connfd, const char *client_ip, int client_port) {
    char inbuf[INPUT_BUF];
    int inbuf_len = 0;
    Session session;
    memset(&session, 0, sizeof(session));

    while (1) {
        if (inbuf_len >= INPUT_BUF) {
            write_log_entry(client_ip, client_port, getpid(), session.username, "FRAME", "BUFFER_OVERFLOW");
            send_err(connfd, 403, "Buffer overflow");
            break;
        }

        ssize_t n = recv(connfd, inbuf + inbuf_len, INPUT_BUF - inbuf_len, 0);

        if (n == 0) {
            write_log_entry(client_ip, client_port, getpid(), session.username, "CONNECTION", "CLIENT_DISCONNECTED");
            break;
        }

        if (n < 0) {
            write_log_entry(client_ip, client_port, getpid(), session.username, "CONNECTION", "RECV_ERROR");
            perror("recv");
            break;
        }

        inbuf_len += (int)n;

        while (1) {
            char *newline = memchr(inbuf, '\n', inbuf_len);
            if (newline == NULL) {
                break;
            }

            int header_len = (int)(newline - inbuf + 1);

            if (strncmp(inbuf, "LEN:", 4) != 0) {
                write_log_entry(client_ip, client_port, getpid(), session.username, "FRAME", "INVALID_HEADER");
                send_err(connfd, 400, "Invalid header");
                return;
            }

            int num_len = header_len - 5;
            char len_str[32];

            if (num_len <= 0 || num_len >= (int)sizeof(len_str)) {
                write_log_entry(client_ip, client_port, getpid(), session.username, "FRAME", "INVALID_LENGTH");
                send_err(connfd, 401, "Invalid length");
                return;
            }

            memcpy(len_str, inbuf + 4, num_len);
            len_str[num_len] = '\0';

            char *endptr = NULL;
            long payload_len = strtol(len_str, &endptr, 10);

            if (*endptr != '\0' || payload_len < 0) {
                write_log_entry(client_ip, client_port, getpid(), session.username, "FRAME", "INVALID_LENGTH");
                send_err(connfd, 401, "Invalid length");
                return;
            }

            if (payload_len > MAX_PAYLOAD) {
                write_log_entry(client_ip, client_port, getpid(), session.username, "FRAME", "PAYLOAD_TOO_LARGE");
                send_err(connfd, 402, "Payload too large");
                return;
            }

            if (inbuf_len < header_len + payload_len) {
                break;
            }

            char payload[MAX_PAYLOAD + 1];
            memcpy(payload, inbuf + header_len, (size_t)payload_len);
            payload[payload_len] = '\0';

            printf("Received payload: %s\n", payload);
            process_command(connfd, payload, &session, client_ip, client_port);

            int consumed = header_len + (int)payload_len;
            memmove(inbuf, inbuf + consumed, (size_t)(inbuf_len - consumed));
            inbuf_len -= consumed;
        }
    }

    close(connfd);
}

int main(void) {
    int listenfd, connfd, opt = 1;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    srand((unsigned int)(time(NULL) ^ getpid()));
    ensure_base_dirs();

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = reap_children;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        perror("sigaction");
        return 1;
    }

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        perror("socket");
        return 1;
    }

    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(listenfd);
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(listenfd);
        return 1;
    }

    if (bind(listenfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(listenfd);
        return 1;
    }

    if (listen(listenfd, BACKLOG) < 0) {
        perror("listen");
        close(listenfd);
        return 1;
    }

    printf("Server running on %s:%d with SID:%s\n", SERVER_IP, SERVER_PORT, SERVER_SID);

    while (1) {
        connfd = accept(listenfd, (struct sockaddr *)&client_addr, &client_len);

        if (connfd < 0) {
            perror("accept");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        int client_port = ntohs(client_addr.sin_port);

        pid_t pid = fork();

        if (pid < 0) {
            perror("fork");
            close(connfd);
            continue;
        }

        if (pid == 0) {
            close(listenfd);
            handle_client(connfd, client_ip, client_port);
            close(connfd);
            exit(0);
        } else {
            close(connfd);
        }
    }

    close(listenfd);
    return 0;
}
