#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <fcntl.h>
#include <ctype.h>

#define PORT 50979
#define SID "1029"
#define MAX_PAYLOAD 4096
#define LOG_FILE "server_IT24102979.log"
#define BACKLOG 10
#define SALT_LEN 16
#define TOKEN_LEN 32
#define MAX_USERS 100
#define USER_FILE "/srv/ie2102/IT24102979/kali/users.txt"
#define SESSION_TIMEOUT 300 /* 5min */
#define RATE_MAX_MSGS 20 /*max messages per minute per client*/
#define RATE_WINDOW 60 /*window size in seconds*/


/* One registered user stored in memory */
typedef struct {
    char username[64];
    char salt[SALT_LEN * 2 + 1];      /* hex-encoded salt */
    char hashed_pass[65];              /* hex SHA-256 = 64 chars + null */
} User;

/* One active session (one per logged-in child process) */
typedef struct {
    char token[TOKEN_LEN * 2 + 1];    /* hex-encoded token */
    char username[64];
    time_t last_active;                /* updated on every command */
    int   logged_in;
} Session;

User    users[MAX_USERS];
int     user_count = 0;
Session current_session = {0};        /* each child has its own copy */



/* Rate limiting — tracks message rate per client (per child) */
typedef struct {
    time_t window_start;   /* when the current 1-minute window began */
    int    msg_count;      /* messages received in this window        */
} RateLimit;




/* Update log file -- A5*/

/* Build a timestamp string like: Year-month-date hour:minute:second */
void get_timestamp(char *buf, size_t len) {
    time_t now     = time(NULL);
    struct tm *tm  = localtime(&now);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", tm);
}

/* Write one line to the log file */
void write_log(const char *client_ip,
               int         client_port,
               pid_t       pid,
               const char *username,
               const char *command,
               const char *result) {

    /* Open in append mode — never overwrites old entries */
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) {
        perror("write_log: cannot open log file");
        return;
    }

    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));

    /* Sanitise inputs — never write NULL into the log */
    const char *safe_ip   = client_ip ? client_ip : "unknown";
    const char *safe_user = username  ? username  : "none";
    const char *safe_cmd  = command   ? command   : "unknown";
    const char *safe_res  = result    ? result    : "unknown";

    /* Truncate command if too long — stops log injection */
    char cmd_safe[128];
    strncpy(cmd_safe, safe_cmd, sizeof(cmd_safe) - 1);
    cmd_safe[sizeof(cmd_safe) - 1] = '\0';

    /* Remove newlines from command — prevents log line breaking */
    for (int i = 0; cmd_safe[i]; i++) {
        if (cmd_safe[i] == '\n' || cmd_safe[i] == '\r')
            cmd_safe[i] = ' ';
    }

    fprintf(log,
        "[%s] IP:%s PORT:%d PID:%d USER:%s CMD:%s RESULT:%s\n",
        timestamp,
        safe_ip,
        client_port,
        (int)pid,
        safe_user,
        cmd_safe,
        safe_res);

    /* Force write to disk immediately — critical for crash safety */
    fflush(log);
    fclose(log);
}






void send_response(int sock, const char *type,
                   const char *code, const char *message) {
    char response[512];
    snprintf(response, sizeof(response),
             "%s %s SID:%s %s\n", type, code, SID, message);
    send(sock, response, strlen(response), 0);
}


void bytes_to_hex(const unsigned char *bytes, int len, char *out) {
    for (int i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02x", bytes[i]);
    }
    out[len * 2] = '\0';
}

int generate_salt(char *salt_hex) {
    unsigned char salt_bytes[SALT_LEN];
    if (RAND_bytes(salt_bytes, SALT_LEN) != 1) {
        return -1;   /* OpenSSL random failed */
    }
    bytes_to_hex(salt_bytes, SALT_LEN, salt_hex);
    return 0;
}

int generate_token(char *token_hex) {
    unsigned char token_bytes[TOKEN_LEN];
    if (RAND_bytes(token_bytes, TOKEN_LEN) != 1) {
        return -1;
    }
    bytes_to_hex(token_bytes, TOKEN_LEN, token_hex);
    return 0;
}

void hash_password(const char *password, const char *salt_hex, char *out_hex) {
    /* Combine salt + password into one string */
    char combined[256];
    snprintf(combined, sizeof(combined), "%s%s", salt_hex, password);

    /* Run SHA-256 on the combined string */
    unsigned char hash[SHA256_DIGEST_LENGTH];   /* 32 bytes */
    SHA256((unsigned char *)combined,
           strlen(combined),
           hash);

    /* Convert result to hex */
    bytes_to_hex(hash, SHA256_DIGEST_LENGTH, out_hex);
}



int is_valid_username(const char *username) {
    if (strlen(username) < 3 || strlen(username) > 32) return 0;
    for (int i = 0; username[i]; i++) {
        if (!isalnum(username[i]) && username[i] != '_') return 0;
    }
    return 1;
}

void save_users() {
    FILE *f = fopen(USER_FILE, "w");
    if (!f) { perror("Cannot open user file"); return; }
    for (int i = 0; i < user_count; i++) {
        fprintf(f, "%s:%s:%s\n",
                users[i].username,
                users[i].salt,
                users[i].hashed_pass);
    }
    fclose(f);
}

void load_users() {
    FILE *f = fopen(USER_FILE, "r");
    if (!f) return;   /* file doesn't exist yet — that's fine */

    user_count = 0;
    while (user_count < MAX_USERS) {
        int r = fscanf(f, "%63[^:]:%32[^:]:%64[^\n]\n",
                       users[user_count].username,
                       users[user_count].salt,
                       users[user_count].hashed_pass);
        if (r != 3) break;
        user_count++;
    }
    fclose(f);
}

int is_session_valid() {
    if (!current_session.logged_in) return 0;
    time_t now = time(NULL);
    if (now - current_session.last_active > SESSION_TIMEOUT) {
        current_session.logged_in = 0;   /* expire it */
        return 0;
    }
    return 1;
}

void refresh_session() {
    current_session.last_active = time(NULL);
}








int recv_exact(int sock, char *buf, int n) {
    int total = 0;
    while (total < n) {
        int received = recv(sock, buf + total, n - total, 0);
        if (received <= 0) return -1;
        total += received;
    }
    return total;
}
int read_framed_message(int sock, char *payload_buf,
                        char *client_ip, int client_port) {
    char header[32];
    memset(header, 0, sizeof(header));
    int i = 0;

    // Read byte by byte until we hit a newline
    while (i < (int)sizeof(header) - 1) {
        char c;
        int r = recv(sock, &c, 1, 0);
        if (r <= 0) return -1;
        if (c == '\n') break;
        header[i++] = c;
    }

    // Header must start with "LEN:"
    if (strncmp(header, "LEN:", 4) != 0) {
        write_log(client_ip, client_port, getpid(),
                  "unknown", header, "ERR_INVALID_HEADER");
        return -2;
    }

    // Parse the number after "LEN:"
    int payload_len = atoi(header + 4);

    // Reject oversized payloads
    if (payload_len <= 0 || payload_len > MAX_PAYLOAD) {
        write_log(client_ip, client_port, getpid(),
                  "unknown", header, "ERR_OVERSIZED");
        return -3;
    }

    // Now read exactly payload_len bytes
    int r = recv_exact(sock, payload_buf, payload_len);
    if (r < 0) return -1;
    payload_buf[payload_len] = '\0';
    return payload_len;
}

/* Brute-force lockout tracking */
typedef struct {
    char username[64];
    int  fail_count;
    time_t locked_until;
} LoginAttempt;

LoginAttempt attempts[MAX_USERS] = {0};
int attempt_count = 0;

LoginAttempt *get_attempt(const char *username) {
    for (int i = 0; i < attempt_count; i++) {
        if (strcmp(attempts[i].username, username) == 0)
            return &attempts[i];
    }
    if (attempt_count < MAX_USERS) {
        strncpy(attempts[attempt_count].username, username, 63);
        attempts[attempt_count].fail_count    = 0;
        attempts[attempt_count].locked_until  = 0;
        return &attempts[attempt_count++];
    }
    return NULL;
}


/*
 * Returns 1 if the client is within rate limit.
 * Returns 0 if they have exceeded it.
 * Call this once per received message.
 */
int check_rate_limit(RateLimit *rl) {
    time_t now = time(NULL);

    /* If the time window has expired, reset the counter */
    if (now - rl->window_start >= RATE_WINDOW) {
        rl->window_start = now;
        rl->msg_count    = 0;
    }

    rl->msg_count++;

    if (rl->msg_count > RATE_MAX_MSGS) {
        return 0;   /* rate exceeded */
    }
    return 1;   /* still within limit */
}







void cmd_register(int sock, char *args,
                  char *client_ip, int client_port) {
    char username[64], password[64];

    /* Parse "REGISTER username password" */
    if (sscanf(args, "%63s %63s", username, password) != 2) {
        send_response(sock, "ERR", "400",
                      "Usage: REGISTER <user> <pass>");
        write_log(client_ip, client_port, getpid(),
                  "none", "REGISTER", "ERR_BAD_ARGS");
        return;
    }

    /* Validate username format */
    if (!is_valid_username(username)) {
        send_response(sock, "ERR", "400",
                      "Invalid username. Use 3-32 alphanumeric chars.");
        write_log(client_ip, client_port, getpid(),
                  username, "REGISTER", "ERR_BAD_USERNAME");
        return;
    }

    /* Load latest users from disk */
    load_users();

    /* Check username is not already taken */
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            send_response(sock, "ERR", "409",
                          "Username already exists.");
            write_log(client_ip, client_port, getpid(),
                      username, "REGISTER", "ERR_DUPLICATE");
            return;
        }
    }

    /* Generate salt and hash the password */
    char salt_hex[SALT_LEN * 2 + 1];
    char hash_hex[65];

    if (generate_salt(salt_hex) < 0) {
        send_response(sock, "ERR", "500", "Server error.");
        return;
    }

    hash_password(password, salt_hex, hash_hex);

    /* Store the new user */
    strncpy(users[user_count].username, username, 63);
    strncpy(users[user_count].salt,     salt_hex, SALT_LEN * 2);
    strncpy(users[user_count].hashed_pass, hash_hex, 64);
    user_count++;

    save_users();

    send_response(sock, "OK", "201", "User registered successfully.");
    write_log(client_ip, client_port, getpid(),
              username, "REGISTER", "OK");
}




void cmd_login(int sock, char *args,
               char *client_ip, int client_port) {
    char username[64], password[64];

    if (sscanf(args, "%63s %63s", username, password) != 2) {
        send_response(sock, "ERR", "400",
                      "Usage: LOGIN <user> <pass>");
        return;
    }

    /* Validate username before anything else */
    if (!is_valid_username(username)) {
        send_response(sock, "ERR", "400", "Invalid username.");
        return;
    }

    LoginAttempt *att = get_attempt(username);

    /* Check lockout — only if att is valid */
    if (att != NULL && att->locked_until > time(NULL)) {
        int secs = (int)(att->locked_until - time(NULL));
        char msg[64];
        snprintf(msg, sizeof(msg),
                 "Account locked. Try again in %d seconds.", secs);
        send_response(sock, "ERR", "423", msg);
        write_log(client_ip, client_port, getpid(),
                  username, "LOGIN", "ERR_LOCKED");
        return;
    }

    load_users();

    /* Find the user */
    User *found = NULL;
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            found = &users[i];
            break;
        }
    }

    if (!found) {
        send_response(sock, "ERR", "401", "Invalid credentials.");
        write_log(client_ip, client_port, getpid(),
                  username, "LOGIN", "ERR_NO_USER");
        return;
    }

    /* Hash the provided password using stored salt */
    char hash_hex[65];
    hash_password(password, found->salt, hash_hex);

    if (strcmp(hash_hex, found->hashed_pass) != 0) {
        /* Wrong password */
        if (att != NULL) {
            att->fail_count++;
            if (att->fail_count >= 5) {
                att->locked_until = time(NULL) + 300;
                att->fail_count   = 0;
                send_response(sock, "ERR", "423",
                    "Too many failed attempts. Locked for 5 minutes.");
                write_log(client_ip, client_port, getpid(),
                          username, "LOGIN", "ERR_LOCKED_NOW");
                return;
            }
        }
        send_response(sock, "ERR", "401", "Invalid credentials.");
        write_log(client_ip, client_port, getpid(),
                  username, "LOGIN", "ERR_WRONG_PASS");
        return;
    }

    /* Correct password — reset counters */
    if (att != NULL) {
        att->fail_count   = 0;
        att->locked_until = 0;
    }

    /* Generate session token */
    char token[TOKEN_LEN * 2 + 1];
    if (generate_token(token) < 0) {
        send_response(sock, "ERR", "500", "Server error.");
        return;
    }

    strncpy(current_session.token,    token,    TOKEN_LEN * 2);
    strncpy(current_session.username, username, 63);
    current_session.last_active = time(NULL);
    current_session.logged_in   = 1;

    char msg[256];
    snprintf(msg, sizeof(msg),
             "Login successful. TOKEN:%s", token);
    send_response(sock, "OK", "200", msg);
    write_log(client_ip, client_port, getpid(),
              username, "LOGIN", "OK");
}







int check_token(int sock, char *payload,
                char *client_ip, char *username_out) {
    /* Find TOKEN: in the payload */
    char *tok_ptr = strstr(payload, "TOKEN:");
    if (!tok_ptr) {
        send_response(sock, "ERR", "401",
                      "Not authenticated. Please LOGIN first.");

	write_log(client_ip, 0, getpid(), "none", "TOKEN_CHECK", "ERR");
   	
	return 0;
    }

    char provided[TOKEN_LEN * 2 + 1];
    strncpy(provided, tok_ptr + 6, TOKEN_LEN * 2);
    provided[TOKEN_LEN * 2] = '\0';

    if (!is_session_valid()) {
        send_response(sock, "ERR", "401",
                      "Session expired. Please LOGIN again.");
        return 0;
    }

    if (strcmp(provided, current_session.token) != 0) {
        send_response(sock, "ERR", "403", "Invalid token.");
        return 0;
    }

    refresh_session();   /* reset 5-minute timer */
    if (username_out)
        strncpy(username_out, current_session.username, 63);
    return 1;
}

void cmd_logout(int sock, char *args,
                char *client_ip, int client_port) {
    char username[64] = "none";
    if (!check_token(sock, args, client_ip, username)) return;

    current_session.logged_in = 0;
    memset(current_session.token, 0, sizeof(current_session.token));

    send_response(sock, "OK", "200", "Logged out successfully.");
    write_log(client_ip, client_port, getpid(),
              username, "LOGOUT", "OK");
}


void sigchld_handler(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}


/*Update handle_client================================================================*/
void handle_client(int client_sock,
                   char *client_ip, int client_port) {
    char      payload[MAX_PAYLOAD + 1];
    RateLimit rl = { time(NULL), 0 };   /* initialise rate limiter */

    load_users();

    write_log(client_ip, client_port, getpid(),
              "none", "CONNECT", "OK");
    send_response(client_sock, "OK", "100",
                  "Welcome. Please REGISTER or LOGIN.");

    while (1) {
        memset(payload, 0, sizeof(payload));

        int len = read_framed_message(client_sock, payload,
                                      client_ip, client_port);

        /* Client disconnected */
        if (len == -1) {
            write_log(client_ip, client_port, getpid(),
                      current_session.logged_in
                          ? current_session.username : "none",
                      "DISCONNECT", "OK");
            break;
        }

        /* Bad header format */
        if (len == -2) {
            send_response(client_sock, "ERR", "400",
                          "Invalid header. Use LEN:<n>");
	    
	    write_log(client_ip, client_port, getpid(),
			    "none", "BAD_HEADER", "ERR_INVALID");
	    
	    continue;
        }

        /* Payload too large — A4 overflow rejection */
        if (len == -3) {
            send_response(client_sock, "ERR", "413",
                          "Payload too large. Max 4096 bytes.");
            write_log(client_ip, client_port, getpid(),
                      "none", "OVERSIZED_PAYLOAD", "ERR_413");
            break;
        }

        /* ── A4: Rate limiting check ── */
        if (!check_rate_limit(&rl)) {
            send_response(client_sock, "ERR", "429",
                          "Too many requests. Slow down.");
            write_log(client_ip, client_port, getpid(),
                      current_session.logged_in
                          ? current_session.username : "none",
                      "RATE_LIMIT_EXCEEDED", "ERR");
            break;   /* disconnect abusive client */
        }

        /* Route to the right command handler */
        if (strncmp(payload, "REGISTER ", 9) == 0)
            cmd_register(client_sock, payload + 9,
                         client_ip, client_port);

        else if (strncmp(payload, "LOGIN ", 6) == 0)
            cmd_login(client_sock, payload + 6,
                      client_ip, client_port);

        else if (strncmp(payload, "LOGOUT", 6) == 0)
            cmd_logout(client_sock, payload,
                       client_ip, client_port);

        else {
            char username[64] = "none";
            if (check_token(client_sock, payload,
                            client_ip, username)) {
                write_log(client_ip, client_port, getpid(),
                          username, payload, "OK");
                send_response(client_sock, "OK", "200",
                              "Command received.");
            }
        }
    }

    close(client_sock);
}




/*void handle_client(int client_sock, char *client_ip, int client_port) {
    char payload[MAX_PAYLOAD + 1];

    write_log(client_ip, client_port, getpid(),
              "none", "CONNECT", "OK");

    send_response(client_sock, "OK", "100",
                  "Welcome. Please REGISTER or LOGIN.");

    while (1) {
        memset(payload, 0, sizeof(payload));
        int len = read_framed_message(client_sock, payload,
                                      client_ip, client_port);

        if (len == -1) {
            // Client disconnected
            write_log(client_ip, client_port, getpid(),
                      "none", "DISCONNECT", "OK");
            break;
        }
        if (len == -2) {
            send_response(client_sock, "ERR", "400",
                          "Invalid header. Use LEN:<n>");
            continue;
        }
        if (len == -3) {
            send_response(client_sock, "ERR", "413",
                          "Payload too large. Max 4096 bytes.");
            break;
        }

        // Log the received command
        write_log(client_ip, client_port, getpid(),
                  "none", payload, "RECEIVED");

        // Basic command handling
        if (strncmp(payload, "REGISTER", 8) == 0) {
            send_response(client_sock, "OK", "200",
                          "REGISTER received (auth coming soon)");
        } else if (strncmp(payload, "LOGIN", 5) == 0) {
            send_response(client_sock, "OK", "200",
                          "LOGIN received (auth coming soon)");
        } else if (strncmp(payload, "LOGOUT", 6) == 0) {
            send_response(client_sock, "OK", "200", "Goodbye.");
            break;
        } else {
            send_response(client_sock, "ERR", "404",
                          "Unknown command.");
        }
    }

    close(client_sock);
}*/


int main() {
    int server_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Set up SIGCHLD handler first
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);

    // Create TCP socket
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket failed");
        exit(1);
    }

    // Allow reuse of port immediately after restart
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Set up server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind socket to port
    if (bind(server_sock, (struct sockaddr*)&server_addr,
             sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(1);
    }

    // Start listening
    if (listen(server_sock, BACKLOG) < 0) {
        perror("listen failed");
        exit(1);
    }

    printf("Server started. SID:%s listening on port %d\n", SID, PORT);

    /* Log server startup with a special entry */
    FILE *startup = fopen(LOG_FILE, "a");
    if (startup) {
	char timestamp[32];
	get_timestamp(timestamp, sizeof(timestamp));
	fprintf(startup,
		"[%s] IP:SERVER PORT:%d PID:%d USER:system "
	        "CMD:SERVER_START RESULT:OK\n",
	        timestamp, PORT, (int)getpid());
	fflush(startup);
	fclose(startup);
    }




    /*write_log("SERVER", 0, getpid(), "none", "START", "OK");*/

    // Main accept loop
    while (1) {
        int client_sock = accept(server_sock,
                                 (struct sockaddr*)&client_addr,
                                 &client_len);
        if (client_sock < 0) {
            if (errno == EINTR) continue;
            perror("accept failed");
            continue;
        }

        char *client_ip = inet_ntoa(client_addr.sin_addr);
        int client_port = ntohs(client_addr.sin_port);

        printf("New connection from %s:%d\n", client_ip, client_port);

        pid_t pid = fork();

        if (pid < 0) {
            perror("fork failed");
            close(client_sock);
        } else if (pid == 0) {
            // Child process
            close(server_sock);
            handle_client(client_sock, client_ip, client_port);
            exit(0);
        } else {
            // Parent process
            close(client_sock);
        }
    }

    close(server_sock);
    return 0;
}

