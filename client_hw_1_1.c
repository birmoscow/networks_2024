#define _GNU_SOURCE

#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static const char ARG_SERVER[] = "--server";
static const char ARG_CLIENT[] = "--client";
static const char ARG_HELP[] = "--help";
static const char EXIT[] = "exit()";
static char MODE;
static char IP[20];
static unsigned PORT;
static int SOCKET;

enum CONSTS
{
    MAX_LEN = 100,
};


void
startTCPServer(struct sockaddr_in addr)
{

    SOCKET = socket(AF_INET, SOCK_STREAM, 0);
    if (bind(SOCKET, &addr, sizeof(addr))) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        exit(1);
    }

    printf("SOCKET - OK\n");
    fflush(stdout);

    if (listen(SOCKET, 1) != 0) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        exit(1);
    }

    int isActive = 1;
    ssize_t msgLen;
    char msg[MAX_LEN + 1] = {0};
    while (isActive) {
        int curClient = accept(SOCKET, NULL, 0);
        if (send(curClient, "Hi!\n", 5, 0) < 0) {
            fprintf(stderr, "Error: %s\n", strerror(errno));
            exit(1);
        }
        while (msgLen = recv(curClient, msg, MAX_LEN, 0)) {
            if (msgLen < 0) {
                fprintf(stderr, "Error: %s\n", strerror(errno));
                exit(1);
            }
            printf("Msg : %s\n\n", msg);
            printf("Your answer or write 'exit()' to exit: ");
            fflush(stdout);
            for (int i = 0; i < MAX_LEN + 1; ++i) {
                msg[i] = 0;
            }
            scanf("%s", msg);

            if (strncmp(msg, EXIT, sizeof(EXIT)) == 0) {
                close(curClient);
                break;
            }
            if (send(curClient, msg, strnlen(msg, MAX_LEN), 0) < 0) {
                fprintf(stderr, "Error: %s\n", strerror(errno));
                exit(1);
            }
        }

        char bufChar;
        int flag = 1;
        while (flag) {
            printf("Exit? (y/n) ? :");
            fflush(stdout);
            scanf("%c", &bufChar);
            if (bufChar == 'y') {
                isActive = 0;
                flag = 0;
            } else if (bufChar == 'n') {
                flag = 0;
            }
        }
    }
}


void
startUDPServer(struct sockaddr_in addr)
{
    SOCKET = socket(AF_INET, SOCK_DGRAM, 0);
    if (bind(SOCKET, &addr, sizeof(addr))) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        exit(1);
    }

    printf("SOCKET - OK\n");
    fflush(stdout);
    char msg[MAX_LEN + 1] = {0};
    int flag = 1;
    char *clientIP;
    struct sockaddr_in client;
    while (flag) {
        recvfrom(SOCKET, msg, MAX_LEN, 0, NULL, 0);
        unsigned ba, bb, bc, bd, be;
        if (sscanf(msg, "%u.%u.%u.%u:%u", &ba, &bb, &bc, &bd, &be) == 5) {
            if (ba < 256 && bb < 256 && bc < 256 && bd < 256) {
                if (asprintf(&clientIP, "%u.%u.%u.%u", ba, bb, bc, bd) < 0) {
                    fprintf(stderr, "Error: %s\n", strerror(errno));
                    exit(1);
                }
                printf("Hello, %s:%u!\n", clientIP, be);
                fflush(stdout);
                client.sin_family = AF_INET,
                client.sin_port = htons(be),
                client.sin_addr.s_addr = inet_addr(clientIP),
                free(clientIP);
                flag = 0;
            }
        }
    }


    for (int i = 0; i < MAX_LEN + 1; ++i) {
        msg[i] = 0;
    }
    flag = 1;
    if (sendto(SOCKET, "Hello!\n", 8, 0, &client, sizeof(client)) < 0) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        exit(1);
    }

    while (flag) {
        recvfrom(SOCKET, msg, MAX_LEN, 0, &client, sizeof(client));
        printf("Msg: %s\n", msg);
        printf("Answer: ");
        fflush(stdout);
        for (int i = 0; i < MAX_LEN + 1; ++i) {
            msg[i] = 0;
        }
        scanf("%s", msg);
        if (sendto(SOCKET, msg, strnlen(msg, MAX_LEN), 0, &client, sizeof(client)) < 0) {
            fprintf(stderr, "Error: %s\n", strerror(errno));
            exit(1);
        }
    }
}


void
startTCPClient(struct sockaddr_in addr)
{


    SOCKET = socket(AF_INET, SOCK_STREAM, 0);
    char msg[MAX_LEN + 1] = {0};
    ssize_t msgLen;
    if (connect(SOCKET, &addr, sizeof(addr)) < 0) {
        fprintf(stderr, "190 Error: %s\n", strerror(errno));
        exit(1);
    }

    while (msgLen = recv(SOCKET, msg, MAX_LEN, 0)) {
        if (msgLen < 0) {
            fprintf(stderr, "196 Error: %s\n", strerror(errno));
            exit(1);
        }
        printf("Msg : %s\n\n", msg);
        printf("Your answer or write 'exit()' to exit: ");
        fflush(stdout);
        for (int i = 0; i < MAX_LEN + 1; ++i) {
            msg[i] = 0;
        }
        scanf("%s", msg);

        if (strncmp(msg, EXIT, sizeof(EXIT)) == 0) {
            break;
        }
        if (send(SOCKET, msg, strnlen(msg, MAX_LEN), 0) < 0) {
            fprintf(stderr, "Error: %s\n", strerror(errno));
            exit(1);
        }
    }

}


void
startUDPClient(struct sockaddr_in addr)
{
    SOCKET = socket(AF_INET, SOCK_DGRAM, 0);
    if (bind(SOCKET, (struct sockaddr*)&addr, sizeof(addr))) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        exit(1);
    }

    printf("SOCKET - OK\n");
    printf("Who is server?\n");
    fflush(stdout);

    unsigned port;
    char ip[21];
    int flag = 1;
    while (flag) {
        printf("Port? : ");
        fflush(stdout);
        if (scanf("%u", &port) == 1) {
            flag = 0;
        }
    }

    printf("IP? (smth like '1.1.1.1' ) : ");
    fflush(stdout);
    scanf("%20s", ip);
    struct sockaddr_in addrServ =
    {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = inet_addr(ip),
    };


    char msg[MAX_LEN + 1] = {0};
    flag = 1;
    char *buf_str;

    if (asprintf(&buf_str, "%s:%u", IP, PORT) < 0) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        exit(1);
    }
    if (sendto(SOCKET, buf_str, strlen(buf_str) + 1, 0, &addrServ, sizeof(addrServ)) < 0) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        exit(1);
    }

    while (flag) {
        recvfrom(SOCKET, msg, MAX_LEN, 0, &addrServ, sizeof(addrServ));
        printf("Msg: %s\n", msg);
        printf("Answer: ");
        fflush(stdout);
        for (int i = 0; i < MAX_LEN + 1; ++i) {
            msg[i] = 0;
        }
        scanf("%s", msg);
        if (sendto(SOCKET, msg, strnlen(msg, MAX_LEN) + 1, 0, &addrServ, sizeof(addrServ)) < 0) {
            fprintf(stderr, "Error: %s\n", strerror(errno));
            exit(1);
        }
    }
}

int
main(int argc, char **argv)
{
    errno = 0;
    if (argc < 2) {
        fprintf(stderr, "Error: incorrect mode\n");
        exit(1);
    } else if (strncmp(argv[1], ARG_SERVER, sizeof(ARG_SERVER)) == 0) {
        MODE = 's';
    } else if (strncmp(argv[1], ARG_CLIENT, sizeof(ARG_CLIENT)) == 0) {
        MODE = 'c';
    } else if (strncmp(argv[1], ARG_HELP, sizeof(ARG_HELP)) == 0) {
        printf("--server for server mode\n"
               "--client for client mode\n");
        exit(0);
    } else {
        fprintf(stderr, "Error: incorrect mode\n");
        exit(1);
    }

    char buf;
    int flag = 1;
    while (flag) {
        printf("TCP or UDP? ('t'/'u'): ");
        fflush(stdout);
        scanf("%c", &buf);
        if (buf == 't' || buf == 'u') {
            flag = 0;
        }
    }

    if (MODE == 'c' && buf == 't') {
        printf("ENTER SERVER INFO!\n");
    }

    fflush(stdout);
    flag = 1;
    while (flag) {
        printf("Port? : ");
        fflush(stdout);
        if (scanf("%u", &PORT) == 1) {
            flag = 0;
        }
    }

    printf("IP? (smth like '1.1.1.1' ) : ");
    fflush(stdout);
    scanf("%20s", IP);
    struct sockaddr_in addr =
    {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr.s_addr = inet_addr(IP),
    };

    if (MODE == 's' && buf == 't') {
        startTCPServer(addr);
    } else if (MODE == 's') {
        startUDPServer(addr);
    } else if (MODE == 'c' && buf == 't') {
        startTCPClient(addr);
    } else {
        startUDPClient(addr);
    }

    close(SOCKET);
    exit(0);
}
