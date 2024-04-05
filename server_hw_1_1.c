#define _GNU_SOURCE

#include <net/ethernet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static char IP[20];
static unsigned PORT;
static int SOCKET;

enum CONSTS
{
    SPECIAL_PORT = 1105,
};

int
check(struct sockaddr a, struct sockaddr b)
{
    for (int i = 0; i < 6; i++) {
        if (a.sa_data[i] != b.sa_data[i]) return 0;
    }
    return 1;
}

int
main(void)
{
    errno = 0;
    printf("Port? : ");
    fflush(stdout);
    scanf("%u", &PORT);
    printf("IP? (smth like '1.1.1.1' ) : ");
    fflush(stdout);
    scanf("%s", IP);

    struct sockaddr_in addr =
    {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr.s_addr = inet_addr(IP),
    };

    if ((SOCKET = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        fprintf(stderr, "47: Error: %s\n", strerror(errno));
        exit(1);
    }

    if (bind(SOCKET, &addr, sizeof(addr))) {
        fprintf(stderr, "44: Error: %s\n", strerror(errno));
        exit(1);
    }

    printf("SOCKET - OK\n");
    printf("Waiting for clients...\n");
    fflush(stdout);

    struct sockaddr client_f;
    struct sockaddr client_s, bufs;
    ssize_t size;
    char msg[101] = {0};
    socklen_t sl = sizeof(bufs);

    if ((size = recvfrom(SOCKET, msg, 100, 0, &client_f, &sl)) < 0) {
        perror(NULL);
        exit(1);
    }

    printf("There is first client\n");
    printf("ip:port (hex) is: %x.%x.%x.%x:%u\n", client_f.sa_data[2], client_f.sa_data[3], client_f.sa_data[4], client_f.sa_data[5],
            ((unsigned)client_f.sa_data[0] << 8) + (unsigned)client_f.sa_data[1]);

    if ((size = recvfrom(SOCKET, msg, 100, 0, &client_s, &sl)) < 0) {
        perror(NULL);
        exit(1);
    }

    printf("And second...\n");
    printf("ip:port (hex) is: %x.%x.%x.%x:%u\n", client_s.sa_data[2], client_s.sa_data[3], client_s.sa_data[4], client_s.sa_data[5],
            ((unsigned)client_s.sa_data[0] << 8) +  (unsigned)client_s.sa_data[1]);

    if (sendto(SOCKET, "The chat is ready...\n", 22, 0, &client_s, sizeof(client_s)) < 0) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        exit(1);
    }

    while (1) {
        if ((size = recvfrom(SOCKET, msg, 100, 0, &bufs, &sl)) < 0) {
            fprintf(stderr, "90: Error: %s\n", strerror(errno));
            exit(1);
        }
        printf("MSG: %s\n", msg);

        if (check(bufs, client_f)) {
            if (sendto(SOCKET, msg, strnlen(msg, 100) + 1, 0, &client_s, sizeof(client_s)) < 0) {
                fprintf(stderr, "103 Error: %s\n", strerror(errno));
                exit(1);
            }
        } else if (check(bufs, client_s)) {
            if (sendto(SOCKET, msg, strnlen(msg, 100) + 1, 0, &client_f, sizeof(client_f)) < 0) {
                fprintf(stderr, "108 Error: %s\n", strerror(errno));
                exit(1);
            }
        }
    }

    close(SOCKET);
    exit(0);
}
