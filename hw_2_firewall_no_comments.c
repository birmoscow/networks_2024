#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

static char MODE;
enum
{
    PARAMS = 5,
    IP_SZ_CONST = 20,
    IP_BYTES = 4,
    B_FST = 0,
    B_SND = 1,
    B_TRD = 2,
    B_FTH = 3,
    MIN_ARGC = 3,
    IF_FST = 1,
    IF_SND = 2,
    ETH_TYPE_FST_BYTE = 12,
    ETH_TYPE_SND_BYTE = 13,
    MAX_PKT_SIZE = 70000,
    TRUE = 1,
    FALSE = 0,
    PORT_BYTES = 2,
    OFFSET_IPV4_PROTO = 23,
    OFFSET_IPV4_SRC = 26,
    OFFSET_IPV4_DST = 30,
    OFFSET_PORT_SRC = 34,
    OFFSET_PORT_DST = 36,
    UDP = 17,
    TCP = 6,
};


// BIG-ENDIAN
typedef struct Rule
{
    unsigned char src_ip[IP_BYTES];
    unsigned char dst_ip[IP_BYTES];
    unsigned char src_port[PORT_BYTES];
    unsigned char dst_port[PORT_BYTES];
    char proto;
} Rule;


typedef struct List
{
    struct List *next;
    Rule rule;
} List;


void
freeList(List *head)
{
    List *buf;
    while (head && head->next) {
        buf = head;
        head = head->next;
        free(buf);
    }

    if (head) free(head);
}


List*
readFile(void)
{
    FILE *rules = fopen("rules.bir", "r");
    if (rules == NULL) {
        fprintf(stderr, "Cannot open 'rules.bir'\n");
        exit(1);
    }

    fscanf(rules, "%c\n", &MODE);
    List *head = NULL;
    List *last = NULL;
    Rule bufRule;
    char bufStr1[IP_SZ_CONST], bufStr2[IP_SZ_CONST];
    int scanf_ret;
    unsigned ub1, ub2;
    while ((scanf_ret = fscanf(rules, "%c%s%u%s%u\n", &bufRule.proto,
                                              bufStr1,
                                              &ub1,
                                              bufStr2,
                                              &ub2)) != EOF) {
        if (scanf_ret != PARAMS) {
            fprintf(stderr, "Smth goes wrong in readFile()\n");
            fprintf(stderr, "scanf_ret = %d\n proto: %c\n", scanf_ret, bufRule.proto);
            exit(1);
        }

        if (bufStr1[0] == '0') {
            for (int i = 0; i < IP_BYTES; ++i) bufRule.src_ip[i] = 0;
        } else {
            if (sscanf(bufStr1, "%hhu.%hhu.%hhu.%hhu", &bufRule.src_ip[B_FST], &bufRule.src_ip[B_SND],
                    &bufRule.src_ip[B_TRD], &bufRule.src_ip[B_FTH]) != IP_BYTES) {
                fprintf(stderr, "Smth goes wrong in readFile()\n");
                exit(1);
            }
        }

        if (bufStr2[0] == '0') {
             for (int i = 0; i < IP_BYTES; ++i) bufRule.dst_ip[i] = 0;
        } else {
            if (sscanf(bufStr2, "%hhu.%hhu.%hhu.%hhu", &bufRule.dst_ip[B_FST], &bufRule.dst_ip[B_SND],
                    &bufRule.dst_ip[B_TRD], &bufRule.dst_ip[B_FTH]) != IP_BYTES) {
                fprintf(stderr, "Smth goes wrong in readFile()\n");
                exit(1);
            }
        }

        bufRule.src_port[B_FST] = (ub1 & 0xFF00) >> 8;
        bufRule.src_port[B_SND] = ub1 & 0xFF;

        bufRule.dst_port[B_FST] = (ub2 & 0xFF00) >> 8;
        bufRule.dst_port[B_SND] = ub2 & 0xFF;

        List *cur = malloc(sizeof(List));
        cur->next = NULL;
        cur->rule = bufRule;

        if (head == NULL) {
            head = cur;
            last = cur;
        } else {
            last->next = cur;
            last = cur;
        }
    }

    fclose(rules);
    return head;
}


int
isARP(unsigned char *frame)
{
    if (frame[ETH_TYPE_FST_BYTE] == 0x08 && frame[ETH_TYPE_SND_BYTE] == 0x06) {
        return TRUE;
    }
    return FALSE;
}


int
isIPv4(unsigned char *frame)
{
    if (frame[ETH_TYPE_FST_BYTE] == 0x08 && frame[ETH_TYPE_SND_BYTE] == 0x00) {
        return TRUE;
    }
    return FALSE;
}


int
chkRule_src_ip(Rule rule) {
    if (rule.src_ip[B_FST] == 0 && rule.src_ip[B_SND] == 0 &&
        rule.src_ip[B_TRD] == 0 && rule.src_ip[B_FTH] == 0) return FALSE;
    return TRUE;
}


int
chkRule_dst_ip(Rule rule) {
    if (rule.dst_ip[B_FST] == 0 && rule.dst_ip[B_SND] == 0 &&
        rule.dst_ip[B_TRD] == 0 && rule.dst_ip[B_FTH] == 0) return FALSE;
    return TRUE;
}


int
chkRule_src_port(Rule rule) {
    if (rule.src_port[B_FST] == 0 && rule.src_port[B_SND] == 0) return FALSE;
    return TRUE;
}


int
chkRule_dst_port(Rule rule) {
    if (rule.dst_port[B_FST] == 0 && rule.dst_port[B_SND] == 0) return FALSE;
    return TRUE;
}


void
filter(int in, int out, List *rules)
{
    unsigned char *buf = malloc(MAX_PKT_SIZE);
    while (TRUE) {
        size_t size = read(in, buf, MAX_PKT_SIZE);
        if (isARP(buf) || !isIPv4(buf)) {
            write(out, buf, size);
            continue;
        }

        List *bufRule = rules;
        int flag = 0;
        while (bufRule) {
            flag = 1;
            if (bufRule->rule.proto == 'u' && buf[OFFSET_IPV4_PROTO] != UDP) flag = 0;
            if (bufRule->rule.proto == 't' && buf[OFFSET_IPV4_PROTO] != TCP) flag = 0;
            if (chkRule_src_ip(bufRule->rule)) {
                for (int i = 0; i < IP_BYTES; ++i) {
                    if (buf[OFFSET_IPV4_SRC + i] != bufRule->rule.src_ip[i]) flag = 0;
                }
            }

            if (chkRule_dst_ip(bufRule->rule)) {
                for (int i = 0; i < IP_BYTES; ++i) {
                    if (buf[OFFSET_IPV4_DST + i] != bufRule->rule.dst_ip[i]) flag = 0;
                }
            }

            if (chkRule_src_port(bufRule->rule)) {
                for (int i = 0; i < PORT_BYTES; ++i) {
                    if (buf[OFFSET_PORT_SRC + i] != bufRule->rule.src_port[i]) flag = 0;
                }
            }

            if (chkRule_dst_port(bufRule->rule)) {
                for (int i = 0; i < PORT_BYTES; ++i) {
                    if (buf[OFFSET_PORT_DST + i] != bufRule->rule.dst_port[i]) flag = 0;
                }
            }


            if (flag == 1) break;
            bufRule = bufRule->next;
        }

        if (flag && MODE == 'w') {
            write(out, buf, size);
        }

        if (!flag && MODE == 'b') {
            write(out, buf, size);
        }
    }
}


int
main(int argc, char **argv)
{
    if (argc < MIN_ARGC) {
        printf("format: %s <int_id> <int_id>\n", argv[0]);
        exit(0);
    }

    errno = 0;
    List *rules = readFile();

    int in = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (in <= 0) {
        fprintf(stderr, "%s\n", strerror(errno));
        exit(1);
    }

    int out = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));


    if (out <= 0) {
        fprintf(stderr, "%s\n", strerror(errno));
        exit(1);
    }

    struct sockaddr_ll in_if;
    struct sockaddr_ll out_if;

    in_if.sll_family = AF_PACKET;
    in_if.sll_protocol = htons(ETH_P_ALL);
    out_if.sll_family = AF_PACKET;
    out_if.sll_protocol = htons(ETH_P_ALL);

    sscanf(argv[IF_FST], "%d", &in_if.sll_ifindex);
    sscanf(argv[IF_SND], "%d", &out_if.sll_ifindex);

    if (bind(in, (const struct sockaddr*)&in_if, sizeof(struct sockaddr_ll)) == -1) {
        printf("bind err 0\n");
        exit(1);
    }

    if (bind(out, (const struct sockaddr*)&out_if, sizeof(struct sockaddr_ll)) == -1) {
        printf("bind err 1\n");
        exit(1);
    }

    pid_t pid = fork();
    switch (pid) {
        case -1:
            perror("fork\n");
            exit(1);
        case 0:
            filter(out, in, rules);
            break;
        default:
            filter(in, out, rules);
            break;
    }

    freeList(rules);
    close(in);
    close(out);

    return 0;
}
