#include <openssl/ssl.h>
#include <openssl/err.h>

#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>


enum CONSTS
{
    MAX_LEN = 4096,
    MIN_ARG = 2,
    IP_SIZE = 20,
};


static const char ARG_SERVER[] = "--server";
static const char ARG_CLIENT[] = "--client";
static const char ARG_HELP[] = "--help";
static char MODE;
static char IP[IP_SIZE];
static unsigned PORT;
static int SOCKET;


void SSL_CTX_keylog_cb_func_cb(const SSL *ssl, const char *line){
    FILE  * fp;
    fp = fopen("keylog", "a");
    if (fp == NULL)
    {
        printf("Failed to create log file\n");
        exit(1);
    }
    fprintf(fp, "%s\n", line);
    fclose(fp);
}


void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}


void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}


/*          */
/*  SERVER  */
/*          */


int OpenListener(const struct sockaddr addr)
{
    SOCKET = socket(AF_INET, SOCK_STREAM, 0);
    if (bind(SOCKET, &addr, sizeof(addr))) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        exit(1);
    }

    if (listen(SOCKET, 1) != 0) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        exit(1);
    }

    printf("SOCKET - OK\n");
    fflush(stdout);

    return SOCKET;
}


SSL_CTX* InitServerCTX(void)
{
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    const SSL_METHOD *method = TLS_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}


void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
    char buf[MAX_LEN] = {0};
    int sd, bytes;

    if ( SSL_accept(ssl) == -1 ) {     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    } else {
        ShowCerts(ssl);        /* get any certificates */
        while ((bytes = SSL_read(ssl, buf, sizeof(buf))) > 0) {
            buf[bytes] = '\0';
            printf("Client msg: \"%s\"\n", buf);

            printf("Answer: ");
            fflush(stdout);

            scanf("%s", buf);
            SSL_write(ssl, buf, strlen(buf) + 1);
        }
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}


void
startTCPServer(struct sockaddr addr)
{
    if ((getuid() != 0)) {
        fprintf(stderr, "sudo?\n");
        exit(1);
    }


    SSL_CTX *ctx;
    int server;

    // Initialize the SSL library
    SSL_library_init();
    ctx = InitServerCTX();        /* initialize SSL */

    SSL_CTX_set_keylog_callback(ctx, SSL_CTX_keylog_cb_func_cb);


    LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
    server = OpenListener(addr);    /* create server socket */


    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        Servlet(ssl);         /* service connection */
    }
    SSL_CTX_free(ctx);         /* release context */
}


/*          */
/*  CLIENT  */
/*          */


int OpenConnection(const struct sockaddr addr)
{
    SOCKET = socket(AF_INET, SOCK_STREAM, 0);
    if ( connect(SOCKET, &addr, sizeof(addr)) != 0 )
    {
        close(SOCKET);
        fprintf(stderr, "CONNECTION ERR\n");
        exit(1);
    }
    return SOCKET;
}


SSL_CTX* InitCTX(void)
{
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    const SSL_METHOD *method = TLS_client_method();
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}


void
startTCPClient(struct sockaddr addr)
{
    SSL_CTX *ctx;
    SSL *ssl;
    char buf[MAX_LEN];
    int bytes;

    SSL_library_init();
    ctx = InitCTX();

    SSL_CTX_set_keylog_callback(ctx, SSL_CTX_keylog_cb_func_cb);

    OpenConnection(addr);
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, SOCKET);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == -1 )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */
        SSL_write(ssl, "Hello! Its me!", strlen("Hello! Its me!") + 1);   /* encrypt & send message */

        while((bytes = SSL_read(ssl, buf, sizeof(buf))) > 0) { /* get reply & decrypt */
            buf[bytes] = 0;
            printf("Received: \"%s\"\n", buf);
            printf("Answer: ");
            fflush(stdout);
            scanf("%s", buf);
            SSL_write(ssl, buf, sizeof(buf));
        }


        SSL_free(ssl);        /* release connection state */
    }
    SSL_CTX_free(ctx);        /* release context */
}


int
main(int argc, char **argv)
{
    errno = 0;
    if (argc < MIN_ARG) {
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

    if (MODE == 'c') {
        printf("ENTER SERVER INFO!\n");
    }

    fflush(stdout);
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

    if (MODE == 's') {
        startTCPServer(*((struct sockaddr*)&addr));
    } else {
        startTCPClient(*((struct sockaddr*)&addr));
    }

    close(SOCKET);
    exit(0);
}
