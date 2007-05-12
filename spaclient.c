#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include "common.h"

union uint32_u
{
    uint32_t u32;
    uint8_t u8[4];
};

struct spa_config
{
    struct sockaddr_in server_address;
    char key[MAX_KEY_SIZE+1];
    size_t key_len;
    uint8_t request[BITS_TO_BYTES(MAX_REQUEST_BITS)];
    size_t request_len;
    enum {IGNORE_CLIENT_ADDRESS, MANUAL_CLIENT_ADDRESS, AUTO_CLIENT_ADDRESS} client_address_mode;
    in_addr_t client_address;
};

struct spa_challenge
{
    uint16_t port;
    uint16_t nonce_len;
    uint8_t nonce[BITS_TO_BYTES(MAX_CHALLENGE_BITS)];
};
    
/*****************************
 getline(FILE*)
 Reads in a line of input from a file, storing it in a dynamically-allocated
   string
 Params:  FILE* file - the file to read from
 Returns: a string containing the line.  Must be freed with free()
 Effects: I/O
*/ 
static char* 
getLine(FILE* file, int stripnl)
{
    char* ptr = NULL;
    char* nptr = NULL;
    size_t len = 0;
#define LINE_SIZE 80
    size_t size = LINE_SIZE;
    size_t oldsize = 0;
    
    do
    {
        /* allocate an appropriately-sized buffer */
        nptr = realloc(ptr, size+1);
        if (nptr == NULL)
        {
            free(ptr);
            return NULL;
        }
        ptr = nptr;
        
        /* read into the buffer */
        fgets(&ptr[oldsize], size-oldsize+1, file);
        len = strlen(ptr);
        
        if (size > (UINT_MAX/2))
            return ptr;
        oldsize = size;
        size*=2;
    } while (ptr[len-1] != '\n');
    
    /* remove trailing newline */
    if (stripnl)
        ptr[len-1] = '\0';
    
    return ptr;
}


/* addr must be in network byte order */
/*static char* 
ipv4_to_string(char buf[16], in_addr_t addr)
{
    union uint32_u u;
    u.u32 = addr;
    
    snprintf(buf, 16, "%hhu.%hhu.%hhu.%hhu", u.u8[0], u.u8[1], u.u8[2], u.u8[3]);
    return buf;
}*/

static uint8_t
hextobin(char c)
{
    switch (c)
    {
        case '0':
            return 0; break;
        case '1':
            return 1; break;
        case '2':
            return 2; break;
        case '3':
            return 3; break;
        case '4':
            return 4; break;
        case '5':
            return 5; break;
        case '6':
            return 6; break;
        case '7':
            return 7; break;
        case '8':
            return 8; break;
        case '9':
            return 9; break;
        case 'a': case 'A':
            return 10; break;
        case 'b': case 'B':
            return 11; break;
        case 'c': case 'C':
            return 12; break;
        case 'd': case 'D':
            return 13; break;
        case 'e': case 'E':
            return 14; break;
        case 'f': case 'F':
            return 15; break;
        default:
            return UINT8_MAX;
    }
}

static void
print_config(const struct spa_config* config, FILE* file)
{
    unsigned i;
    
    fprintf(file, "Server:  %s/%hu\n", inet_ntoa(config->server_address.sin_addr), ntohs(config->server_address.sin_port));
    fputs("Request: 0x", file);
    for (i=0; i<config->request_len; i++)
        fprintf(file, "%hhx", config->request[i]);
    fputc('\n', file);
    fprintf(file, "Key:     %s\n", config->key);
}

static int
get_config_cmdl(struct spa_config* config, const int argc, const char** argv)
{
    struct hostent* host;
    char* ptr;
    unsigned long tmp;
    size_t len;
    unsigned i;
    uint8_t high, low;
    
    if (argc != 5)
    {
        fprintf(stderr, "Usage: %s <host> <port> <request> <key>\n", argv[0]);
        return -1;
    }
    
    /* get the server address */
    host = gethostbyname(argv[1]);
    if (host == NULL)
    {
        fprintf(stderr, "Error resolving host %s: %s\n", argv[1], hstrerror(h_errno));
        return -1;
    }
    if ((host->h_addrtype != AF_INET) || (host->h_length != 4) || (host->h_addr_list[0] == NULL))
    {
        fprintf(stderr, "Unexpected result from gethostbyname()");
        return -1;
    }
    config->server_address.sin_addr.s_addr = *((in_addr_t*)host->h_addr_list[0]);
    
    /* get the server port number */
    tmp = strtoul(argv[2], &ptr, 10);
    if ((*ptr != '\0') || (tmp > 65535))
    {
        fprintf(stderr, "Invalid port number: %s\n", argv[2]);
        return -1;
    }
    config->server_address.sin_port = htons(tmp);
    
    /* get the request string */
    len = strlen(argv[3]);
    i = 0;
    if ((len >= 2) && (argv[3][0] == '0') && (argv[3][1] == 'x'))
        i = 2;
    if ((len-i+1)*4 < MIN_REQUEST_BITS)
    {
        fprintf(stderr, "Error: request too short\n");
        return -1;
    }
    else if ((len-i+1)*4 > MAX_REQUEST_BITS)
    {
        fprintf(stderr, "Error: request too long\n");
        return -1;
    }
    else
    {
        config->request_len = 0;
        if ((len-i) & 0x00000001)
        {
            /* handle the first character separately */
            low = hextobin(argv[3][i++]);
            config->request[config->request_len++] = low;
        }
    
        for (; i<len; i+=2)
        {
            high = hextobin(argv[3][i]);
            low = hextobin(argv[3][i+1]);
            if ((high == UINT8_MAX) || (low == UINT8_MAX))
            {
                fprintf(stderr, "Error: invalid character in request string\n");
                return -1;
            }
            config->request[config->request_len++] = (high<<4)|low;
        }
    }
    
    /* get the key */
    if (strlen(argv[4]) < MIN_KEY_SIZE)
    {
        fprintf(stderr, "Error: key too short\n");
        return -1;
    }
    else if (strlen(argv[4]) > MAX_KEY_SIZE)
    {
        fprintf(stderr, "Error: key too long\n");
        return -1;
    }
    config->key_len = strlen(argv[4]);
    strncpy(config->key, argv[4], config->key_len);
        
    return 0;
}

static int
get_config_term(struct spa_config* config)
{
    fprintf(stderr, "Error: interactive mode not yet implemented\n");
    return -1;
}

static int
get_config(struct spa_config* config, const int argc, const char** argv)
{
    /* common initialization */
    memset(config, 0, sizeof(struct spa_config));
    config->server_address.sin_family = AF_INET;
    
    if (argc > 1)
        return get_config_cmdl(config, argc, argv);
    else
        return get_config_term(config);
}

static int
open_socket(const struct spa_config* config)
{
    int sock;
    int retval;
    struct sockaddr_in addr;
    
    /* open */
    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock == -1)
    {
        fprintf(stderr, "Error opening socket: %s\n", strerror(errno));
        return -1;
    }
    
    /* bind */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    retval = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (retval == -1)
    {
        fprintf(stderr, "Error binding socket: %s\n", strerror(errno));
        return -1;
    }
    
    /* connect */
    retval = connect(sock, (struct sockaddr*)&config->server_address, sizeof(config->server_address));
    if (retval == -1)
    {
        fprintf(stderr, "Error connecting socket: %s\n", strerror(errno));
        return -1;
    }
    
    /* FIXME: get local address here */
    
    return sock;
}

static int
send_request(int sock, const struct spa_config* config)
{
    uint8_t* message;
    size_t len;
    ssize_t retval;

    assert(config != NULL);
    
    /* build the request message */
    len = sizeof(struct SpaRequestHeader) + config->request_len;
    message = malloc(len);
    if (message == NULL)
    {
        fprintf(stderr, "Error: out of memory\n");
        return -1;
    }
    memset(message, 0, sizeof(struct SpaRequestHeader));
    ((struct SpaRequestHeader*)message)->requestBytes = htons(config->request_len);
    memcpy(message+sizeof(struct SpaRequestHeader), config->request, config->request_len);
    
    /* send the request */
    retval = send(sock, message, len, 0);
    if (retval == -1)
    {
        fprintf(stderr, "Error sending request: %s\n", strerror(errno));
        free(message);
        return -1;
    }
    else if (retval != (ssize_t)len)
    {
        fprintf(stderr, "Error sending request: message truncated\n");
        free(message);
        return -1;
    }
    free(message);
    return 0;
}

static int decrypt_port(uint16_t* port, const uint8_t* buf, const char* key, size_t keylen)
{
    uint8_t hash[BITS_TO_BYTES(HASH_BITS)];
    struct PortMessage message;
    AES_KEY ctx;
    int retval;
    
    assert(sizeof(struct PortMessage)*8 == CIPHER_BLOCK_BITS);
    assert(HASH_BITS >= PORT_MESSAGE_HASH_BITS);
    assert(HASH_BITS >= CIPHER_KEY_BITS);

    /* generate the decryption key */
    SHA1((unsigned char*)key, keylen, hash);
    
    /* decrypt the message */
    retval = AES_set_decrypt_key(hash, 128, &ctx);
    if (retval)
    {
        fprintf(stderr, "Error setting decryption key\n");
        return -1;
    }
    AES_ecb_encrypt(buf, (unsigned char*)&message, &ctx, AES_DECRYPT);

    /* verify the hash */
    SHA1((unsigned char*)&message, offsetof(struct PortMessage, hash), hash);
    if (memcmp(hash, message.hash, sizeof(message.hash)))
    {
        fprintf(stderr, "Error verifying challenge hash\n");
        return -1;
    }

#ifdef DEBUG
    fprintf(stderr, "received challenge, dport=%hu\n", ntohs(message.port));
#endif

    *port = ntohs(message.port);
    return 0;
}

static int
receive_challenge(int sock, struct spa_challenge* challenge, const struct spa_config* config)
{
    uint8_t buf[sizeof(struct ChallengeHeader)+BITS_TO_BYTES(MAX_CHALLENGE_BITS)];
    int retval;
    struct timeval timeout;
    
    assert(challenge != NULL);
    assert(config != NULL);
    
    /* set the socket timeout */
    timeout.tv_sec = TIMEOUT_SECS;
    timeout.tv_usec = TIMEOUT_USECS;
    retval = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (retval == -1)
    {
        fprintf(stderr, "Error setting socket timeout: %s\n", strerror(errno));
        return -1;
    }
    
    /* receive the message */
    retval = recv(sock, buf, sizeof(buf), 0);
    if (retval == -1)
    {
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
            fprintf(stderr, "Timeout waiting for server response\n");
        else
            fprintf(stderr, "Error receiving challenge: %s\n", strerror(errno));
        return -1;
    }

    /* parse the message */    
    challenge->nonce_len = ntohs(((struct ChallengeHeader*)buf)->nonceBytes);
    if (retval != (int)(sizeof(struct ChallengeHeader)+challenge->nonce_len))
    {
        fprintf(stderr, "Error receiving challenge: message truncated\n");
        return -1;
    }
    memcpy(challenge->nonce, buf+sizeof(struct ChallengeHeader), challenge->nonce_len);
    retval = decrypt_port(&challenge->port, buf+offsetof(struct ChallengeHeader, portMessage), config->key, config->key_len);
    if (retval)
        return -1; /* error message already logged */
    
    return 0;
}

static int compute_mac(uint8_t* mac, int sock, const struct spa_challenge* challenge, const struct spa_config* config)
{
    uint8_t* buf;
    size_t buflen;
    union uint32_u u;
    struct sockaddr_in addr;
    socklen_t addr_len;
    int retval;
    uint8_t key[BITS_TO_BYTES(HASH_BITS)];
    
    assert(challenge != NULL);
    assert(config != NULL);
    
    /* allocate a buffer for the message */
    buflen = challenge->nonce_len + sizeof(uint32_t) + sizeof(uint32_t) + config->request_len;
    buf = malloc(buflen);
    if (buf == NULL)
    {
        fprintf(stderr, "Error: out of memory\n");
        return -1;
    }
    
    /* copy the challenge into the message */
    memcpy(buf, challenge->nonce, challenge->nonce_len);
    
    /* copy the client address into the message */
    if (config->client_address_mode == IGNORE_CLIENT_ADDRESS)
        u.u32 = 0;
    else if (config->client_address_mode == MANUAL_CLIENT_ADDRESS)
        u.u32 = config->client_address; /* already in NBO */
    else
    {
        addr_len = sizeof(addr);
        retval = getsockname(sock, (struct sockaddr*)&addr, &addr_len);
        if (retval == -1)
        {
            fprintf(stderr, "Error retrieving socket address: %s\n", strerror(errno));
            return -1;
        }
        printf("WARNING: Using auto-detected source address %s\n", inet_ntoa(addr.sin_addr));
        printf("If this address is modified in transit by a NAT, authentication will fail.\n");
        u.u32 = addr.sin_addr.s_addr; /* already in NBO */
    }
    memcpy(buf+challenge->nonce_len, u.u8, sizeof(uint32_t));
    
    /* copy the server address into the message */    
    u.u32 = config->server_address.sin_addr.s_addr; /* already in NBO */
    memcpy(buf+challenge->nonce_len+sizeof(uint32_t), u.u8, sizeof(uint32_t));
    
    /* copy the request into the message */
    memcpy(buf+challenge->nonce_len+2*sizeof(uint32_t), config->request, config->request_len);

    /* generate the MAC key */
    SHA1((unsigned char*)config->key, config->key_len, key);
    
    /* generate the MAC */
    HMAC(EVP_sha1(), key, BITS_TO_BYTES(HASH_BITS), buf, buflen, mac, NULL);
    
    free(buf);
    return 0;
}

static int
send_response(int sock, const struct spa_challenge* challenge, const struct spa_config* config)
{
    uint8_t buf[BITS_TO_BYTES(HASH_BITS)];
    int retval;
    
    assert(challenge != NULL);
    assert(config != NULL);
    
    retval = compute_mac(buf, sock, challenge, config);
    if (retval == -1)
        return -1; /* error message already logged */
    
    /* send the response */
    retval = send(sock, buf, sizeof(buf), 0);
    if (retval == -1)
    {
        fprintf(stderr, "Error sending response: %s\n", strerror(errno));
        return -1;
    }
    else if (retval != (ssize_t)sizeof(buf))
    {
        fprintf(stderr, "Error sending response: message truncated\n");
        return -1;
    }
    return 0;
}

int 
main(int argc, const char** argv)
{
    struct spa_config config;
    struct spa_challenge challenge;
    int retval;
    int sock;
    
    retval = get_config(&config, argc, argv);
    if (retval)
        exit(EXIT_FAILURE); /* error message already printed */
    print_config(&config, stdout);
    
    /* FIXME: set client address mode properly */
    config.client_address_mode = AUTO_CLIENT_ADDRESS;
    
    sock = open_socket(&config);
    if (sock == -1)
        exit(EXIT_FAILURE); /* error message already printed */
    retval = send_request(sock, &config);
    if (retval)
        exit(EXIT_FAILURE); /* error message already printed */
    retval = receive_challenge(sock, &challenge, &config);
    if (retval)
        exit(EXIT_FAILURE); /* error message already logged */
    retval = send_response(sock, &challenge, &config);
    if (retval)
        exit(EXIT_FAILURE); /* error message already logged */

    printf("Authentication complete; port = %hu\n", challenge.port);

    /* clean up */
    memset(&config, 0, sizeof(config));
    close(sock);

    
    return EXIT_SUCCESS;
}
