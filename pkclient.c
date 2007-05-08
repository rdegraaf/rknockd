#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "common.h"

struct pk_config
{
    in_addr_t server_address;
    char key[MAX_KEY_SIZE+1];
    size_t key_len;
    uint16_t request[BITS_TO_BYTES(MAX_CHALLENGE_BITS)];
    size_t request_len;
    enum {IGNORE_CLIENT_ADDRESS, MANUAL_CLIENT_ADDRESS, AUTO_CLIENT_ADDRESS} client_address_mode;
    in_addr_t client_address;
    uint16_t base_port;
    uint16_t bits_per_knock;
};


struct pk_challenge
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


/* buf must be at least 16 bytes */
static void
ipv4_to_string(char* buf, in_addr_t addr)
{
    union
    {
        uint32_t u32;
        uint8_t u8[4];
    } bytes;
    
    bytes.u32 = htonl(addr);
    
    snprintf(buf, 16, "%hhu.%hhu.%hhu.%hhu", bytes.u8[0], bytes.u8[1], bytes.u8[2], bytes.u8[3]);
}


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

static int
open_socket(const struct pk_config* config)
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
    /*retval = connect(sock, (struct sockaddr*)&config->server_address, sizeof(config->server_address));
    if (retval == -1)
    {
        fprintf(stderr, "Error connecting socket: %s\n", strerror(errno));
        return -1;
    }*/
    
    /* FIXME: get local address here */
    
    return sock;
}


static int
send_request(int sock, const struct pk_config* config)
{
    uint8_t message[1];
    ssize_t retval;
    unsigned i;
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = config->server_address; /* already in NBO */
    
    for (i=0; i<config->request_len; ++i)
    {
        addr.sin_port = htons(config->request[i]);
        retval = sendto(sock, message, 0, 0, (struct sockaddr*)&addr, sizeof(addr));
        if (retval == -1)
        {
            fprintf(stderr, "Error sending knock: %s\n", strerror(errno));
            return -1;
        }
    }

    return 0;
}


static int 
receive_challenge(int sock, struct pk_challenge* challenge, const struct pk_config* config)
{
    return 0;
}

static int 
send_response (int sock, const struct pk_challenge* challenge, const struct pk_config* config)
{
    return 0;
}

static int 
parse_request(struct pk_config* config, const char* str)
{
    size_t len;
    unsigned index;
    unsigned knock;
    unsigned bits;
    uint8_t val;
    unsigned tmp;

    len = strlen(str);
    index = 0;
    if ((len >= 2) && (str[0] == '0') && (str[1] == 'x'))
        index = 2;
    if ((len-index+1)*4 < MIN_REQUEST_BITS)
    {
        fprintf(stderr, "Error: request too short\n");
        return -1;
    }
    else if ((len-index+1)*4 > MAX_REQUEST_BITS)
    {   
        fprintf(stderr, "Error: request too long\n");
        return -1;
    }
    else
    {
        config->request_len = 0;
        bits = 0;
        knock = 0;
        while (index < len)
        {
            while ((bits < config->bits_per_knock) && (index < len))
            {
                val = hextobin(str[index]);
                if (val == UINT8_MAX)
                {
                    fprintf(stderr, "Error: invalid digit in request: %c\n", str[index]);
                    return -1;
                }
                knock <<= 4;
                knock |= val;
                ++index;
                bits += 4;
            }
            if (bits >= config->bits_per_knock)
            {
                tmp = config->base_port + (knock >> (bits - config->bits_per_knock)) + config->request_len*(1<<config->bits_per_knock);
                if (tmp > 65535)
                {
                    fprintf(stderr, "Error: request too long for given base port, bits per knock\n");
                    return -1;
                }
                config->request[config->request_len] = tmp;
                config->request_len++;
                bits -= config->bits_per_knock;
                knock &= ((1<<bits)-1);
            }
        }
        if (bits > 0)
        {
            tmp = config->base_port + knock + config->request_len*(1<<config->bits_per_knock);
            if (tmp > 65535)
            {
                fprintf(stderr, "Error: request too long for given base port, bits per knock\n");
                return -1;
            }
            config->request[config->request_len] = tmp;
            config->request_len++;
        }
    }
    return 0;
}


static int
get_config_cmdl(struct pk_config* config, const int argc, const char** argv)
{
    struct hostent* host;
    char* ptr;
    unsigned long tmp;
    int ret;
    
    if (argc != 6)
    {
        fprintf(stderr, "Usage: %s <host> <base port> <bits per knock> <request> <key>\n", argv[0]);
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
    config->server_address = *((in_addr_t*)host->h_addr_list[0]);
    
    /* get the server port number */
    tmp = strtoul(argv[2], &ptr, 10);
    if ((*ptr != '\0') || (tmp > 65535))
    {
        fprintf(stderr, "Invalid port number: %s\n", argv[2]);
        return -1;
    }
    config->base_port = tmp;
    
    /* get the bits per knock */
    tmp = strtoul(argv[3], &ptr, 10);
    if ((*ptr != '\0') || (tmp == 0) || (tmp > 16))
    {
        fprintf(stderr, "Invalid bits per knock: %s\n", argv[2]);
        return -1;
    }
    config->bits_per_knock = tmp;
    
    /* get the request string */
    ret = parse_request(config, argv[4]);
    if (ret == -1)
        return -1;
    
    /* get the key */
    if (strlen(argv[5]) < MIN_KEY_SIZE)
    {
        fprintf(stderr, "Error: key too short\n");
        return -1;
    }
    else if (strlen(argv[5]) > MAX_KEY_SIZE)
    {
        fprintf(stderr, "Error: Key too long\n");
        return -1;
    }
    config->key_len = strlen(argv[5]);
    strncpy(config->key, argv[5], config->key_len);
    
    return 0;
}

static int
get_config_term(struct pk_config* config)
{
    fprintf(stderr, "Error: interactive mode not yet implemented\n");
    return -1;
}


static int
get_config(struct pk_config* config, const int argc, const char** argv)
{
    /* common initialization */
    memset(config, 0, sizeof(struct pk_config));
    
    if (argc > 1)
        return get_config_cmdl(config, argc, argv);
    else
        return get_config_term(config);
}


static void
print_config(const struct pk_config* config, FILE* file)
{
    unsigned i;
    char buf[16];
    
    ipv4_to_string(buf, ntohl(config->server_address));
    fprintf(file, "Server:  %s/%hu\n", buf, config->base_port);
    fputs("Request: ", file);
    for (i=0; i<config->request_len; i++)
        fprintf(file, "%hu ", config->request[i]);
    fputc('\n', file);
    fprintf(file, "Key:     %s\n", config->key);
}


int 
main(int argc, const char** argv)
{
    struct pk_config config;
    struct pk_challenge challenge;
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


    /* clean up */
    memset(&config, 0, sizeof(config));
    close(sock);

    
    return EXIT_SUCCESS;
}
