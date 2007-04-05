#ifndef RKNOCKD_COMMON_H
    #define RKNOCKD_COMMON_H
    
    #ifdef __cplusplus
        #include <boost/cstdint.hpp>
        using boost::uint16_t;
        using boost::uint8_t;
    #else
        #include <stdint.h>
    #endif

    #ifdef DEBUG
        #define THROW(x) throw x
    #else
        #define THROW(x)
    #endif
    
    #define XQUOTE(x) #x
    #define QUOTE(x) XQUOTE(x)

    #ifdef __cplusplus
    namespace Rknockd
    {
    #endif
    
        #define CLIENT_RECEIVE_TIMEOUT_SECS 0
        #define CLIENT_RECEIVE_TIMEOUT_USECS 500000
    
        #define DEFAULT_BASE_PORT           1024
        #define DEFAULT_MAX_KNOCKS          10
        #define DEFAULT_BITS_PER_KNOCK      8
        #define DEFAULT_CHALLENGE_BYTES     10
        #define DEFAULT_RANDOM_DEVICE       "/dev/random"
        #define MIN_KEY_SIZE                4
        #define MAX_KEY_SIZE                128

        #define MIN_CHALLENGE_BYTES         5
        #define MAX_CHALLENGE_BYTES         128
        #define MIN_REQUEST_BYTES           5
        #define MAX_REQUEST_BYTES           128

        #define HASH_BYTES 20
        #define MAC_BYTES 20
        #define CIPHER_BLOCK_BYTES 16
        #define CIPHER_KEY_BYTES 16
        #define PORT_MESSAGE_PAD_BYTES 7
        #define PORT_MESSAGE_HASH_BYTES 7

        struct PortMessage
        {
            uint16_t port;
            uint8_t pad[PORT_MESSAGE_PAD_BYTES];
            uint8_t hash[PORT_MESSAGE_HASH_BYTES];
        } __attribute__((__packed__));

        struct SpaRequestHeader
        {
            uint16_t requestBytes;
            uint16_t _pad;
            /* the "struct hack" is not allowed in C++ 
               boost::uint8_t request[]; */
        } __attribute__((__packed__));

        struct SpaChallengeHeader
        {
            uint16_t nonceBytes;
            uint16_t _pad;
            uint8_t portMessage[CIPHER_BLOCK_BYTES];
            /* the "struct hack" is not allowed in C++ 
               boost::uint8_t challenge[]; */
        } __attribute__((__packed__));

    #ifdef __cplusplus
    } // namespace Rknockd
    #endif

    
#endif /* RKNOCKD_COMMON_HPP*/
