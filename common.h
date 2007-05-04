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
    
    #define BITS_TO_BYTES(x) (((x)+7) >> 3)

    #ifdef __cplusplus
    namespace Rknockd
    {
    #endif
    
        #define TIMEOUT_SECS 1
        #define TIMEOUT_USECS 0
    
        #define DEFAULT_BASE_PORT           1024
        #define DEFAULT_MAX_KNOCKS          10
        #define DEFAULT_BITS_PER_KNOCK      8
        #define DEFAULT_CHALLENGE_BITS      80
        #define DEFAULT_RANDOM_DEVICE       "/dev/random"
        #define DEFAULT_TTL                 10
        #define MIN_KEY_SIZE                4
        #define MAX_KEY_SIZE                128
        #define MIN_TTL                     1
        #define MAX_TTL                     60

        #define MIN_CHALLENGE_BITS          40
        #define MAX_CHALLENGE_BITS          1024
        #define MIN_REQUEST_BITS            40
        #define MAX_REQUEST_BITS            1024

        #define HASH_BITS                   160
        #define MAC_BITS                    160
        #define CIPHER_BLOCK_BITS           128
        #define CIPHER_KEY_BITS             128
        #define PORT_MESSAGE_PAD_BITS       56
        #define PORT_MESSAGE_HASH_BITS      56

        struct PortMessage
        {
            uint16_t port;
            uint8_t pad[BITS_TO_BYTES(PORT_MESSAGE_PAD_BITS)];
            uint8_t hash[BITS_TO_BYTES(PORT_MESSAGE_HASH_BITS)];
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
            uint8_t portMessage[BITS_TO_BYTES(CIPHER_BLOCK_BITS)];
            /* the "struct hack" is not allowed in C++ 
               boost::uint8_t challenge[]; */
        } __attribute__((__packed__));

    #ifdef __cplusplus
    } // namespace Rknockd
    #endif

    
#endif /* RKNOCKD_COMMON_HPP*/
