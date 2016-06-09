#ifndef RKNOCKD_LISTENER_HPP
    #define RKNOCKD_LISTENER_HPP

    #include <stdexcept>
    #include <string>
    #include <sstream>
    #include <queue>
    #include <vector>
    #include <array>
    #include <cstddef>
    #include <tr1/unordered_map>
    #include "Config.hpp"
    #include "NFQ.hpp"
    #include "Logmsg.hpp"
    #include "time.h"
    #include "common.h"

    namespace Rknockd
    {
        std::string ipv4_to_string(uint32_t a);

        class IOException : public std::runtime_error
        {
          public:
            IOException(const std::string& s);
        };
    
        class CryptoException : public std::runtime_error
        {
          public:
            CryptoException(const std::string& s);
        };

        class BadRequestException : public std::runtime_error
        {
          public:
            BadRequestException(const std::string& s);
        };

        class UnknownHostException : public std::runtime_error
        {
          public:
            UnknownHostException(const std::string& s);
        };

        class SocketException : public std::runtime_error
        {
          public:
            SocketException(const std::string& s);
        };

        class Listener
        {
          public:
            void operator()();
            virtual ~Listener();
            virtual void close() THROW((IOException, NFQ::NfqException));
          protected:
            class HostRecordBase
            {
              protected:
                uint32_t saddr;
                uint32_t daddr;
                uint16_t sport;
                uint16_t dport;
                uint16_t targetPort;
              public:
                HostRecordBase(NFQ::NfqUdpPacket::const_ptr pkt);
                HostRecordBase(NFQ::NfqUdpPacket::const_ptr pkt, uint16_t target);
                virtual ~HostRecordBase();
                uint32_t getSrcAddr() const;
                uint16_t getSrcPort() const;
                uint32_t getDstAddr() const;
                uint16_t getDstPort() const;
                uint16_t getTargetPort() const;
                void setTargetPort(uint16_t);
            };

            Listener(const Config& cfg, const std::string& remap, bool verbose) THROW((IOException, NFQ::NfqException));
            virtual void handlePacket(NFQ::NfqPacket::const_ptr p) THROW((CryptoException)) = 0;
            std::unique_ptr<uint8_t[]> generateChallenge(const Config& config, const RequestBase&, size_t& len, const Protocol& proto, uint16_t& dport) THROW((SocketException, IOException, CryptoException));
            void openPort(const HostRecordBase& host, const RequestBase& req) THROW((IOException));
            NFQ::NfqSocket sock;
            std::string randomDevice;
            std::string remapFile;
            int randomFD;
            int remapFD;
            bool verbose;
            
            static uint16_t getPort(uint16_t hint, const Protocol& proto) THROW((SocketException));
            static std::unique_ptr<uint8_t[]> generateResponse(const HostRecordBase& rec, const uint8_t* challenge, size_t clen, bool ignore_client_addr, uint32_t override_server_addr, const std::vector<uint8_t>& request, std::size_t& resp_len);
            static void sendMessage(in_addr_t daddr, in_port_t dport, in_port_t sport, const uint8_t* mess, size_t len) THROW((SocketException, IOException));
            static void printPacketInfo(NFQ::NfqPacket::const_ptr pkt, std::ostream& out);
            static void getHash(uint8_t buf[BITS_TO_BYTES(HASH_BITS)], const std::string& str);
            static void getHash(uint8_t buf[BITS_TO_BYTES(HASH_BITS)], const uint8_t* str, size_t strlen);
            static void encryptPort(uint8_t buf[BITS_TO_BYTES(CIPHER_BLOCK_BITS)], uint16_t port, const uint8_t pad[BITS_TO_BYTES(PORT_MESSAGE_PAD_BITS)], const std::string& keystr) THROW((CryptoException));
            static void computeMAC(std::array<uint8_t, BITS_TO_BYTES(MAC_BITS)>& buf, const std::string& keystr, const uint8_t* msg, size_t msglen) THROW((CryptoException));

            template <typename HostTableType>
            class HostTableGC
            {
              public:
                HostTableGC(HostTableType& t, bool verbose_logging);
                void schedule(typename HostTableType::key_type& addr, long secs, long usecs);
                void operator()();
              private:
                HostTableType& table;
                std::queue<std::pair<struct timeval, typename HostTableType::key_type> > gcQueue;
                bool verbose;
            };
    
          private:
            class ListenerConstructor
            {
              public:
                ListenerConstructor();
            };
        
            static ListenerConstructor _listenerConstructor;
        };

    } // namespace Rknockd

#include "Listener_impl.cpp"

#endif /* RKNOCKD_LISTENER_HPP */
