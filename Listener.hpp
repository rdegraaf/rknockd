#ifndef RKNOCKD_LISTENER_HPP
    #define RKNOCKD_LISTENER_HPP

    #include <stdexcept>
    #include <string>
    #include <sstream>
    #include <queue>
    #include <vector>
    #include <cstddef>
    #include <tr1/unordered_map>
    #include <boost/array.hpp>
    #include "auto_array.hpp"
    #include "Config.hpp"
    #include "NFQ.hpp"
    #include "Logmsg.hpp"
    #include "time.h"
    #include "common.h"

    namespace Rknockd
    {
        std::string ipv4_to_string(boost::uint32_t a);

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
                boost::uint32_t saddr;
                boost::uint32_t daddr;
                boost::uint16_t sport;
                boost::uint16_t dport;
                boost::uint16_t targetPort;
              public:
                HostRecordBase(const NFQ::NfqUdpPacket* pkt);
                HostRecordBase(const NFQ::NfqUdpPacket* pkt, boost::uint16_t target);
                virtual ~HostRecordBase();
                boost::uint32_t getSrcAddr() const;
                boost::uint16_t getSrcPort() const;
                boost::uint32_t getDstAddr() const;
                boost::uint16_t getDstPort() const;
                boost::uint16_t getTargetPort() const;
                void setTargetPort(boost::uint16_t);
            };

            Listener(const Config& cfg, const std::string& remap, bool verbose) THROW((IOException, NFQ::NfqException));
            virtual void handlePacket(const NFQ::NfqPacket* p) THROW((CryptoException)) = 0;
            LibWheel::auto_array<boost::uint8_t> generateChallenge(const Config& config, const RequestBase&, size_t& len, const Protocol& proto, boost::uint16_t& dport) THROW((SocketException, IOException, CryptoException));
            void openPort(const HostRecordBase& host, const RequestBase& req) THROW((IOException));
            NFQ::NfqSocket sock;
            std::string randomDevice;
            std::string remapFile;
            int randomFD;
            int remapFD;
            bool verbose;
            
            static boost::uint16_t getPort(boost::uint16_t hint, const Protocol& proto) THROW((SocketException));
            static LibWheel::auto_array<boost::uint8_t> generateResponse(const HostRecordBase& rec, const uint8_t* challenge, size_t clen, bool ignore_client_addr, boost::uint32_t override_server_addr, const std::vector<boost::uint8_t>& request, std::size_t& resp_len);
            static void sendMessage(in_addr_t daddr, in_port_t dport, in_port_t sport, const boost::uint8_t* mess, size_t len) THROW((SocketException, IOException));
            static void printPacketInfo(const NFQ::NfqPacket* pkt, std::ostream& out);
            static void getHash(boost::uint8_t buf[BITS_TO_BYTES(HASH_BITS)], const std::string& str);
            static void getHash(boost::uint8_t buf[BITS_TO_BYTES(HASH_BITS)], const boost::uint8_t* str, size_t strlen);
            static void encryptPort(boost::uint8_t buf[BITS_TO_BYTES(CIPHER_BLOCK_BITS)], boost::uint16_t port, const boost::uint8_t pad[BITS_TO_BYTES(PORT_MESSAGE_PAD_BITS)], const std::string& keystr) THROW((CryptoException));
            static void computeMAC(boost::array<boost::uint8_t, BITS_TO_BYTES(MAC_BITS)>& buf, const std::string& keystr, const boost::uint8_t* msg, size_t msglen) THROW((CryptoException));

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
