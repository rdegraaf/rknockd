#ifndef RKNOCKD_LISTENER_HPP
    #define RKNOCKD_LISTENER_HPP

    #include <iostream>
    #include <stdexcept>
    #include <string>
    #include "Config.hpp"
    #include "NFQ.hpp"
    #include "common.h"

    namespace Rknockd
    {
        class IOException : public std::runtime_error
        {
          public:
            IOException(const std::string& s);
        };
    
        class CryptoException : public std::runtime_error
        {
          public:
            CryptoException(const std::string& s) : runtime_error(s) {}
        };

        class Listener
        {
          public:
            void operator()();
            virtual ~Listener();
            virtual void close() THROW((IOException, NFQ::NfqException));
          protected:
            Listener(const Config& cfg, const std::string& remap, bool verbose) THROW((IOException, NFQ::NfqException));
            virtual void handlePacket(const NFQ::NfqPacket* p) THROW((CryptoException)) = 0;
            NFQ::NfqSocket sock;
            std::string randomDevice;
            std::string remapFile;
            int randomFD;
            int remapFD;
            bool verbose;
            static void printPacketInfo(const NFQ::NfqPacket* pkt, std::ostream& out);
        };

    }

#endif /* RKNOCKD_LISTENER_HPP */
