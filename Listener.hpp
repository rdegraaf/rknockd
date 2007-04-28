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
    
        class Listener
        {
          public:
            virtual void operator()() = 0;
            virtual ~Listener() THROW((IOException, NFQ::NfqException));
          protected:
            Listener(const Config& cfg, const std::string& remap, bool verbose) THROW((IOException, NFQ::NfqException));
            NFQ::NfqSocket sock;
            std::string randomDevice;
            std::string remapFile;
            int randomFD;
            int remapFD;
            bool verbose;
            void printPacketInfo(const NFQ::NfqPacket* pkt, std::ostream& out) const;
        };

    }

#endif /* RKNOCKD_LISTENER_HPP */
