#ifndef RKNOCKD_LISTENER_HPP
    #define RKNOCKD_LISTENER_HPP

    #include <iostream>
    #include "Config.hpp"
    #include "NFQ.hpp"

    namespace Rknockd
    {
        class Listener
        {
          public:
            Listener(bool verbose);
            virtual void operator()() = 0;
            virtual ~Listener();
          protected:
            bool verbose;
            void printPacketInfo(const NFQ::NfqPacket* pkt, std::ostream& out) const;
        };

    }

#endif /* RKNOCKD_LISTENER_HPP */
