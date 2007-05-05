#ifndef RKNOCKD_PKLISTENER_HPP
    #define RKNOCKD_PKLISTENER_JPP
    
    #include <set>
    #include <boost/array.hpp>
    #include "Listener.hpp"
    #include "NFQ.hpp"
    #include "PKConfig.hpp"
    
    namespace Rknockd
    {
        class PKListener : public Listener
        {
          private:
            typedef std::set<boost::uint16_t> PKResponse;
            typedef std::tr1::unordered_map<AddressPair, HostRecord<PKRequest, PKResponse>, AddressPairHash, AddressPairEqual> HostTable;
            //typedef LibWheel::Trie<boost::uint8_t, PKRequest> RequestTable;

            const PKConfig& config;
            HostTable hostTable;
            //RequestTable requestTable;
            HostTableGC<HostTable> hostTableGC;

            HostRecord<PKRequest, PKResponse>& getRecord(const NFQ::NfqUdpPacket* pkt) THROW((UnknownHostException));
            bool checkResponse(const NFQ::NfqUdpPacket* pkt, const HostRecord<PKRequest, PKResponse>& host);
            void openPort(const HostRecord<PKRequest, PKResponse>& host) THROW((IOException));
            void deleteState(const HostRecord<PKRequest, PKResponse>& host);
            const PKRequest& checkRequest(const NFQ::NfqUdpPacket* pkt) THROW((BadRequestException));
            void issueChallenge(const NFQ::NfqUdpPacket* pkt, const PKRequest& req) THROW((CryptoException, IOException, SocketException));
            void handlePacket(const NFQ::NfqPacket* p) THROW((CryptoException));

          public:
            PKListener(const PKConfig& c, bool verbose_logging) THROW((IOException, NFQ::NfqException));
            ~PKListener();
        };
    
    } // namespace Rknockd

#endif /* RKNOCKD_PKLISTENER_HPP */
