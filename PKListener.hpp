#ifndef RKNOCKD_PKLISTENER_HPP
    #define RKNOCKD_PKLISTENER_JPP
    
    #include <set>
    #include <exception>
    #include <stdexcept>
    #include <cstdint>
    #include <tr1/unordered_set>
    #include <tr1/unordered_map>
    #include "Listener.hpp"
    #include "NFQ.hpp"
    #include "PKConfig.hpp"
    
    namespace Rknockd
    {
        class PKListener : public Listener
        {
          private:
          
            class BadRequestException : public std::exception
            {
              public:
                BadRequestException() : exception() {}
            };
          
            struct AddressPair
            {
                uint32_t saddr;
                uint32_t daddr;
                uint16_t sport;
                AddressPair(NFQ::NfqUdpPacket::const_ptr pkt);
                AddressPair(const Listener::HostRecordBase& host);
            };

            struct AddressPairHash
            {
                std::tr1::hash<uint32_t> uhash;
                std::tr1::hash<uint16_t> shash;
                std::size_t operator()(const AddressPair& a) const;
            };
            struct AddressPairEqual
            {
                bool operator() (const AddressPair& a, const AddressPair& b) const;
            };
            
            class HostRecord : public HostRecordBase
            {
              public:
                enum State { CLOSED, REQUEST, CHALLENGE, RESPONSE, OPEN };
                typedef std::tr1::unordered_map<const PKRequest*, KnockSequence> RequestList;
                
                HostRecord(NFQ::NfqUdpPacket::const_ptr pkt);
                State getState() const;
                KnockSequence& getResponse();
                const PKRequest& getRequest() const;
                //const RequestList& getRequests() const;
                void updateState(NFQ::NfqUdpPacket::const_ptr pkt, const PKConfig::RequestList& crequests);
              private:
                State state;
                const PKRequest* request;
                KnockSequence response;
                RequestList requests;
                
                void updateRequest(NFQ::NfqUdpPacket::const_ptr pkt, const PKConfig::RequestList& crequests);
                void updateResponse(NFQ::NfqUdpPacket::const_ptr pkt);
            };
          
            typedef std::tr1::unordered_map<AddressPair, HostRecord, AddressPairHash, AddressPairEqual> HostTable;
            typedef std::tr1::unordered_set<uint16_t> PortSet;

            const PKConfig& config;
            HostTable hostTable;
            HostTableGC<HostTable> hostTableGC;
            PortSet portSet;

            void handlePacket(NFQ::NfqPacket::const_ptr p) THROW((CryptoException));
            HostRecord& getRecord(NFQ::NfqUdpPacket::const_ptr pkt, bool in_request) THROW((BadRequestException));
            //void deleteRecord(NFQ::NfqUdpPacket::const_ptr pkt);
            void deleteRecord(const HostRecord& rec);
            void issueChallenge(HostRecord& rec, NFQ::NfqUdpPacket::const_ptr pkt) THROW((CryptoException, IOException, SocketException));
            
          public:
            PKListener(const PKConfig& c, bool verbose_logging) THROW((IOException, NFQ::NfqException));
            ~PKListener();
        };
    
    } // namespace Rknockd

#endif /* RKNOCKD_PKLISTENER_HPP */
