#ifndef NFQ_NFQ_HPP
    #define NFQ_NFQ_HPP

    #include <exception>
    #include <stdexcept>
    #include <string>
    #include <boost/utility.hpp>
    #include <boost/cstdint.hpp>
    #include <boost/function.hpp>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include "common.h"

    extern "C"
    {
    #include <libnetfilter_queue/libnetfilter_queue.h>
    }

    /* todo:
        - clean up namespace pollution from C header files
        - use separate exceptions for different types of errors
    */


    namespace NFQ
    {
        class NfqException : public std::runtime_error
        {
          public:
            NfqException(const std::string& d);
        };

        class NfqPacket; // forward declaration


        class NfqSocket : public boost::noncopyable
        {
          public:
            typedef boost::uint16_t QueueNum;
            enum CopyMode {NONE, META, PACKET};

            NfqSocket();
            NfqSocket(QueueNum num) THROW((NfqException));
            ~NfqSocket();
            void connect(QueueNum num) THROW((NfqException));
            void setCopyMode(CopyMode mode, int range=65535) THROW((NfqException));
            NfqPacket* recvPacket(bool noblock=false) THROW((NfqException));
            void waitForPacket() THROW((NfqException));
            void waitForPacket(int func_fd, boost::function<void()> func);
            void sendResponse(NfqPacket* pkt) THROW((NfqException));
            void close() THROW((NfqException));
          private:
            bool isConnected;                   // true on sockets that are connected; false otherwise
            QueueNum queueNum;                  // the NFQUEUE queue to which this socket is connected
            CopyMode copyMode;                  // the amount of packet data to copy from kernelspace
            struct nfq_handle* nfqHandle;       // handle to the libnetfilter_queue library
            struct nfq_q_handle* queueHandle;   // handle to a specific libnetfilter_queue queue
            NfqPacket* pkt;                     // packet being received; used by recvPacket()
        };

        // Allowing copies of NfqPackets to be made would break the responseSent 
        // checking.  If it becomes necessary to make copies, at some point, create 
        // an NfqPacketBuffer class that contains all of the data and getters, but 
        // not responseSet or the setters.  Have NfqPacket inherit that, add the
        // setters, give it a private copy constructor and assignment operator, and 
        // write an assignment operator that allows NfqPackets to be safely assigned
        // to NfqPacketBuffers.  The only way to create an NfqPacket should be 
        // from within NfqSocket::recvPacket().
        class NfqPacket : public boost::noncopyable
        {
          public:
            enum Verdict {ACCEPT, DROP, REPEAT};
            virtual ~NfqPacket();
            boost::uint32_t getId() const;
            boost::uint16_t getHwProtocol() const;
            boost::uint8_t getNfHook() const;
            boost::uint32_t getNfMark() const;
            const struct timeval& getTimestamp() const;
            boost::uint32_t getIndev() const;
            boost::uint32_t getPhysIndev() const;
            boost::uint32_t getOutdev() const;
            boost::uint32_t getPhysOutdev() const;
            const boost::uint8_t (&getHwSource(boost::uint16_t& addrlen) const)[8];
            const boost::uint8_t* getPacket(size_t& size) const;
            void setVerdict(Verdict v);
            void setNfMark(boost::uint32_t mark);
          protected:
            NfqPacket(struct nfq_data* nfa);
            static int createPacket(struct nfq_q_handle*, struct nfgenmsg*, struct nfq_data*, void*);
            boost::uint8_t* packet;
            size_t packetLen;
          private:
            friend void NfqSocket::connect(NfqSocket::QueueNum); // allow connect to access createPacket
            friend void NfqSocket::sendResponse(NfqPacket*); // allow sendResponse to access responseSent
            struct nfqnl_msg_packet_hdr nfInfo; // 
            boost::uint32_t nfMark;
            struct timeval timestamp;
            boost::uint32_t indev;
            boost::uint32_t physIndev;
            boost::uint32_t outdev;
            boost::uint32_t physOutdev;
            struct nfqnl_msg_packet_hw hwSource;
            boost::uint32_t nfVerdict;
            bool verdictSet;
            bool markSet;
            bool responseSent;
        };

        class NfqIpPacket : public NfqPacket
        {
          public:
            boost::uint32_t getIpSource() const;
            boost::uint32_t getIpDest() const;
            const struct iphdr* getIpHeader(size_t& size) const;
            const boost::uint8_t* getIpPayload(size_t& size) const;
            virtual ~NfqIpPacket() {}
          protected:
            friend int NfqPacket::createPacket(struct nfq_q_handle*, struct nfgenmsg*, struct nfq_data*, void*);
            NfqIpPacket(struct nfq_data* nfa);
            inline unsigned getIpHeaderOffset() const {return 0;}
            inline unsigned getIpPayloadOffset() const {return (reinterpret_cast<struct iphdr*>(packet))->ihl*4;}
        };

        class NfqTcpPacket : public NfqIpPacket
        {
          public:
            boost::uint16_t getTcpSource() const;
            boost::uint16_t getTcpDest() const;
            const struct tcphdr* getTcpHeader(size_t& size) const;
            const boost::uint8_t* getTcpPayload(size_t& size) const;
          protected:
            friend int NfqPacket::createPacket(struct nfq_q_handle*, struct nfgenmsg*, struct nfq_data*, void*);
            NfqTcpPacket(struct nfq_data* nfa);
            inline unsigned getTcpHeaderOffset() const {return getIpPayloadOffset();}
            inline unsigned getTcpPayloadOffset() const {unsigned base = getTcpHeaderOffset(); return base + (reinterpret_cast<struct tcphdr*>(packet+base))->doff*4;}
        };

        class NfqUdpPacket : public NfqIpPacket
        {
          public:
            boost::uint16_t getUdpSource() const;
            boost::uint16_t getUdpDest() const;
            const struct udphdr* getUdpHeader(size_t& size) const;
            const boost::uint8_t* getUdpPayload(size_t& size) const;
          protected:
            friend int NfqPacket::createPacket(struct nfq_q_handle*, struct nfgenmsg*, struct nfq_data*, void*);
            NfqUdpPacket(struct nfq_data* nfa);
            inline unsigned getUdpHeaderOffset() const {return getIpPayloadOffset();}
            inline unsigned getUdpPayloadOffset() const {return getUdpHeaderOffset() + sizeof(struct udphdr);}
        };

    }

#endif /* NFQ_NFQ_HPP */
