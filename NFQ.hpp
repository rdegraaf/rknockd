#ifndef NFQ_NFQ_HPP
    #define NFQ_NFQ_HPP

    #include <exception>
    #include <stdexcept>
    #include <string>
    #include <cstdint>
    #include <memory>
    #include <boost/utility.hpp>
    #include <boost/function.hpp>
    #include <boost/enable_shared_from_this.hpp>
    #include <boost/shared_ptr.hpp>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include "common.h"

    // Maybe std will have a shared_ptr for arrays in C++1z?
    using boost::shared_ptr;
    using boost::enable_shared_from_this;

    extern "C"
    {
    #include <linux/netfilter.h>
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
            typedef u_int16_t QueueNum;
            enum class CopyMode : u_int8_t {
                NONE = NFQNL_COPY_NONE,
                META = NFQNL_COPY_META,
                PACKET = NFQNL_COPY_PACKET
            };

            NfqSocket();
            NfqSocket(QueueNum num) THROW((NfqException));
            ~NfqSocket();
            void connect(QueueNum num) THROW((NfqException));
            void setCopyMode(CopyMode mode, int range=65535) THROW((NfqException));
            shared_ptr<NfqPacket> recvPacket(bool noblock=false) THROW((NfqException));
            void waitForPacket() THROW((NfqException));
            void waitForPacket(int func_fd, boost::function<void()> func);
            void sendResponse(shared_ptr<NfqPacket> pkt) THROW((NfqException));
            void close() THROW((NfqException));
          private:
            bool isConnected;                   // true on sockets that are connected; false otherwise
            QueueNum queueNum;                  // the NFQUEUE queue to which this socket is connected
            CopyMode copyMode;                  // the amount of packet data to copy from kernelspace
            struct nfq_handle* nfqHandle;       // handle to the libnetfilter_queue library
            struct nfq_q_handle* queueHandle;   // handle to a specific libnetfilter_queue queue
            shared_ptr<NfqPacket> pkt;     // packet being received; used by recvPacket()
        };

        // Allowing copies of NfqPackets to be made would break the responseSent 
        // checking.  If it becomes necessary to make copies, at some point, create 
        // an NfqPacketBuffer class that contains all of the data and getters, but 
        // not responseSet or the setters.  Have NfqPacket inherit that, add the
        // setters, give it a private copy constructor and assignment operator, and 
        // write an assignment operator that allows NfqPackets to be safely assigned
        // to NfqPacketBuffers.  The only way to create an NfqPacket should be 
        // from within NfqSocket::recvPacket().
        class NfqPacket : public boost::noncopyable, public enable_shared_from_this<NfqPacket>
        {
          public:
            typedef shared_ptr<NfqPacket> ptr;
            typedef shared_ptr<const NfqPacket> const_ptr;
            enum class Verdict : u_int32_t{
                ACCEPT = NF_ACCEPT,
                DROP = NF_DROP,
                REPEAT = NF_REPEAT
            };
            virtual ~NfqPacket();
            std::uint32_t getId() const;
            std::uint16_t getHwProtocol() const;
            std::uint8_t getNfHook() const;
            std::uint32_t getNfMark() const;
            const struct timeval& getTimestamp() const;
            std::uint32_t getIndev() const;
            std::uint32_t getPhysIndev() const;
            std::uint32_t getOutdev() const;
            std::uint32_t getPhysOutdev() const;
            const std::uint8_t (&getHwSource(std::uint16_t& addrlen) const)[8];
            shared_ptr<const std::uint8_t[]> getPacket(std::size_t& size) const;
            void setVerdict(Verdict v);
            void setNfMark(std::uint32_t mark);
          protected:
            NfqPacket(struct nfq_data* nfa, std::uint8_t* payload, std::size_t psize);
            static int createPacket(struct nfq_q_handle*, struct nfgenmsg*, struct nfq_data*, void*);
            std::unique_ptr<std::uint8_t[]> packet;
            std::size_t packetLen;
          private:
            friend void NfqSocket::connect(NfqSocket::QueueNum); // allow connect to access createPacket
            friend void NfqSocket::sendResponse(NfqPacket::ptr); // allow sendResponse to access responseSent
            struct nfqnl_msg_packet_hdr nfInfo; // 
            std::uint32_t nfMark;
            struct timeval timestamp;
            std::uint32_t indev;
            std::uint32_t physIndev;
            std::uint32_t outdev;
            std::uint32_t physOutdev;
            struct nfqnl_msg_packet_hw hwSource;
            std::uint32_t nfVerdict;
            bool verdictSet;
            bool markSet;
            bool responseSent;
        };

        class NfqIpPacket : public NfqPacket
        {
          public:
            typedef shared_ptr<NfqIpPacket> ptr;
            typedef shared_ptr<const NfqIpPacket> const_ptr;
            std::uint32_t getIpSource() const;
            std::uint32_t getIpDest() const;
            shared_ptr<const struct iphdr> getIpHeader(std::size_t& size) const;
            shared_ptr<const std::uint8_t[]> getIpPayload(std::size_t& size) const;
            virtual ~NfqIpPacket() {}
          protected:
            friend int NfqPacket::createPacket(struct nfq_q_handle*, struct nfgenmsg*, struct nfq_data*, void*);
            NfqIpPacket(struct nfq_data* nfa, std::uint8_t* payload, std::size_t psize);
            inline std::size_t getIpHeaderOffset() const {return 0;}
            inline std::size_t getIpPayloadOffset() const {return (reinterpret_cast<struct iphdr*>(packet.get()))->ihl*4;}
        };

        class NfqTcpPacket : public NfqIpPacket
        {
          public:
            typedef shared_ptr<NfqTcpPacket> ptr;
            typedef shared_ptr<const NfqTcpPacket> const_ptr;
            std::uint16_t getTcpSource() const;
            std::uint16_t getTcpDest() const;
            shared_ptr<const struct tcphdr> getTcpHeader(std::size_t& size) const;
            shared_ptr<const std::uint8_t[]> getTcpPayload(std::size_t& size) const;
          protected:
            friend int NfqPacket::createPacket(struct nfq_q_handle*, struct nfgenmsg*, struct nfq_data*, void*);
            NfqTcpPacket(struct nfq_data* nfa, std::uint8_t* payload, std::size_t psize);
            inline std::size_t getTcpHeaderOffset() const {return getIpPayloadOffset();}
            inline std::size_t getTcpPayloadOffset() const {std::size_t base = getTcpHeaderOffset(); return base + (reinterpret_cast<struct tcphdr*>(packet.get()+base))->doff*4;}
        };

        class NfqUdpPacket : public NfqIpPacket
        {
          public:
            typedef shared_ptr<NfqIpPacket> ptr;
            typedef shared_ptr<const NfqUdpPacket> const_ptr;
            std::uint16_t getUdpSource() const;
            std::uint16_t getUdpDest() const;
            shared_ptr<const struct udphdr> getUdpHeader(std::size_t& size) const;
            shared_ptr<const std::uint8_t[]> getUdpPayload(std::size_t& size) const;
          protected:
            friend int NfqPacket::createPacket(struct nfq_q_handle*, struct nfgenmsg*, struct nfq_data*, void*);
            NfqUdpPacket(struct nfq_data* nfa, std::uint8_t* payload, std::size_t psize);
            inline std::size_t getUdpHeaderOffset() const {return getIpPayloadOffset();}
            inline std::size_t getUdpPayloadOffset() const {return getUdpHeaderOffset() + sizeof(struct udphdr);}
        };

    }

#endif /* NFQ_NFQ_HPP */
