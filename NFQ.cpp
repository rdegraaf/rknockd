// based on libnetfilter_queue/utils/nfqnl_test.c
// documentation based on Brad Fisher's post titled "Re: libnetfilter_queue man
// page" to netfilter-devel@lists.netfilter.org on 2006-02-08
// WARNING: not thread-safe, partly because libnetfilter_queue isn't thread-safe

#include <cerrno>
#include <cstring>
#include <cassert>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include "NFQ.hpp"

extern "C" 
{
#include <linux/netfilter.h>
}

namespace NFQ
{

NfqException::NfqException(const std::string& d)
: runtime_error(d)
{}

NfqSocket::NfqSocket()
: isConnected(false), queueNum(), copyMode(META), nfqHandle(NULL), queueHandle(NULL), pkt(NULL)
{}

NfqSocket::NfqSocket(QueueNum num) THROW((LibWheel::SignalException, NfqException))
: isConnected(false), queueNum(), copyMode(META), nfqHandle(NULL), queueHandle(NULL), pkt(NULL)
{
    connect(num);
}

NfqSocket::~NfqSocket() THROW((LibWheel::SignalException, NfqException))
{
    close();
}

// not thread-safe
void
NfqSocket::connect(QueueNum num) THROW((LibWheel::SignalException, NfqException))
{
    if (isConnected)
        throw NfqException("Socket already connected");

    // open library handle
    nfqHandle = nfq_open();
    if (!nfqHandle)
        throw NfqException("Error opening NFQ handle");
    
    // unbind existing nf_queue handler for AF_INET (if any)
    if (nfq_unbind_pf(nfqHandle, AF_INET) < 0)
        throw NfqException("Error unbinding existing queue handler");
    
    // bind nfnetlink_queue as nf_queue handler for AF_INET
    if (nfq_bind_pf(nfqHandle, AF_INET) < 0)
        throw NfqException("Error binding queue handler");
    
    // bind this socket to the specified queue
    queueHandle = nfq_create_queue(nfqHandle, num, NfqPacket::createPacket, &pkt);
    if (!queueHandle)
        throw NfqException("Error creating queue");
    
    // set default copy mode
    setCopyMode(META, 0);

    isConnected = true;
    queueNum = num;
    return;
}

void 
NfqSocket::setCopyMode(CopyMode mode, int range) THROW((LibWheel::SignalException, NfqException))
{
    static boost::uint8_t mode_table[] = 
    {
        NFQNL_COPY_NONE,
        NFQNL_COPY_META,
        NFQNL_COPY_PACKET
    };

    if (nfq_set_mode(queueHandle, mode_table[mode], range) < 0)
        throw NfqException("Error setting copy mode");
}


NfqPacket* 
NfqSocket::recvPacket(bool noblock) THROW((LibWheel::SignalException, NfqException))
{
    char* buf;
    struct nlmsghdr nlh;
    struct sockaddr_nl peer;
    socklen_t addrlen;
    int fd;
    int status;
    int flags;
    
    // NOTE: this may drop messages if more than one message is queued.
    // Can that even happen?
    
    // get a message header
    fd = nfq_fd(nfqHandle);
    addrlen = sizeof(peer);
    flags = MSG_PEEK | (noblock ? MSG_DONTWAIT : 0);
    status = recvfrom(fd, reinterpret_cast<void*>(&nlh), sizeof(nlh), flags, reinterpret_cast<struct sockaddr*>(&peer), &addrlen);
    if (status <= 0)
    {
        throw NfqException(strerror(errno));
    }
    if ((status != sizeof(nlh)) || (addrlen != sizeof(peer)) || (peer.nl_pid != 0) || (nlh.nlmsg_pid != 0))
    {
        throw NfqException(strerror(EPROTO));
    }

    // read packet
    buf = new char[nlh.nlmsg_len];
    flags = noblock ? MSG_DONTWAIT : MSG_WAITALL;
    status = recvfrom(fd, reinterpret_cast<void*>(buf), nlh.nlmsg_len, flags, reinterpret_cast<struct sockaddr*>(&peer), &addrlen);
    if (status <= 0)
    {
        delete[] buf;
        throw NfqException(strerror(errno));
    }
    if ((static_cast<unsigned>(status) != (nlh.nlmsg_len)) || (addrlen != sizeof(peer)) || (peer.nl_pid != 0) || (nlh.nlmsg_flags & MSG_TRUNC))
    {
        delete[] buf;
        throw NfqException(strerror(EPROTO));
    }
    
    if (nfq_handle_packet(nfqHandle, buf, nlh.nlmsg_len) < 0)
    {
        delete[] buf;
        throw NfqException("Error parsing packet");
    }
        
    delete[] buf;
    return pkt;
}


void
NfqSocket::waitForPacket() THROW((LibWheel::SignalException, NfqException))
{
    fd_set fds;
    int ret;
    
    FD_ZERO(&fds);
    FD_SET(nfq_fd(nfqHandle), &fds);
    ret = select(nfq_fd(nfqHandle)+1, &fds, NULL, NULL, NULL);
    if (ret != 1)
    {
        throw NfqException(std::string("Error waiting for packet: ") + std::strerror(errno));
    }
    return;
}

void
NfqSocket::sendResponse(NfqPacket* pkt) THROW((LibWheel::SignalException, NfqException))
{
    int status;
    
    // make sure that a response hasn't already been sent
    if (pkt->responseSent == false)
    {
        if (!pkt->verdictSet)
            throw NfqException("Verdict not set");
    
        if (pkt->markSet)
            status = nfq_set_verdict_mark(queueHandle, pkt->getId(), pkt->nfVerdict, pkt->nfMark, 0, NULL);
        else
            status = nfq_set_verdict(queueHandle, pkt->getId(), pkt->nfVerdict, 0, NULL);
    
        if (status < 0)
            throw NfqException(strerror(errno));
    
        pkt->responseSent = true;
    }
}

// not thread-safe
void
NfqSocket::close() THROW((LibWheel::SignalException, NfqException))
{
    if (isConnected)
    {
        // unbind from queue
        if (nfq_destroy_queue(queueHandle) < 0)
            throw NfqException("Error disconnecting from queue");
    
        // close library handle
        if (nfq_close(nfqHandle) < 0)
            throw NfqException("Error closing NFQ handle");

        isConnected = false;
    }
    return;
}

// create a NfqPacket, store a pointer in *data
int 
NfqPacket::createPacket(struct nfq_q_handle*, struct nfgenmsg*, struct nfq_data *nfa, void *data)
{
    NfqPacket** pkt = reinterpret_cast<NfqPacket**>(data);
    unsigned psize;
    struct iphdr* iph;
    char* ptr;
    
    // get the payload and determine what it is
    //psize = static_cast<unsigned>(nfq_get_payload(nfa, reinterpret_cast<char**>(&iph)));
    psize = static_cast<unsigned>(nfq_get_payload(nfa, &ptr));
    iph = reinterpret_cast<struct iphdr*>(ptr);
    if ((psize >= 20) && (iph->version == 4))
    {
        // assume IPv4 with full header present
        if ((psize >= (iph->ihl*4 + sizeof(struct tcphdr))) && (iph->protocol == 6))
        {
            // assume TCP with full header present
            *pkt = new NfqTcpPacket(nfa);
        }
        else if ((psize >= (iph->ihl*4 + sizeof(struct udphdr))) && (iph->protocol == 17))
        {
            // assume UDP with full header present
            *pkt = new NfqUdpPacket(nfa);
        }
        else
        {
            // some other IP protocol
            *pkt = new NfqIpPacket(nfa);
        }
    }
    else
    {
        // not able to determine the type of the payload
        *pkt = new NfqPacket(nfa);
    }

    return 0;
}

NfqPacket::NfqPacket(struct nfq_data* nfa)
: packet(NULL), packetLen(0), nfInfo(), nfMark(0), timestamp(), indev(0), physIndev(0), outdev(0), physOutdev(0), hwSource(), nfVerdict(0), verdictSet(false), markSet(false), responseSent(false)
{
    struct nfqnl_msg_packet_hw* shw;
    char* ptr;
    int ret;
    
    // copy message contents into this object
    std::memcpy(&nfInfo, nfq_get_msg_packet_hdr(nfa), sizeof(nfInfo));
    nfMark = nfq_get_nfmark(nfa);
    ret = nfq_get_timestamp(nfa, &timestamp);
    if (ret != 0)
    {
        timestamp.tv_sec = 0;
        timestamp.tv_usec = 0;
    }
    indev = nfq_get_indev(nfa);
    physIndev = nfq_get_physindev(nfa);
    outdev = nfq_get_outdev(nfa);
    physOutdev = nfq_get_physoutdev(nfa);
    shw = nfq_get_packet_hw(nfa);
    if (shw != NULL)
    {
        std::memcpy(&hwSource, shw, sizeof(hwSource));
    }
    else
    {
        std::memset(&hwSource, 0, sizeof(hwSource));
    }
    ret = nfq_get_payload(nfa, &ptr);
    if (ret > 0)
    {
        packet = new boost::uint8_t[ret];
        std::memcpy(packet, ptr, ret);
        packetLen = ret;
    }
}

NfqPacket::~NfqPacket()
{
    assert(responseSent == true);
    delete[] packet;
}

// returns the ID assigned to the packet by Netfilter
boost::uint32_t 
NfqPacket::getId() const
{
    return ntohl(nfInfo.packet_id);
}

// returns the level 3 protocol number??
boost::uint16_t
NfqPacket::getHwProtocol() const
{
    return ntohs(nfInfo.hw_protocol);
}

// returns the Netfilter hook number 
// see NF_IP_LOCAL_IN, etc. in <linux/netfilter_ipv4.h>?
boost::uint8_t
NfqPacket::getNfHook() const
{
    return nfInfo.hook;
}

// returns the current Netfilter mark on this packet, or 0 if not known
boost::uint32_t
NfqPacket::getNfMark() const
{
    return nfMark;
}

// returns the time when the packet arrived, or 0 if not known
const struct timeval& 
NfqPacket::getTimestamp() const
{
    return timestamp;
}

// returns the index of the device on which the packet was received.  If the
// index is 0, the packet was locally generated or the input interface is no 
// longer known (ie. POSTROUTING?)
boost::uint32_t
NfqPacket::getIndev() const
{
    return indev;
}

// returns the index of the physical device on which the packet was received.  
// If the index is 0, the packet was locally generated or the input interface is
// no longer known (ie. POSTROUTING?)
boost::uint32_t
NfqPacket::getPhysIndev() const
{
    return physIndev;
}

// returns the index of the device on which the packet will be sent.  If the
// index is 0, the packet is destined for localhost or the output interface is
// not yet known (ie. PREROUTING?)
boost::uint32_t
NfqPacket::getOutdev() const
{
    return outdev;
}

// returns the index of the physical device on which the packet will be sent. 
// If the index is 0, the packet is destined for localhost or the output
// interface is not yet known (ie. PREROUTING?)
boost::uint32_t
NfqPacket::getPhysOutdev() const
{
    return physOutdev;
}

// returns the source hardware address (such as an ethernet MAC address) of the 
// packet, or all zeroes if not known.  The destination hardware address will 
// not be known until after POSTROUTING and a successful ARP request.
// (The return type is a const reference to boost::uint8_t[8].)
const boost::uint8_t (&NfqPacket::getHwSource(boost::uint16_t& addrlen) const)[8]
{
    addrlen = ntohs(hwSource.hw_addrlen);
    return hwSource.hw_addr;
}

// returns the packet contents.  The amount of data returned depends on the copy
// mode:    NONE    - a null pointer will be returned
//          META    - only packet headers will be returned???
//          PACKET  - the entire packet will be returned
const boost::uint8_t*
NfqPacket::getPacket(size_t& size) const
{
    size = packetLen;
    return packet;
}



void 
NfqPacket::setVerdict(Verdict v)
{
    static boost::uint32_t verdict_table[] = 
    {
        NF_ACCEPT,
        NF_DROP,
        NF_REPEAT
    };

    nfVerdict = verdict_table[v];
    verdictSet = true;
}

void 
NfqPacket::setNfMark(boost::uint32_t mark)
{
    nfMark = mark;
    markSet = true;
}


NfqIpPacket::NfqIpPacket(struct nfq_data* nfa)
: NfqPacket(nfa)
{}

const struct iphdr* 
NfqIpPacket::getIpHeader(size_t& size) const
{
    unsigned offset = getIpHeaderOffset();
    size = getIpPayloadOffset() - offset;
    return reinterpret_cast<struct iphdr*>(packet + offset);
}

const boost::uint8_t* 
NfqIpPacket::getIpPayload(size_t& size) const
{
    unsigned offset = getIpPayloadOffset();
    size = packetLen - offset;
    return packet + offset;
}

boost::uint32_t
NfqIpPacket::getIpSource() const
{
    return ntohl((reinterpret_cast<struct iphdr*>(packet+getIpHeaderOffset()))->saddr);
}
    
boost::uint32_t
NfqIpPacket::getIpDest() const
{
    return ntohl((reinterpret_cast<struct iphdr*>(packet+getIpHeaderOffset()))->daddr);
}
    
NfqTcpPacket::NfqTcpPacket(struct nfq_data* nfa)
: NfqIpPacket(nfa)
{}

const struct tcphdr* 
NfqTcpPacket::getTcpHeader(size_t& size) const
{
    unsigned offset = getTcpHeaderOffset();
    size = getTcpPayloadOffset() - offset;
    return reinterpret_cast<struct tcphdr*>(packet + offset);
}

const boost::uint8_t* 
NfqTcpPacket::getTcpPayload(size_t& size) const
{
    unsigned offset = getTcpPayloadOffset();
    size = packetLen - offset;
    return packet + offset;
}

boost::uint16_t
NfqTcpPacket::getTcpSource() const
{
    return ntohs((reinterpret_cast<struct tcphdr*>(packet+getTcpHeaderOffset()))->source);
}

boost::uint16_t
NfqTcpPacket::getTcpDest() const
{
    return ntohs((reinterpret_cast<struct tcphdr*>(packet+getTcpHeaderOffset()))->dest);
}

NfqUdpPacket::NfqUdpPacket(struct nfq_data* nfa)
: NfqIpPacket(nfa)
{}

const struct udphdr* 
NfqUdpPacket::getUdpHeader(size_t& size) const
{
    unsigned offset = getUdpHeaderOffset();
    size = getUdpPayloadOffset() - offset;
    return reinterpret_cast<struct udphdr*>(packet + offset);
}

const boost::uint8_t* 
NfqUdpPacket::getUdpPayload(size_t& size) const
{
    unsigned offset = getUdpPayloadOffset();
    size = packetLen - offset;
    return packet + offset;
}

boost::uint16_t
NfqUdpPacket::getUdpSource() const
{
    return ntohs((reinterpret_cast<struct udphdr*>(packet+getUdpHeaderOffset()))->source);
}

boost::uint16_t
NfqUdpPacket::getUdpDest() const
{
    return ntohs((reinterpret_cast<struct udphdr*>(packet+getUdpHeaderOffset()))->dest);
}

} // namespace NFQ

