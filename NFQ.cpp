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


namespace NFQ
{

NfqException::NfqException(const std::string& d)
: runtime_error(d)
{}

NfqSocket::NfqSocket()
: isConnected(false), queueNum(), copyMode(CopyMode::META), nfqHandle(NULL), queueHandle(NULL), pkt(nullptr)
{}

NfqSocket::NfqSocket(QueueNum num) THROW((NfqException))
: isConnected(false), queueNum(), copyMode(CopyMode::META), nfqHandle(NULL), queueHandle(NULL), pkt(nullptr)
{
    connect(num);
}

NfqSocket::~NfqSocket()
{
    try {
        close();
    } catch (const NfqException& e) {
    }
}

// not thread-safe
void
NfqSocket::connect(QueueNum num) THROW((NfqException))
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
    setCopyMode(CopyMode::META, 0);

    isConnected = true;
    queueNum = num;
    return;
}

void 
NfqSocket::setCopyMode(CopyMode mode, int range) THROW((NfqException))
{
    if (nfq_set_mode(queueHandle, u_int8_t(mode), range) < 0)
        throw NfqException("Error setting copy mode");
}


std::unique_ptr<NfqPacket>
NfqSocket::recvPacket(bool noblock) THROW((NfqException))
{
    // NOTE: this may drop messages if more than one message is queued.
    // Can that even happen?
    
    // get a message header
    struct nlmsghdr nlh;
    struct sockaddr_nl peer;
    int fd = nfq_fd(nfqHandle);
    socklen_t addrlen = sizeof(peer);
    int flags = MSG_PEEK | (noblock ? MSG_DONTWAIT : 0);
    ssize_t status = recvfrom(fd, reinterpret_cast<void*>(&nlh), sizeof(nlh), flags, reinterpret_cast<struct sockaddr*>(&peer), &addrlen);
    if (status <= 0) {
        throw NfqException(strerror(errno));
    }
    if ((status != sizeof(nlh)) || (addrlen != sizeof(peer)) || (peer.nl_pid != 0) || (nlh.nlmsg_pid != 0)) {
        throw NfqException(strerror(EPROTO));
    }

    // read packet
    std::unique_ptr<char[]> buf(new char[nlh.nlmsg_len]);
    flags = noblock ? MSG_DONTWAIT : MSG_WAITALL;
    status = recvfrom(fd, reinterpret_cast<void*>(buf.get()), nlh.nlmsg_len, flags, reinterpret_cast<struct sockaddr*>(&peer), &addrlen);
    if (status <= 0) {
        throw NfqException(strerror(errno));
    }
    if ((static_cast<unsigned>(status) != (nlh.nlmsg_len)) || (addrlen != sizeof(peer)) || (peer.nl_pid != 0) || (nlh.nlmsg_flags & MSG_TRUNC)) {
        throw NfqException(strerror(EPROTO));
    }
    
    if (nfq_handle_packet(nfqHandle, buf.get(), nlh.nlmsg_len) < 0) {
        throw NfqException("Error parsing packet");
    }
        
    return std::move(pkt);
}


void
NfqSocket::waitForPacket() THROW((NfqException))
{
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(nfq_fd(nfqHandle), &fds);
    int ret = select(nfq_fd(nfqHandle)+1, &fds, NULL, NULL, NULL);
    if (ret != 1) {
        throw NfqException(std::string("Error waiting for packet: ") + std::strerror(errno));
    }
    return;
}
void 
NfqSocket::waitForPacket(int func_fd, boost::function<void()> func)
{
    fd_set fds;
    int ret;
    int max_fd = (func_fd > nfq_fd(nfqHandle)) ? func_fd : nfq_fd(nfqHandle);
    while (1) {
        FD_ZERO(&fds);
        FD_SET(nfq_fd(nfqHandle), &fds);
        FD_SET(func_fd, &fds);
        do {
            ret = select(max_fd+1, &fds, NULL, NULL, NULL);
        } while ((ret == -1) && (errno == EINTR));
        if (ret == -1) {
            throw NfqException(std::string("Error waiting for packet: ") + std::strerror(errno));
        } else if (FD_ISSET(func_fd, &fds)) {
            func();
            if (ret == 2) {
                return;
            }
        } else {
            return;
        }
    }
}


void
NfqSocket::sendResponse(NfqPacket* pkt) THROW((NfqException))
{
    // make sure that a response hasn't already been sent
    if (pkt->responseSent == false) {
        if (!pkt->verdictSet)
            throw NfqException("Verdict not set");

        int status;
        if (pkt->markSet)
            status = nfq_set_verdict2(queueHandle, pkt->getId(), pkt->nfVerdict, pkt->nfMark, 0, NULL);
        else
            status = nfq_set_verdict(queueHandle, pkt->getId(), pkt->nfVerdict, 0, NULL);
    
        if (status < 0)
            throw NfqException(strerror(errno));
    
        pkt->responseSent = true;
    }
}

//TODO not thread-safe
void
NfqSocket::close() THROW((NfqException))
{
    if (isConnected) {
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
    // get the payload and determine what it is
    std::uint8_t* payload;
    //TODO: handle an error return
    std::size_t psize = static_cast<std::size_t>(nfq_get_payload(nfa, &payload));
    NfqPacket** pkt = reinterpret_cast<NfqPacket**>(data);
    if ((psize >= sizeof(struct iphdr)) && (reinterpret_cast<struct iphdr*>(payload)->version == 4)) {
        // assume IPv4 with full header present
        struct iphdr* iph = reinterpret_cast<struct iphdr*>(payload);
        if ((psize >= (iph->ihl*4 + sizeof(struct tcphdr))) && (iph->protocol == IPPROTO_TCP)) {
            // assume TCP with full header present
            *pkt = new NfqTcpPacket(nfa, payload, psize);
        } else if ((psize >= (iph->ihl*4 + sizeof(struct udphdr))) && (iph->protocol == IPPROTO_UDP)) {
            // assume UDP with full header present
            *pkt = new NfqUdpPacket(nfa, payload, psize);
        } else {
            // some other IP protocol
            *pkt = new NfqIpPacket(nfa, payload, psize);
        }
    } else {
        // not able to determine the type of the payload
        *pkt = new NfqPacket(nfa, payload, psize);
    }

    return 0;
}

NfqPacket::NfqPacket(struct nfq_data* nfa, std::uint8_t* payload, std::size_t psize)
: packet(new std::uint8_t[psize]), packetLen(psize), nfInfo(), nfMark(0), timestamp(), indev(0), physIndev(0), outdev(0), physOutdev(0), hwSource(), nfVerdict(0), verdictSet(false), markSet(false), responseSent(false)
{
    // copy message contents into this object
    std::memcpy(&nfInfo, nfq_get_msg_packet_hdr(nfa), sizeof(nfInfo));
    nfMark = nfq_get_nfmark(nfa);
    int ret = nfq_get_timestamp(nfa, &timestamp);
    if (ret != 0) {
        timestamp.tv_sec = 0;
        timestamp.tv_usec = 0;
    }
    indev = nfq_get_indev(nfa);
    physIndev = nfq_get_physindev(nfa);
    outdev = nfq_get_outdev(nfa);
    physOutdev = nfq_get_physoutdev(nfa);
    struct nfqnl_msg_packet_hw* shw;
    shw = nfq_get_packet_hw(nfa);
    if (shw != NULL) {
        std::memcpy(&hwSource, shw, sizeof(hwSource));
    } else {
        std::memset(&hwSource, 0, sizeof(hwSource));
    }
    if ((psize > 0) && (nullptr != payload)) {
        std::memcpy(packet.get(), payload, psize);
    }
}

NfqPacket::~NfqPacket()
{
    assert(responseSent == true);
}

// returns the ID assigned to the packet by Netfilter
std::uint32_t 
NfqPacket::getId() const
{
    return ntohl(nfInfo.packet_id);
}

// returns the level 3 protocol number??
std::uint16_t
NfqPacket::getHwProtocol() const
{
    return ntohs(nfInfo.hw_protocol);
}

// returns the Netfilter hook number 
// see NF_IP_LOCAL_IN, etc. in <linux/netfilter_ipv4.h>?
std::uint8_t
NfqPacket::getNfHook() const
{
    return nfInfo.hook;
}

// returns the current Netfilter mark on this packet, or 0 if not known
std::uint32_t
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
std::uint32_t
NfqPacket::getIndev() const
{
    return indev;
}

// returns the index of the physical device on which the packet was received.  
// If the index is 0, the packet was locally generated or the input interface is
// no longer known (ie. POSTROUTING?)
std::uint32_t
NfqPacket::getPhysIndev() const
{
    return physIndev;
}

// returns the index of the device on which the packet will be sent.  If the
// index is 0, the packet is destined for localhost or the output interface is
// not yet known (ie. PREROUTING?)
std::uint32_t
NfqPacket::getOutdev() const
{
    return outdev;
}

// returns the index of the physical device on which the packet will be sent. 
// If the index is 0, the packet is destined for localhost or the output
// interface is not yet known (ie. PREROUTING?)
std::uint32_t
NfqPacket::getPhysOutdev() const
{
    return physOutdev;
}

// returns the source hardware address (such as an ethernet MAC address) of the 
// packet, or all zeroes if not known.  The destination hardware address will 
// not be known until after POSTROUTING and a successful ARP request.
// (The return type is a const reference to uint8_t[8].)
const std::uint8_t (&NfqPacket::getHwSource(std::uint16_t& addrlen) const)[8]
{
    addrlen = ntohs(hwSource.hw_addrlen);
    return hwSource.hw_addr;
}

// returns the packet contents.  The amount of data returned depends on the copy
// mode:    NONE    - a null pointer will be returned
//          META    - only packet headers will be returned???
//          PACKET  - the entire packet will be returned
const std::uint8_t*
NfqPacket::getPacket(std::size_t& size) const
{
    size = packetLen;
    return packet.get();
}


void 
NfqPacket::setVerdict(Verdict v)
{
    nfVerdict = u_int32_t(v);
    verdictSet = true;
}

void 
NfqPacket::setNfMark(std::uint32_t mark)
{
    nfMark = mark;
    markSet = true;
}


NfqIpPacket::NfqIpPacket(struct nfq_data* nfa, std::uint8_t* payload, std::size_t psize)
: NfqPacket(nfa, payload, psize)
{
    assert((nullptr != packet) && (0 != packetLen));
}

const struct iphdr* 
NfqIpPacket::getIpHeader(std::size_t& size) const
{
    std::size_t offset = getIpHeaderOffset();
    size = getIpPayloadOffset() - offset;
    return reinterpret_cast<struct iphdr*>(packet.get() + offset);
}

const std::uint8_t* 
NfqIpPacket::getIpPayload(std::size_t& size) const
{
    std::size_t offset = getIpPayloadOffset();
    size = packetLen - offset;
    return packet.get() + offset;
}

std::uint32_t
NfqIpPacket::getIpSource() const
{
    return ntohl((reinterpret_cast<struct iphdr*>(packet.get()+getIpHeaderOffset()))->saddr);
}

std::uint32_t
NfqIpPacket::getIpDest() const
{
    return ntohl((reinterpret_cast<struct iphdr*>(packet.get()+getIpHeaderOffset()))->daddr);
}

NfqTcpPacket::NfqTcpPacket(struct nfq_data* nfa, std::uint8_t* payload, std::size_t psize)
: NfqIpPacket(nfa, payload, psize)
{}

const struct tcphdr* 
NfqTcpPacket::getTcpHeader(std::size_t& size) const
{
    std::size_t offset = getTcpHeaderOffset();
    size = getTcpPayloadOffset() - offset;
    return reinterpret_cast<struct tcphdr*>(packet.get() + offset);
}

const std::uint8_t* 
NfqTcpPacket::getTcpPayload(std::size_t& size) const
{
    std::size_t offset = getTcpPayloadOffset();
    size = packetLen - offset;
    return packet.get() + offset;
}

std::uint16_t
NfqTcpPacket::getTcpSource() const
{
    return ntohs((reinterpret_cast<struct tcphdr*>(packet.get()+getTcpHeaderOffset()))->source);
}

std::uint16_t
NfqTcpPacket::getTcpDest() const
{
    return ntohs((reinterpret_cast<struct tcphdr*>(packet.get()+getTcpHeaderOffset()))->dest);
}

NfqUdpPacket::NfqUdpPacket(struct nfq_data* nfa, std::uint8_t* payload, std::size_t psize)
: NfqIpPacket(nfa, payload, psize)
{}

const struct udphdr* 
NfqUdpPacket::getUdpHeader(std::size_t& size) const
{
    std::size_t offset = getUdpHeaderOffset();
    size = getUdpPayloadOffset() - offset;
    return reinterpret_cast<struct udphdr*>(packet.get() + offset);
}

const std::uint8_t* 
NfqUdpPacket::getUdpPayload(std::size_t& size) const
{
    std::size_t offset = getUdpPayloadOffset();
    size = packetLen - offset;
    return packet.get() + offset;
}

std::uint16_t
NfqUdpPacket::getUdpSource() const
{
    return ntohs((reinterpret_cast<struct udphdr*>(packet.get()+getUdpHeaderOffset()))->source);
}

std::uint16_t
NfqUdpPacket::getUdpDest() const
{
    return ntohs((reinterpret_cast<struct udphdr*>(packet.get()+getUdpHeaderOffset()))->dest);
}

} // namespace NFQ

