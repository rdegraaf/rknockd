#include <stdexcept>
#include <string>
#include <cstring>
#include <cerrno>
#include <boost/cstdint.hpp>
#include <unistd.h>
#include <fcntl.h>
#include <gcrypt.h>
#include "Config.hpp"
#include "Listener.hpp"
#include "NFQ.hpp"
#include "Signals.hpp"
#include "Logmsg.hpp"
#include "common.h"

namespace Rknockd
{


    union uint32_u
    {
        boost::uint32_t u32;
        boost::uint8_t u8[sizeof(boost::uint32_t)];
    };

// static data members
Listener::ListenerConstructor Listener::_listenerConstructor;


IOException::IOException(const std::string& s) 
: runtime_error(s) 
{}

CryptoException::CryptoException(const std::string& s) 
: runtime_error(s) 
{}

BadRequestException::BadRequestException(const std::string& s) 
: runtime_error(s) 
{}

UnknownHostException::UnknownHostException(const std::string& s) 
: runtime_error(s) 
{}

SocketException::SocketException(const std::string& s) 
: runtime_error(s) 
{}

Listener::Listener(const Config& cfg, const std::string& remap, bool v) THROW((IOException, NFQ::NfqException))
: sock(cfg.getNfQueueNum()), randomDevice(cfg.getRandomDevice()), remapFile(remap), randomFD(), remapFD(), verbose(v)
{
    sock.setCopyMode(NFQ::NfqSocket::PACKET);
    
    randomFD = ::open(cfg.getRandomDevice().c_str(), O_RDONLY);
    if (randomFD == -1)
        throw IOException(std::string("Error opening ") + cfg.getRandomDevice() + ": " + std::strerror(errno));

    remapFD = open(remap.c_str(), O_WRONLY);
    if (remapFD == -1)
        throw IOException(std::string("Error opening /proc/") + remap + ": " + std::strerror(errno));
}

Listener::~Listener()
{
    if (remapFD != 0)
        ::close(remapFD);

    if (randomFD != 0)
        ::close(randomFD);
    
    try
    {
        sock.close();
    } 
    catch (const NFQ::NfqException& e)
    {}
}


/* 
Entry point for SpaListener
*/
void 
Listener::operator() ()
{
    try
    {
        // loop forever, processing packets
        // send the process a SIGINT to stop 
        while (1)
        {
            try
            {
                sock.waitForPacket(LibWheel::SignalQueue::getReadFD(), LibWheel::SignalQueue::handleNext);
                NFQ::NfqPacket* packet = sock.recvPacket(true);

                // set the verdict first, so that we don't keep the kernel waiting
                packet->setVerdict(NFQ::NfqPacket::DROP);
                sock.sendResponse(packet);
/*#ifdef DEBUG
                printPacketInfo(packet, std::cout);
#endif*/
                // handle the packet
                handlePacket(packet);

                delete packet;
            }
            catch (const NFQ::NfqException& e)
            {
                LibWheel::logmsg(LibWheel::logmsg_err, "Error processing packet: %s", e.what());
            }
        }
    }
    catch (const LibWheel::Interrupt& e) // thrown when SIGINT is caught
    {
        LibWheel::logmsg(LibWheel::logmsg_notice, "SIGINT caught; exiting normally\n");
    }
    catch (const CryptoException& e)
    {
        LibWheel::logmsg(LibWheel::logmsg_crit, "Error in libgcrypt: %s", e.what());
    }
}


void
Listener::close() THROW((NFQ::NfqException, IOException))
{
    if (::close(remapFD) == -1)
        throw IOException(std::string("Error closing /proc/") + remapFile + ": " + std::strerror(errno));
    remapFD = 0;
    
    if (::close(randomFD) == -1)
        throw IOException(std::string("Error closing /proc/") + randomDevice + ": " + std::strerror(errno));
    randomFD = 0;
    
    sock.close();
}


void 
Listener::printPacketInfo(const NFQ::NfqPacket* packet, std::ostream& out)
{
    const NFQ::NfqTcpPacket* tcp_packet = dynamic_cast<const NFQ::NfqTcpPacket*>(packet);
    const NFQ::NfqUdpPacket* udp_packet = dynamic_cast<const NFQ::NfqUdpPacket*>(packet);
    const NFQ::NfqIpPacket* ip_packet = dynamic_cast<const NFQ::NfqIpPacket*>(packet);

    if (udp_packet)
    {
        out << "UDP packet received\n"
            << "  Source address:         " << std::hex << udp_packet->getIpSource() << std::dec
            << "\n  Destination address:    " << std::hex << udp_packet->getIpDest() << std::dec
            << "\n  Source port:            " << udp_packet->getUdpSource()
            << "\n  Destination port:       " << udp_packet->getUdpDest()
            << std::endl;
    }
    else if (tcp_packet) 
    {
        out << "TCP packet received\n"
            << "  Source address:         " << std::hex << tcp_packet->getIpSource() << std::dec
            << "\n  Destination address:    " << std::hex << tcp_packet->getIpDest() << std::dec
            << "\n  Source port:            " << tcp_packet->getTcpSource()
            << "\n  Destination port:       " << tcp_packet->getTcpDest()
            << std::endl;
    }
    else if (ip_packet) 
    {
        out << "IP packet received\n"
            << "  Source address:         " << std::hex << tcp_packet->getIpSource() << std::dec
            << "\n  Destination address:    " << std::hex << tcp_packet->getIpDest() << std::dec
            << std::endl;
    }
    else
    {
        out << "Packet received" << std::endl;
    }
    out << "  Protocol:               " << packet->getHwProtocol()
        << "\n  Hook:                   " << static_cast<unsigned>(packet->getNfHook())
        << "\n  Mark:                   " << packet->getNfMark()
        << "\n  Input device:           " << packet->getIndev()
        << "\n  Physical input device:  " << packet->getPhysIndev()
        << "\n  Output device:          " << packet->getOutdev()
        << "\n  Physical output device: " << packet->getPhysOutdev()
        << "\n  Timestamp:              " << packet->getTimestamp().tv_sec << '.' << packet->getTimestamp().tv_usec
        << std::endl;  

    /*size_t size;
    out << std::hex << std::setfill('0');
    for (int i=0; i<10; i++)
    {
        for (int j=0; j<8; j++)
            out << std::setw(2) << (unsigned)packet->getPacket(size)[8*i + j] << ' ';
        out << std::endl;
    }
    out << std::dec;*/
}

Listener::HostRecordBase::HostRecordBase(const NFQ::NfqUdpPacket* pkt)
: saddr(pkt->getIpSource()), daddr(pkt->getIpDest()), sport(pkt->getUdpSource()), dport(pkt->getUdpDest()), targetPort()
{}


Listener::HostRecordBase::HostRecordBase(const NFQ::NfqUdpPacket* pkt, boost::uint16_t target)
: saddr(pkt->getIpSource()), daddr(pkt->getIpDest()), sport(pkt->getUdpSource()), dport(pkt->getUdpDest()), targetPort(target)
{}


Listener::HostRecordBase::~HostRecordBase()
{}


boost::uint32_t 
Listener::HostRecordBase::getSrcAddr() const
{
    return saddr;
}


boost::uint16_t 
Listener::HostRecordBase::getSrcPort() const
{
    return sport;
}


boost::uint32_t
Listener::HostRecordBase::getDstAddr() const
{
    return daddr;
}


boost::uint16_t 
Listener::HostRecordBase::getDstPort() const
{
    return dport;
}


boost::uint16_t 
Listener::HostRecordBase::getTargetPort() const
{
    return targetPort;
}



/* 
Compute the SHA1 hash of a string
*/
void 
Listener::getHash(boost::uint8_t buf[BITS_TO_BYTES(HASH_BITS)], const std::string& str)
{
    gcry_md_hash_buffer(GCRY_MD_SHA1, buf, str.c_str(), str.length());    
}


/* Compute the SHA1 hash of a buffer
*/
void 
Listener::getHash(boost::uint8_t buf[BITS_TO_BYTES(HASH_BITS)], const boost::uint8_t* str, size_t strlen)
{
    gcry_md_hash_buffer(GCRY_MD_SHA1, buf, str, strlen);    
}


/* 
Build an struct PortMessage and encrypt it with AES-128-ECB
Throws: CryptoException - if there is an error in the crypto library
*/
void 
Listener::encryptPort(boost::uint8_t buf[BITS_TO_BYTES(CIPHER_BLOCK_BITS)], boost::uint16_t port, const boost::uint8_t pad[BITS_TO_BYTES(PORT_MESSAGE_PAD_BITS)], const std::string& keystr) THROW((CryptoException))
{
    boost::uint8_t hash[BITS_TO_BYTES(HASH_BITS)];
    struct PortMessage mess;
    gcry_error_t err;
    gcry_cipher_hd_t handle;

    assert(sizeof(PortMessage) == BITS_TO_BYTES(CIPHER_BLOCK_BITS));
    assert(HASH_BITS >= PORT_MESSAGE_HASH_BITS);
    assert(HASH_BITS >= CIPHER_KEY_BITS);

    // generate the plaintext message
    mess.port = htons(port);
    std::memcpy(&mess.pad, pad, BITS_TO_BYTES(PORT_MESSAGE_PAD_BITS));
    getHash(hash, reinterpret_cast<boost::uint8_t*>(&mess), offsetof(PortMessage, hash));
    std::memcpy(&mess.hash, hash, BITS_TO_BYTES(PORT_MESSAGE_HASH_BITS));

    // generate the encryption key
    getHash(hash, keystr);

    // encrypt the message
    err = gcry_cipher_open(&handle, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0);
    if (err)
        throw CryptoException(std::string("Error initializing cryptosystem: ") + gcry_strerror(err));
    err = gcry_cipher_setkey(handle, hash, BITS_TO_BYTES(CIPHER_KEY_BITS));
    if (err)
        throw CryptoException(std::string("Error setting key: ") + gcry_strerror(err));
    err = gcry_cipher_encrypt(handle, buf, BITS_TO_BYTES(CIPHER_BLOCK_BITS), &mess, BITS_TO_BYTES(CIPHER_BLOCK_BITS));
    if (err)
        throw CryptoException(std::string("Error encrypting: ") + gcry_strerror(err));
    gcry_cipher_close(handle);

    // clean up
    memset(&mess, 0, sizeof(mess));
    memset(hash, 0, sizeof(hash));
}    


/* 
Compute a MAC on a challenge
Throws: CryptoException - if there is an error in the crypto library
*/
void 
Listener::computeMAC(boost::array<boost::uint8_t, BITS_TO_BYTES(MAC_BITS)>& buf, const std::string& keystr, const boost::uint8_t* challenge, size_t clen, boost::uint32_t client_addr, boost::uint32_t serv_addr, const std::vector<boost::uint8_t>& request, bool ignore_client_addr)
{
    boost::uint8_t key[BITS_TO_BYTES(HASH_BITS)];
    boost::uint8_t* msg;
    size_t msglen;
    uint32_u caddr;
    uint32_u saddr;
    gcry_md_hd_t handle;
    gcry_error_t err;

    assert(challenge != NULL);

    // build the message
    msglen = clen + sizeof(boost::uint32_t) + sizeof(boost::uint32_t) + request.size();
    msg = new boost::uint8_t[msglen];
    std::memcpy(msg, challenge, clen);
    if (ignore_client_addr)
        caddr.u32 = 0;
    else
        caddr.u32 = htonl(client_addr);
    std::memcpy(msg+clen, caddr.u8, sizeof(boost::uint32_t));
    saddr.u32 = htonl(serv_addr);
    std::memcpy(msg+clen+sizeof(boost::uint32_t), saddr.u8, sizeof(boost::uint32_t));
    std::copy(request.begin(), request.end(), msg+clen+2*sizeof(boost::uint32_t));

    // generate the MAC key
    getHash(key, keystr);

    // calculate the MAC
    err = gcry_md_open(&handle, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
    if (err)
        throw CryptoException(std::string("Error initializing hash algorithm: ") + gcry_strerror(err));
    err = gcry_md_setkey(handle, key, BITS_TO_BYTES(HASH_BITS));
    if (err)
        throw CryptoException(std::string("Error setting HMAC key: ") + gcry_strerror(err));
    gcry_md_write(handle, msg, msglen);
    gcry_md_final(handle);
    std::memcpy(buf.c_array(), gcry_md_read(handle, 0), BITS_TO_BYTES(MAC_BITS));
    gcry_md_close(handle);

    delete[] msg;
    memset(key, 0, sizeof(key));
}

Listener::ListenerConstructor::ListenerConstructor()    
{
    // initialize gcrypt
    if (!gcry_check_version (GCRYPT_VERSION))
    {
        std::cerr << "version mismatch" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    if (geteuid() == 0) // use secure memory if we're running as root
        gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    else
        gcry_control(GCRYCTL_DISABLE_SECMEM, 0); 
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}





}
