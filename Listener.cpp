#include <stdexcept>
#include <string>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include "Config.hpp"
#include "Listener.hpp"
#include "NFQ.hpp"
#include "Signals.hpp"
#include "Logmsg.hpp"
#include "common.h"

#include <iostream>
namespace Rknockd
{


IOException::IOException(const std::string& s) 
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



}
