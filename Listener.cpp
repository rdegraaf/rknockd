#include "Listener.hpp"

namespace Rknockd
{

Listener::Listener()
{}

Listener::~Listener()
{}

void 
Listener::printPacketInfo(const NFQ::NfqPacket* packet, std::ostream& out) const
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