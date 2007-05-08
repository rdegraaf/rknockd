#include <csignal>
#include <cassert>
#include <tr1/unordered_set>
#include <boost/cstdint.hpp>
#include <linux/netfilter_ipv4/ipt_REMAP.h>
#include "PKConfig.hpp"
#include "Listener.hpp"
#include "NFQ.hpp"
#include "PKListener.hpp"
#include "Signals.hpp"

#include <iostream>

namespace Rknockd
{

/*
Creates an AddressPair from a NfqUdpPacket 
*/
PKListener::AddressPair::AddressPair(const NFQ::NfqUdpPacket* pkt)
: saddr(pkt->getIpSource()), daddr(pkt->getIpDest()), sport(pkt->getUdpSource())
{}


/* 
Creates an AddressPair from a HostRecord
*/
PKListener::AddressPair::AddressPair(const Listener::HostRecordBase& host)
: saddr(host.getSrcAddr()), daddr(host.getDstAddr()), sport(host.getSrcPort())
{}


std::size_t 
PKListener::AddressPairHash::operator() (const AddressPair& a) const
{
    return uhash(a.saddr) ^ uhash(a.daddr) ^ shash(a.sport);
}

bool
PKListener::AddressPairEqual::operator() (const AddressPair& a, const AddressPair& b) const 
{
    return ((a.saddr==b.saddr) && (a.daddr==b.daddr) && (a.sport==b.sport));
}


PKListener::HostRecord::HostRecord(const NFQ::NfqUdpPacket* pkt)
: HostRecordBase(pkt), state(CLOSED), request(), response(), requests()
{}


PKListener::HostRecord::State
PKListener::HostRecord::getState() const
{
    return state;
}

void
PKListener::HostRecord::updateState(const NFQ::NfqUdpPacket* pkt, const PKConfig::RequestList& crequests)
{
    switch (state)
    {
      case CLOSED:
      case REQUEST:
        updateRequest(pkt, crequests);
        break;
      case CHALLENGE:
      case RESPONSE:
        updateResponse(pkt);
        break;
      case OPEN:
        break;
    }
}

void
PKListener::HostRecord::updateRequest(const NFQ::NfqUdpPacket* pkt, const PKConfig::RequestList& crequests)
{
    // update the list of currently matched requests
    for (RequestList::iterator i=requests.begin(); i!=requests.end(); )
    {
        PKRequestString& req = i->second;
        PKRequestString::iterator port = req.find(pkt->getUdpDest());

        if (port == req.end())
        {
            //  we no longer match this request
            i = requests.erase(i);
std::cout << "updateRequest(): deleting request" << std::endl;
        }
        else
        {
            // port number in set; remove it and check if we've matched
            req.erase(port);
            if (req.size() == 0)
            {
                request = i->first;
                state = CHALLENGE;
std::cout << "updateRequest(): state = " << state << std::endl;
                return;
            }
            ++i;
        }
    }
    
    // check if we're matching any new requests
    for (PKConfig::RequestList::const_iterator i=crequests.begin(); i!=crequests.end(); ++i)
    {
        const PKRequestString& req = i->getRequestString();
        if ((requests.find(&(*i)) == requests.end()) && (req.find(pkt->getUdpDest()) != req.end()))
        {
            RequestList::iterator iter = (requests.insert(std::make_pair(&(*i), req))).first;
            iter->second.erase(pkt->getUdpDest());
            state = REQUEST;
std::cout << "updateRequest(): adding request" << std::endl;
        }
    }
    
    // make sure that we're still matching something
    if (requests.size() == 0)
    {
        state = CLOSED;
std::cout << "updateResponse(): state = " << state << std::endl;
        return;
    }
std::cout << "updateResponse(): state = " << state << std::endl;
}


void
PKListener::HostRecord::updateResponse(const NFQ::NfqUdpPacket* pkt)
{
    PKResponse::iterator i = response.find(pkt->getUdpDest());
    if (i != response.end())
    {
        response.erase(i);
        if (response.size() == 0)
            state = OPEN;
        else
            state = RESPONSE;
    }
    else
    {
        state = CLOSED;
    }
std::cout << "updateResponse(): state = " << state << std::endl;

}

PKListener::PKListener(const PKConfig& c, bool verbose_logging) THROW((IOException, NFQ::NfqException))
: Listener(c, "/proc/"REMAP_PROC_FILE, verbose_logging), config(c), hostTable(), hostTableGC(hostTable, verbose_logging), portSet()
{
    // load all port numbers that we're interested in into portSet
    const std::vector<PKRequest>& requests = c.getRequests();
    for (std::vector<PKRequest>::const_iterator i=requests.begin(); i!=requests.end(); ++i)
    {
        for (PKRequestString::const_iterator j=i->getRequestString().begin(); j!=i->getRequestString().end(); ++j)
            portSet.insert(*j);
    }

    // set the SIGALRM handler
    LibWheel::SignalQueue::setHandler(SIGALRM, LibWheel::SignalQueue::HANDLE);
    LibWheel::SignalQueue::addHandler(SIGALRM, boost::ref(hostTableGC));
}

PKListener::~PKListener()
{
    LibWheel::SignalQueue::deleteHandler(SIGALRM, boost::ref(hostTableGC));
}

void
PKListener::handlePacket(const NFQ::NfqPacket* p) THROW((CryptoException))
{
    bool in_request = false;
    const NFQ::NfqUdpPacket* packet = dynamic_cast<const NFQ::NfqUdpPacket*>(p);
    assert(packet != NULL);
    
std::cout << "got port " << packet->getUdpDest() << std::endl;

    // check if this port number is used in a request
    if (portSet.find(packet->getUdpDest()) != portSet.end())
        in_request = true;
    
    try
    {
        HostRecord& rec = getRecord(packet, in_request);
        rec.updateState(packet, config.getRequests());

        try
        {
            switch (rec.getState())
            {
              case HostRecord::CLOSED:
                deleteRecord(rec);
                break;
              case HostRecord::REQUEST:
                break;
              case HostRecord::CHALLENGE:
                issueChallenge(rec);
                break;
              case HostRecord::RESPONSE:
                break;
              case HostRecord::OPEN:
                openPort(rec);
                break;
            }
        }
        catch (const IOException& e)
        {
            LibWheel::logmsg(LibWheel::logmsg_err, "I/O error: %s", e.what());
        }
        catch (const SocketException& e)
        {
            LibWheel::logmsg(LibWheel::logmsg_err, "Socket error: %s", e.what());
        }
    }
    catch (const BadRequestException& e)
    {
        // port number not in any request and host not in response state
std::cout << "Exception!" << std::endl;
    }
}

PKListener::HostRecord& 
PKListener::getRecord(const NFQ::NfqUdpPacket* pkt, bool in_request) THROW((BadRequestException))
{
    HostTable::iterator iter = hostTable.find(AddressPair(pkt));
    if (iter == hostTable.end())
    {
        if (in_request == false) // throw if there's no point creating a record
            throw BadRequestException();
        HostRecord rec(pkt);
        AddressPair addr(pkt);
        iter = (hostTable.insert(std::make_pair(addr, rec))).first;
        hostTableGC.schedule(addr, TIMEOUT_SECS, TIMEOUT_USECS);
std::cout << "getRecord(): creating record" << std::endl;
    }
    else if ((in_request == false) && (iter->second.getState() != HostRecord::CHALLENGE) && (iter->second.getState() != HostRecord::RESPONSE))
    {
        hostTable.erase(iter);
std::cout << "getRecord(): deleting record" << std::endl;
        throw BadRequestException();
    }
    return iter->second;
}

void 
PKListener::deleteRecord(const HostRecord& rec)
{
    hostTable.erase(AddressPair(rec));
}

void 
PKListener::issueChallenge(const HostRecord& rec) THROW((CryptoException, IOException, SocketException))
{
    // FIXME
}

void
PKListener::openPort(const HostRecord& rec) THROW((IOException))
{
    // FIXME
}

} // namespace Rknockd
