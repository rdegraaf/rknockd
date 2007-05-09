#include <iterator>
#include <csignal>
#include <cassert>
#include <tr1/unordered_set>
#include <boost/cstdint.hpp>
#include <boost/static_assert.hpp>
#include <linux/netfilter_ipv4/ipt_REMAP.h>
#include "PKConfig.hpp"
#include "Listener.hpp"
#include "NFQ.hpp"
#include "PKListener.hpp"
#include "Signals.hpp"

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

KnockSequence& 
PKListener::HostRecord::getResponse()
{
    return response;
}


const PKRequest&
PKListener::HostRecord::getRequest() const
{
    assert(request != NULL);
    return *request;
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
        KnockSequence& req = i->second;
        KnockSequence::iterator port = req.find(pkt->getUdpDest());

        if (port == req.end())
        {
            //  we no longer match this request
            i = requests.erase(i);
        }
        else
        {
            // port number in set; remove it and check if we've matched
            req.erase(port);
            if (req.size() == 0)
            {
                request = i->first;
                state = CHALLENGE;
                return;
            }
            ++i;
        }
    }
    
    // check if we're matching any new requests
    for (PKConfig::RequestList::const_iterator i=crequests.begin(); i!=crequests.end(); ++i)
    {
        const KnockSequence& req = i->getRequestString();
        if ((requests.find(&(*i)) == requests.end()) && (req.find(pkt->getUdpDest()) != req.end()))
        {
            RequestList::iterator iter = (requests.insert(std::make_pair(&(*i), req))).first;
            iter->second.erase(pkt->getUdpDest());
            state = REQUEST;
        }
    }
    
    // make sure that we're still matching something
    if (requests.size() == 0)
    {
        state = CLOSED;
        return;
    }
}


void
PKListener::HostRecord::updateResponse(const NFQ::NfqUdpPacket* pkt)
{
    KnockSequence::iterator i = response.find(pkt->getUdpDest());
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

}

PKListener::PKListener(const PKConfig& c, bool verbose_logging) THROW((IOException, NFQ::NfqException))
: Listener(c, "/proc/"REMAP_PROC_FILE, verbose_logging), config(c), hostTable(), hostTableGC(hostTable, verbose_logging), portSet()
{
    // load all port numbers that we're interested in into portSet
    const std::vector<PKRequest>& requests = c.getRequests();
    for (std::vector<PKRequest>::const_iterator i=requests.begin(); i!=requests.end(); ++i)
    {
        for (KnockSequence::const_iterator j=i->getRequestString().begin(); j!=i->getRequestString().end(); ++j)
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
                issueChallenge(rec, packet);
                break;
              case HostRecord::RESPONSE:
                break;
              case HostRecord::OPEN:
                openPort(rec, rec.getRequest());
                deleteRecord(rec);
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
    }
    else if ((in_request == false) && (iter->second.getState() != HostRecord::CHALLENGE) && (iter->second.getState() != HostRecord::RESPONSE))
    {
        hostTable.erase(iter);
        throw BadRequestException();
    }
    return iter->second;
}

void 
PKListener::deleteRecord(const HostRecord& rec)
{
    hostTable.erase(AddressPair(rec));
}


template <typename InIt, typename Out>
void
getBytes(const InIt& begin, const InIt& end, const typename std::back_insert_iterator<Out>& o)
{
    // FIXME: what's the proper way to do this?
    BOOST_STATIC_ASSERT(sizeof(typename Out::value_type) == sizeof(boost::uint8_t));
    BOOST_STATIC_ASSERT(sizeof(typename InIt::value_type) == sizeof(boost::uint16_t));
    
    typename std::back_insert_iterator<Out> out = o;
    union
    {
        boost::uint16_t u16;
        boost::uint8_t u8[2];
    } elmt;
    
    for (InIt i=begin; i!=end; ++i)
    {
        elmt.u16 = htons(*i);
        out = std::copy(elmt.u8, elmt.u8+2, out);
    }
}


void 
PKListener::issueChallenge(HostRecord& rec, const NFQ::NfqUdpPacket* pkt) THROW((CryptoException, IOException, SocketException))
{
    //LibWheel::auto_array<boost::uint8_t> challenge;
    size_t challenge_len;
    //LibWheel::auto_array<boost::uint8_t> resp;
    size_t resp_len;
    boost::uint16_t dport;
    boost::array<boost::uint8_t, BITS_TO_BYTES(MAC_BITS)> mac;

    if (verbose)
        LibWheel::logmsg(LibWheel::logmsg_info, "Good request received from %s:%hu", ipv4_to_string(pkt->getIpSource()).c_str(), pkt->getUdpSource());

    LibWheel::auto_array<boost::uint8_t> challenge(generateChallenge(config, rec.getRequest(), challenge_len, dport));
    
    sendMessage(pkt->getIpSource(), pkt->getUdpSource(), pkt->getUdpDest(), challenge.get(), challenge_len);

    std::vector<boost::uint8_t> vec;
    getBytes(rec.getRequest().getRequestString().begin(), rec.getRequest().getRequestString().end(), std::back_inserter(vec));
    LibWheel::auto_array<boost::uint8_t> resp(generateResponse(rec, challenge.get()+sizeof(ChallengeHeader), challenge_len-sizeof(ChallengeHeader), rec.getRequest().getIgnoreClientAddr(), vec, resp_len));
    computeMAC(mac, rec.getRequest().getSecret(), resp.get(), resp_len);
    KnockSequenceParser::generateKnockSequence(rec.getResponse(), mac, config.getBasePort(), config.getBitsPerKnock());
    rec.setTargetPort(dport);

    if (verbose)
        LibWheel::logmsg(LibWheel::logmsg_info, "Sent challenge, dport=%hu to %s:%hu", dport, ipv4_to_string(pkt->getIpSource()).c_str(), pkt->getUdpSource());
}

} // namespace Rknockd
