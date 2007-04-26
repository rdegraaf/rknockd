/* 
Killing this program *can* result in dropped packets.  Since they're sent to 
netlink from the kernel before this program knows about them, there's no way to 
avoid it.  SIGINT triggers a synchronous exit after any current packet has been 
processed; use SIGINT to shut down this program.

Note: this program uses asynchronous signal handlers.  If threading is added,
then these will need to be converted to synchronous signal handlers.
*/

#define PROGNAME spaserver
#define VERSION 0.1

#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <sstream>
#include <map>
#include <vector>
#include <queue>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cstddef>
#include <cctype>
#include <tr1/unordered_map>
#include <boost/array.hpp>
#include <boost/cstdint.hpp>
#include <gcrypt.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <getopt.h>
#include <linux/netfilter_ipv4/ipt_REMAP.h>
#include "Config.hpp"
#include "NFQ.hpp"
#include "Listener.hpp"
#include "SpaConfig.hpp"
#include "Trie.hpp"
#include "Logmsg.hpp"
#include "Signals.hpp"
#include "spc_sanitize.h"
#include "time.h"


namespace Rknockd
{

std::string 
ipv4_to_string(boost::uint32_t a)
{
    union uint32_bytes
    {
        boost::uint32_t u32;
        boost::uint8_t u8[4];
    };
    std::ostringstream os;
    uint32_bytes addr;
    
    addr.u32 = htonl(a); // convert to big-endian
    os << static_cast<unsigned>(addr.u8[0]) << '.' 
       << static_cast<unsigned>(addr.u8[1]) << '.' 
       << static_cast<unsigned>(addr.u8[2]) << '.' 
       << static_cast<unsigned>(addr.u8[3]);
    return os.str();
}


class SpaListener : public Listener
{
  private:
    class BadRequestException : public std::runtime_error
    {
      public:
        BadRequestException(const std::string& s) : runtime_error(s) {}
    };
    
    class UnknownHostException : public std::runtime_error
    {
      public:
        UnknownHostException(const std::string& s) : runtime_error(s) {}
    };

    class CryptoException : public std::runtime_error
    {
      public:
        CryptoException(const std::string& s) : runtime_error(s) {}
    };

    class SocketException : public std::runtime_error
    {
      public:
        SocketException(const std::string& s) : runtime_error(s) {}
    };

    class IOException : public std::runtime_error
    {
      public:
        IOException(const std::string& s) : runtime_error(s) {}
    };

    class SpaListenerConstructor
    {
      public:
        SpaListenerConstructor();
    };
    
    class HostRecord
    {
        boost::uint32_t saddr;
        boost::uint32_t daddr;
        boost::uint16_t sport;
        boost::uint16_t dport;
        boost::uint16_t targetPort;
        const SpaRequest& request;
        boost::array<boost::uint8_t, MAC_BYTES> response;
      public:
        HostRecord(const NFQ::NfqUdpPacket* pkt, boost::uint16_t target, const SpaRequest& req, const uint8_t* challenge, size_t clen);
        ~HostRecord();
        boost::uint32_t getSrcAddr() const;
        boost::uint16_t getSrcPort() const;
        boost::uint32_t getDstAddr() const;
        boost::uint16_t getDstPort() const;
        boost::uint16_t getTargetPort() const;
        const SpaRequest& getRequest() const;
        const boost::array<boost::uint8_t, MAC_BYTES>& getResponse() const;
    };
    
    struct AddressPair
    {
        boost::uint32_t saddr;
        boost::uint32_t daddr;
        boost::uint16_t sport;
        boost::uint16_t dport;
        AddressPair(const NFQ::NfqUdpPacket* pkt);
        AddressPair(const SpaListener::HostRecord& host);
    };
    
    struct AddressPairHash
    {
        std::tr1::hash<boost::uint32_t> uhash;
        std::tr1::hash<boost::uint16_t> shash;
        std::size_t operator()(const Rknockd::SpaListener::AddressPair& a) const
        {
            return uhash(a.saddr) ^ uhash(a.daddr)^ shash(a.sport) ^ (shash(a.dport)<<16);
        }
    };
    struct AddressPairEqual
    {
        bool operator() (const AddressPair& a, const AddressPair& b) const 
        {
            return ((a.saddr==b.saddr) && (a.daddr==b.daddr) && (a.sport==b.sport) && (a.dport==b.dport));
        }
    };

    union uint32_u
    {
        boost::uint32_t u32;
        boost::uint8_t u8[sizeof(boost::uint32_t)];
    };

    typedef std::tr1::unordered_map<AddressPair, HostRecord, AddressPairHash, AddressPairEqual> HostTable;
    typedef LibWheel::Trie<boost::uint8_t, SpaRequest> RequestTable;

    class HostTableGC
    {
      public:
        HostTableGC(HostTable& t, bool verbose_logging);
        void schedule(AddressPair& addr, long secs, long usecs);
        void operator()();
      private:
        HostTable& table;
        std::queue<std::pair<struct timeval, AddressPair> > gcQueue;
        bool verbose;
    };
    
    const SpaConfig& config;
    HostTable hostTable;
    RequestTable requestTable;
    HostTableGC hostTableGC;

    static SpaListenerConstructor _classconstructor;
    
    HostRecord& getRecord(const NFQ::NfqUdpPacket* pkt) THROW((UnknownHostException));
    bool checkResponse(const NFQ::NfqUdpPacket* pkt, const HostRecord& host);
    void openPort(const HostRecord& host);
    void deleteState(const HostRecord& host);
    const SpaRequest& checkRequest(const NFQ::NfqUdpPacket* pkt) THROW((BadRequestException));
    void issueChallenge(const NFQ::NfqUdpPacket* pkt, const SpaRequest& req) THROW((CryptoException, IOException, SocketException));
    void handlePacket(const NFQ::NfqPacket* p);

    static void getHash(boost::uint8_t buf[HASH_BYTES], const std::string& str);
    static void getHash(boost::uint8_t buf[HASH_BYTES], const boost::uint8_t* str, size_t strlen);
    static void encryptPort(boost::uint8_t buf[CIPHER_BLOCK_BYTES], boost::uint16_t port, const boost::uint8_t pad[PORT_MESSAGE_PAD_BYTES], const std::string& keystr) THROW((CryptoException));
    static void computeMAC(boost::array<boost::uint8_t, MAC_BYTES>& buf, const std::string& keystr, const boost::uint8_t* challenge, size_t clen, boost::uint32_t client_addr, boost::uint32_t serv_addr, const std::vector<boost::uint8_t>& request, bool ignore_client_addr);

  public:
    SpaListener(const SpaConfig& c, bool verbose_logging);
    ~SpaListener();
    void operator()();
};


// static data members
SpaListener::SpaListenerConstructor SpaListener::_classconstructor;


SpaListener::SpaListenerConstructor::SpaListenerConstructor()    
{
    if (!gcry_check_version (GCRYPT_VERSION))
    {
        std::cerr << "version mismatch" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0); // FIXME if supporting secure memory
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}


SpaListener::HostRecord::HostRecord(const NFQ::NfqUdpPacket* pkt, boost::uint16_t target, const SpaRequest& req, const uint8_t* challenge, size_t clen)
: saddr(pkt->getIpSource()), daddr(pkt->getIpDest()), sport(pkt->getUdpSource()), dport(pkt->getUdpDest()), targetPort(target), request(req), response()
{
    SpaListener::computeMAC(response, req.getSecret(), challenge, clen, saddr, daddr, req.getRequestString(), req.getIgnoreClientAddr());
}


SpaListener::HostRecord::~HostRecord()
{}


boost::uint32_t 
SpaListener::HostRecord::getSrcAddr() const
{
    return saddr;
}


boost::uint16_t 
SpaListener::HostRecord::getSrcPort() const
{
    return sport;
}

boost::uint32_t
SpaListener::HostRecord::getDstAddr() const
{
    return daddr;
}

boost::uint16_t 
SpaListener::HostRecord::getDstPort() const
{
    return dport;
}


boost::uint16_t 
SpaListener::HostRecord::getTargetPort() const
{
    return targetPort;
}

const SpaRequest&
SpaListener::HostRecord::getRequest() const
{
    return request;
}

const boost::array<boost::uint8_t, MAC_BYTES>&
SpaListener::HostRecord::getResponse() const
{
    return response;
}


/* 
Creates an AddressPair from a NfqUdpPacket 
*/
SpaListener::AddressPair::AddressPair(const NFQ::NfqUdpPacket* pkt)
: saddr(pkt->getIpSource()), daddr(pkt->getIpDest()), sport(pkt->getUdpSource()), dport(pkt->getUdpDest())
{}


/* 
Creates an AddressPair from a HostRecord
*/
SpaListener::AddressPair::AddressPair(const SpaListener::HostRecord& host)
: saddr(host.getSrcAddr()), daddr(host.getDstAddr()), sport(host.getSrcPort()), dport(host.getDstPort())
{}


SpaListener::HostTableGC::HostTableGC(HostTable& table, bool verbose_logging)
: table(table), gcQueue(), verbose(verbose_logging)
{}

void 
SpaListener::HostTableGC::schedule(AddressPair& addr, long secs, long usecs)
{
    struct timeval time;
    struct itimerval itime;

    // calculate the GC execution time    
    gettimeofday(&time, NULL);
    time.tv_usec += usecs;
    time.tv_sec += secs;
    if (time.tv_usec >= 1000000)
    {
        time.tv_sec += (time.tv_usec / 1000000);
        time.tv_usec %= 1000000;
    }
    
    // schedule the GC
    // it's safe to schedule before pushing to the queue, because the timer
    // interrupt is handled synchronously
    if (gcQueue.size() == 0)
    {
        itime.it_interval.tv_sec = 0;
        itime.it_interval.tv_usec = 0;
        itime.it_value.tv_sec = secs;
        itime.it_value.tv_usec = usecs;
        setitimer(ITIMER_REAL, &itime, NULL);
    }
    gcQueue.push(std::make_pair(time, addr));
}

void
SpaListener::HostTableGC::operator()()
{
    struct timeval curtime;

    gettimeofday(&curtime, NULL);
    
    // delete old junk
    while (!gcQueue.empty() && (LibWheel::cmptime(&gcQueue.front().first, &curtime) < 0))
    {
        if (verbose && (table.find(gcQueue.front().second) != table.end()))
            LibWheel::logmsg(LibWheel::logmsg_info, "GC: deleting stale entry");
        table.erase(gcQueue.front().second);
        gcQueue.pop();
    }
    
    // schedule the next GC run
    if (!gcQueue.empty())
    {
        struct itimerval itime;
        itime.it_interval.tv_sec = 0;
        itime.it_interval.tv_usec = 0;
        LibWheel::subtime(&itime.it_value, &gcQueue.front().first, &curtime);
        setitimer(ITIMER_REAL, &itime, NULL);
    }
}


/* 
Looks up a host in the host hash table 
If an entry exists in the hash table matching *pkt, return it.  Otherwise, 
throw an UnknownHostException.
*/
SpaListener::HostRecord& 
SpaListener::getRecord(const NFQ::NfqUdpPacket* pkt) THROW((UnknownHostException))
{
    HostTable::iterator iter = hostTable.find(AddressPair(pkt));
    if (iter == hostTable.end())
        throw UnknownHostException("Host not found");
    return iter->second;
}


/* 
Checks if a response is valid
If the response in *pkt is the one expected for host, return true.  Otherwise,
return false.
*/
bool 
SpaListener::checkResponse(const NFQ::NfqUdpPacket* pkt, const HostRecord& host)
{
    size_t payload_size;
    const boost::uint8_t* contents = pkt->getUdpPayload(payload_size);

    // make sure that we have a valid message
    if (payload_size != MAC_BYTES)
        return false;

    // check if we received the expected response
    if (std::equal(host.getResponse().begin(), host.getResponse().end(), contents))
        return true;
    else
        return false;
}


/* 
Open a port to a source host after successful authentication
Sends a message to ipt_REMAP asking it to redirect the next connection to 
the random target port to the requested destination port
*/
void 
SpaListener::openPort(const HostRecord& host)
{
    struct ipt_remap remap;
    int fd;
    int ret;
    const SpaRequest& req = host.getRequest();

    LibWheel::logmsg(LibWheel::logmsg_info, "Forwarding %s:%hu/%s to %s:%hu", 
        ipv4_to_string(host.getSrcAddr()).c_str(), host.getTargetPort(), 
        req.getProtocol().getName().c_str(), 
        ipv4_to_string(host.getDstAddr()).c_str(), req.getPort());
    
    // build a remap rule
    memset(&remap, 0, sizeof(remap));
    remap.src_addr = htonl(host.getSrcAddr());
    if (req.getAddr() != 0)
        remap.dst_addr = htonl(req.getAddr());
    else
        remap.dst_addr = htonl(host.getDstAddr());
    remap.remap_addr = htonl(0);
    remap.dst_port = htons(host.getTargetPort());
    remap.remap_port = htons(req.getPort());
    remap.proto = req.getProtocol().getNumber();
    remap.ttl = htons(req.getTTL());

    // write the remap rule to the kernel driver
    fd = open("/proc/"REMAP_PROC_FILE, O_WRONLY);
    if (fd == -1)
    {
        LibWheel::logmsg(LibWheel::logmsg_err, "Error opening /proc/"REMAP_PROC_FILE": %s", strerror(errno));
        return;
    }
    ret = write(fd, &remap, sizeof(remap));
    if (ret == -1)
        LibWheel::logmsg(LibWheel::logmsg_err, "Error writing to /proc/"REMAP_PROC_FILE": %s", strerror(errno));
    else if (ret != sizeof(remap))
        LibWheel::logmsg(LibWheel::logmsg_err, "Error writing to /proc/"REMAP_PROC_FILE": message truncated");
    ret = close(fd);
    if (ret == -1)
        LibWheel::logmsg(LibWheel::logmsg_err, "Error closing /proc/"REMAP_PROC_FILE": %s", strerror(errno));
}


/* 
Remove an entry from the host hash table
*/
void 
SpaListener::deleteState(const HostRecord& host)
{
    hostTable.erase(AddressPair(host));
}


/* 
Checks if a packet contains a valid request string
If *pkt contains a valid request message, return a reference to the 
corresponding SpaRequest object.  Otherwise, throw a BadRequestException.
*/
const SpaRequest& 
SpaListener::checkRequest(const NFQ::NfqUdpPacket* pkt) THROW((BadRequestException))
{
    assert(pkt != NULL);
    size_t payload_size;
    const SpaRequestHeader* hdr = reinterpret_cast<const SpaRequestHeader*>(pkt->getUdpPayload(payload_size));
    const boost::uint8_t* contents = pkt->getUdpPayload(payload_size) + sizeof(SpaRequestHeader);
    const SpaRequest* request;
    boost::uint16_t request_bytes = ntohs(hdr->requestBytes);

    // make sure we have a valid message
    if (payload_size < sizeof(SpaRequestHeader))
        throw BadRequestException("Message too small");
    else if ((request_bytes < MIN_REQUEST_BYTES) || (request_bytes > MAX_REQUEST_BYTES))
        throw BadRequestException("Invalid request size");
    else if (payload_size > sizeof(SpaRequestHeader)+request_bytes)
        throw BadRequestException("Message too large");
    else if (payload_size < sizeof(SpaRequestHeader)+request_bytes)
        throw BadRequestException("Message truncated");

    // look up the request
    request = requestTable.search(contents, request_bytes);
    if (request == NULL)
        throw BadRequestException("Unrecognized request");
    else
    {
        if (verbose)
            LibWheel::logmsg(LibWheel::logmsg_info, "Good request received from %s:%hu", ipv4_to_string(pkt->getIpSource()).c_str(), pkt->getUdpSource());
        return *request;
    }
}


/* 
Sends a challenge message to a client
Generate a random challenge and target port, build a challenge message, send it
to the source of *pkt, and add an entry for the client to the hosts hash table.
Throws: SocketException - error sending challenge message
        IOException - error reading random data
*/
void 
SpaListener::issueChallenge(const NFQ::NfqUdpPacket* pkt, const SpaRequest& req) THROW((CryptoException, IOException, SocketException))
{
    unsigned challenge_len = sizeof(SpaChallengeHeader) + config.getChallengeBytes();
    boost::uint8_t* challenge;
    SpaChallengeHeader* header;
    unsigned rand_len = config.getChallengeBytes() + PORT_MESSAGE_PAD_BYTES + 2;
    boost::uint8_t* rand_bytes;
    boost::uint16_t dport;
    int ret;

    // read some random data;
    rand_bytes = new boost::uint8_t[rand_len];
    ret = read(config.getRandomFD(), rand_bytes, rand_len);
    if (ret < static_cast<int>(rand_len)) // error reading random bytes
        throw IOException(std::string("Error reading random data: ") + std::strerror(errno));

    // create a challenge
    challenge = new boost::uint8_t[challenge_len];
    header = reinterpret_cast<SpaChallengeHeader*>(challenge);
    std::memset(challenge, 0, challenge_len);
    std::memcpy(&challenge[sizeof(SpaChallengeHeader)], rand_bytes, config.getChallengeBytes());
    header->nonceBytes = config.getChallengeBytes();

    // create a port message
    dport = *(reinterpret_cast<boost::uint16_t*>(&rand_bytes[rand_len-2]));
    boost::uint8_t* pad = &rand_bytes[config.getChallengeBytes()];
    encryptPort(header->portMessage, dport, pad, req.getSecret());

    // send the challenge
    // it's not a race condition to send before creating the host record, 
    // because responses are also handled in this thread
    int sock_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock_fd == -1)
        throw SocketException(std::string("Error creating socket: ") + std::strerror(errno));
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(pkt->getUdpDest());
    addr.sin_addr.s_addr = htonl(pkt->getIpDest());
    ret = bind(sock_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    if (ret == -1)
        throw SocketException(std::string("Error binding socket: ") + std::strerror(errno));
    addr.sin_port = htons(pkt->getUdpSource());
    addr.sin_addr.s_addr = htonl(pkt->getIpSource());
    ret = sendto(sock_fd, challenge, challenge_len, 0, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    if (ret  == -1)
        throw IOException(std::string("Error sending challenge: ") + std::strerror(errno));
    else if (ret != static_cast<int>(challenge_len))
        throw IOException(std::string("Error sending challenge: message truncated"));
    ret = close(sock_fd);
    if (ret == -1)
        throw SocketException(std::string("Error closing socket: ") + std::strerror(errno));

    // create a record for this host
    HostRecord hrec(pkt, dport, req, challenge+sizeof(SpaChallengeHeader), config.getChallengeBytes());
    AddressPair haddr(hrec);
    hostTable.insert(std::make_pair(haddr, hrec));
    hostTableGC.schedule(haddr, TIMEOUT_SECS, TIMEOUT_USECS);

    delete[] challenge;
    delete[] rand_bytes;

    if (verbose)
        LibWheel::logmsg(LibWheel::logmsg_info, "Sent challenge, dport=%hu to %s:%hu", dport, ipv4_to_string(pkt->getIpSource()).c_str(), pkt->getUdpSource());
}


/* 
Handle a packet received from Netlink
*/
void 
SpaListener::handlePacket(const NFQ::NfqPacket* p)
{
    const NFQ::NfqUdpPacket* packet = dynamic_cast<const NFQ::NfqUdpPacket*>(p);
    assert(packet != NULL);

    // FIXME: catch all exceptions

    try
    {
        HostRecord& host = getRecord(packet);

        // we have already issued a challenge to this host;
        // check if this is a valid response
        if (checkResponse(packet, host))
        {
            openPort(host);
        }
        else
        {
            LibWheel::logmsg(LibWheel::logmsg_err, "Incorrect response received from %s:%hu", ipv4_to_string(packet->getIpSource()).c_str(), packet->getUdpSource());
        }
        deleteState(host);
    }
    catch (UnknownHostException& e)
    {
        // check if this packet contains a valid request
        try
        {
            const SpaRequest& req = checkRequest(packet);

            // we got a valid request; issue a challenge
            issueChallenge(packet, req);
        }
        catch (BadRequestException& e)
        {
            LibWheel::logmsg(LibWheel::logmsg_err, "Incorrect request received from %s:%hu: %s", ipv4_to_string(packet->getIpSource()).c_str(), packet->getUdpSource(), e.what());
        }
    }
}


/* 
Compute the SHA1 hash of a string
*/
void 
SpaListener::getHash(boost::uint8_t buf[HASH_BYTES], const std::string& str)
{
    gcry_md_hash_buffer(GCRY_MD_SHA1, buf, str.c_str(), str.length());    
}


/* Compute the SHA1 hash of a buffer
*/
void 
SpaListener::getHash(boost::uint8_t buf[HASH_BYTES], const boost::uint8_t* str, size_t strlen)
{
    gcry_md_hash_buffer(GCRY_MD_SHA1, buf, str, strlen);    
}

// FIXME:  use boost::array where possible

/* 
Build an struct PortMessage and encrypt it with AES-128-ECB
Throws: CryptoException - if there is an error in the crypto library
*/
void 
SpaListener::encryptPort(boost::uint8_t buf[CIPHER_BLOCK_BYTES], boost::uint16_t port, const boost::uint8_t pad[PORT_MESSAGE_PAD_BYTES], const std::string& keystr) THROW((CryptoException))
{
    boost::uint8_t hash[HASH_BYTES];
    struct PortMessage mess;
    gcry_error_t err;
    gcry_cipher_hd_t handle;

    assert(sizeof(PortMessage) == CIPHER_BLOCK_BYTES);
    assert(HASH_BYTES >= PORT_MESSAGE_HASH_BYTES);
    assert(HASH_BYTES >= CIPHER_KEY_BYTES);

    // generate the plaintext message
    mess.port = htons(port);
    std::memcpy(&mess.pad, pad, PORT_MESSAGE_PAD_BYTES);
    getHash(hash, reinterpret_cast<boost::uint8_t*>(&mess), offsetof(PortMessage, hash));
    std::memcpy(&mess.hash, hash, PORT_MESSAGE_HASH_BYTES);

    // generate the encryption key
    getHash(hash, keystr);

    // encrypt the message
    err = gcry_cipher_open(&handle, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0);
    if (err)
        throw CryptoException(std::string("Error initializing cryptosystem: ") + gcry_strerror(err));
    err = gcry_cipher_setkey(handle, hash, CIPHER_KEY_BYTES);
    if (err)
        throw CryptoException(std::string("Error setting key: ") + gcry_strerror(err));
    err = gcry_cipher_encrypt(handle, buf, CIPHER_BLOCK_BYTES, &mess, CIPHER_BLOCK_BYTES);
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
SpaListener::computeMAC(boost::array<boost::uint8_t, MAC_BYTES>& buf, const std::string& keystr, const boost::uint8_t* challenge, size_t clen, boost::uint32_t client_addr, boost::uint32_t serv_addr, const std::vector<boost::uint8_t>& request, bool ignore_client_addr)
{
    boost::uint8_t key[HASH_BYTES];
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
    err = gcry_md_setkey(handle, key, HASH_BYTES);
    if (err)
        throw CryptoException(std::string("Error setting HMAC key: ") + gcry_strerror(err));
    gcry_md_write(handle, msg, msglen);
    gcry_md_final(handle);
    std::memcpy(buf.c_array(), gcry_md_read(handle, 0), MAC_BYTES);
    gcry_md_close(handle);

    delete[] msg;
    memset(key, 0, sizeof(key));
}


/* 
Constructor for SpaListener
Initialize, program the request matcher trie with all request strings
*/
SpaListener::SpaListener(const SpaConfig& c, bool verbose_logging)
: Listener(verbose_logging), config(c), hostTable(), requestTable(), hostTableGC(hostTable, verbose_logging)
{
    // program the requests trie with all request strings
    const std::vector<SpaRequest>& requests = c.getRequests();

    for (std::vector<SpaRequest>::const_iterator i = requests.begin(); i != requests.end(); ++i)
    {
        requestTable.addString(i->getRequestString(), *i);
    }
    
    // set the SIGALARM handler
    LibWheel::SignalQueue::setHandler(SIGALRM, boost::ref(hostTableGC));
}


/* Destructor for SpaListener
*/
SpaListener::~SpaListener()
{
    LibWheel::SignalQueue::setHandler(SIGALRM, LibWheel::SignalQueue::DEFAULT);
}


/* 
Entry point for SpaListener
Designed this way for compatibility with boost::thread
*/
void 
SpaListener::operator() ()
{
    try
    {
        NFQ::NfqSocket sock(config.getNfQueueNum());
        sock.setCopyMode(NFQ::NfqSocket::PACKET);

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
                catch (NFQ::NfqException& e)
                {
                    LibWheel::logmsg(LibWheel::logmsg_err, "Error processing packet: %s", e.what());
                }
            }
        }
        catch (LibWheel::Interrupt& e) // thrown when SIGINT is caught
        {
            LibWheel::logmsg(LibWheel::logmsg_notice, "SIGINT caught; exiting normally\n");
        }
        try
        {
            sock.close();
        }
        catch (NFQ::NfqException& e)
        {
            LibWheel::logmsg(LibWheel::logmsg_err, "Error disconnecting from NFQUEUE: %s", e.what());
        }
    }
    catch (NFQ::NfqException& e)
    {
        LibWheel::logmsg(LibWheel::logmsg_err, "Error connecting to NFQUEUE: %s", e.what());
    }
}


} // namespace Rknockd


/* 
Prints version info
*/
void print_version()
{
    std::cout << QUOTE(PROGNAME) << ": " <<  QUOTE(VERSION)
              << "\nCopyright (c) Rennie deGraaf, 2007.  All rights reserved."
              << std::endl;
}


/*
Print a help message
*/
void print_help()
{
    std::cout << "Usage: "QUOTE(PROGNAME)" [-c <config file>] [-D] [-V] [-h] [-v]\n"
              << "where -c <config file> - use the specified configuration file\n"
              << "      -D - run the program as a daemon\n"
              << "      -V - enable verbose logging\n"
              << "      -h - print this message\n"
              << "      -v - print version information" << std::endl;
    return;
}


void parse_args(int argc, char** argv, std::string& config_file, bool& daemon, bool& verbose)
{
    char* short_options = "c:DhvV";
    static struct option long_options[] = {
        {"config", 1, 0, 'c'},
        {"daemon", 0, 0, 'D'},
        {"verbose", 0, 0, 'V'},
        {"help", 0, 0, 'h'},
        {"version", 0, 0, 'v'},
        {0, 0, 0, 0}
    };
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
    {
        switch (c)
        {
            case 'c':
                config_file = optarg;
                break;
            case 'D':
                daemon = true;
                break;
            case 'V':
                verbose = true;
                break;
            case 'h':
                print_version();
                print_help();
                std::exit(EXIT_SUCCESS);
            case 'v':
                print_version();
                std::exit(EXIT_SUCCESS);
            case '?':
                if (isprint(optopt))
                    std::cerr << "Unrecognized option -" << static_cast<char>(optopt) << std::endl;
                else
                    std::cerr << "Unrecognized option character 0x" << std::hex << optopt << std::dec << std::endl;
                std::exit(EXIT_FAILURE);
            case ':':
                std::cerr << "File name expected after option -c" << std::endl;
                std::exit(EXIT_FAILURE);
            case '0':
            default:
                std::cerr << "getopt() returned an unexpected value" << std::endl;
                std::exit(EXIT_FAILURE);
        }
    }
    
    if (optind < argc)
    {
        std::cerr << "Unrecognized garbage on the command line: ";
        while (optind < argc)
            std::cerr << argv[optind++] << ' ';
        std::cerr << std::endl;
        std::exit(EXIT_FAILURE);
    }
}

void sigint_handler()
{
    throw LibWheel::Interrupt();
}


int
main(int argc, char** argv)
{
    std::string config_file = "spaconfig.xml";
    bool make_daemon = false;
    bool verbose = false;
    
    // initialize the logmsg facility (spc_sanitize_* needs it)
    LibWheel::logmsg.open(LibWheel::logmsg_stderr, 0, argv[0]);
    
    // sanitize the system
    spc_sanitize_environment(0, NULL);
    spc_sanitize_files();
    
    // parse command-line arguments
    parse_args(argc, argv, config_file, make_daemon, verbose);
    
#ifdef DEBUG
    verbose = true;
    make_daemon = false;
#endif

    try
    {
        // load configuration
        Rknockd::SpaConfig config(config_file);
/*#ifdef DEBUG
        config.printConfig(std::cout);
#endif*/

        LibWheel::SignalQueue::setHandler(SIGINT, sigint_handler);
        
        // we've finished initializing; time to summon Beelzebub
        if (make_daemon)
        {
            // Ia Ia Cthulhu Fhtagn!
            daemon(0, 0);

            // stderr is closed; switch to syslog
            LibWheel::logmsg.open(LibWheel::logmsg_syslog, 0, argv[0]);
        }

        // run the listener
        Rknockd::SpaListener listener(config, verbose);
        listener();
    }
    catch (const Rknockd::ConfigException& e)
    {
        std::cerr << "Error loading configuration file " << config_file << ": " << e.what() << std::endl;;
        std::exit(EXIT_FAILURE);
    }
    
    LibWheel::logmsg.close();
    return EXIT_SUCCESS;
}

