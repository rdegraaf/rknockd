#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <sstream>
#include <map>
#include <vector>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cstddef>
#include <tr1/unordered_map>
#include <boost/array.hpp>
#include <boost/cstdint.hpp>
#include <boost/thread/thread.hpp>
#include <gcrypt.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "Config.hpp"
#include "NFQ.hpp"
#include "Listener.hpp"
#include "SpaConfig.hpp"
#include "Trie.hpp"
#include <linux/netfilter_ipv4/ipt_REMAP.h>

// typedef for <ip address, udp port> pairs
namespace Rknockd
{
    /*struct SourceAddress
    {
        boost::uint32_t addr;
        boost::uint16_t port;
        SourceAddress(boost::uint32_t a, boost::uint16_t p) : addr(a), port(p){}
    };*/
    typedef std::pair<boost::uint32_t, boost::uint16_t> SourceAddress;
}


// hash function for <ip address, udp port> pairs
namespace std
{
    namespace tr1
    {
        template<> struct hash<Rknockd::SourceAddress> 
        {
            std::size_t operator()(const Rknockd::SourceAddress& p) const
            {
                return uhash(p.first) + shash(p.second);
            }
            hash<boost::uint32_t> uhash;
            hash<boost::uint16_t> shash;
        };
    }
}


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

    class HostRecord
    {
        boost::uint32_t saddr;
        boost::uint16_t sport;
        boost::uint16_t dport;
        const Protocol& protocol;
        boost::array<boost::uint8_t, MAC_BYTES> response;
      public:
        HostRecord(boost::uint32_t sa, boost::uint16_t sp, boost::uint32_t da, boost::uint16_t dp, const SpaRequest& req, const uint8_t* challenge, size_t clen);
        ~HostRecord();
        boost::uint32_t getAddr() const;
        boost::uint16_t getPort() const;
        boost::uint16_t getDestPort() const;
        const Protocol& getProtocol() const;
        const boost::array<boost::uint8_t, MAC_BYTES>& getResponse() const;
    };
    
    union uint32_u
    {
        boost::uint32_t u32;
        boost::uint8_t u8[sizeof(boost::uint32_t)];
    };

    class SpaListenerConstructor
    {
      public:
        SpaListenerConstructor();
    };
    
    typedef std::tr1::unordered_map<SourceAddress, HostRecord> HostTable;
    typedef Libwheel::Trie<boost::uint8_t, SpaRequest> RequestTable;

    const SpaConfig& config;
    HostTable hostTable;
    RequestTable requestTable;

    static SpaListenerConstructor _classconstructor;
    
    HostRecord& getRecord(boost::uint32_t saddr, boost::uint16_t sport) THROW((UnknownHostException));
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
    SpaListener(const SpaConfig& c);
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


SpaListener::HostRecord::HostRecord(boost::uint32_t sa, boost::uint16_t sp, boost::uint32_t da, boost::uint16_t dp, const SpaRequest& req, const uint8_t* challenge, size_t clen)
: saddr(sa), sport(sp), dport(dp), protocol(req.getProtocol()), response()
{
    SpaListener::computeMAC(response, req.getSecret(), challenge, clen, sa, da, req.getRequestString(), req.getIgnoreClientAddr());
}


SpaListener::HostRecord::~HostRecord()
{}


boost::uint32_t 
SpaListener::HostRecord::getAddr() const
{
    return saddr;
}


boost::uint16_t 
SpaListener::HostRecord::getPort() const
{
    return sport;
}


boost::uint16_t 
SpaListener::HostRecord::getDestPort() const
{
    return dport;
}

const Protocol&
SpaListener::HostRecord::getProtocol() const
{
    return protocol;
}

const boost::array<boost::uint8_t, MAC_BYTES>&
SpaListener::HostRecord::getResponse() const
{
    return response;
}


SpaListener::HostRecord& 
SpaListener::getRecord(boost::uint32_t saddr, boost::uint16_t sport) THROW((UnknownHostException))
{
    HostTable::iterator iter = hostTable.find(SourceAddress(saddr, sport));
    if (iter == hostTable.end())
        throw UnknownHostException("Host not found");
    return iter->second;
}


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


void 
SpaListener::openPort(const HostRecord& host)
{
    // FIXME: stub
    std::cout << "Opening port " << host.getDestPort() << '/' << host.getProtocol() << " to " << ipv4_to_string(host.getAddr()) << std::endl;
}


void 
SpaListener::deleteState(const HostRecord& host)
{
    hostTable.erase(SourceAddress(host.getAddr(), host.getPort()));
}


const SpaRequest& 
SpaListener::checkRequest(const NFQ::NfqUdpPacket* pkt) THROW((BadRequestException))
{
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
#ifdef DEBUG
    std::cerr << "Good request received from " << ipv4_to_string(pkt->getIpSource()) << ':' << pkt->getUdpSource() << std::endl;
#endif
        return *request;
    }
}
    
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
    HostRecord hrec(pkt->getIpSource(), pkt->getUdpSource(), pkt->getIpDest(), dport, req, challenge+sizeof(SpaChallengeHeader), config.getChallengeBytes());
    hostTable.insert(std::pair<SourceAddress, HostRecord>(SourceAddress(pkt->getIpSource(), pkt->getUdpSource()), hrec));

    delete[] challenge;
    delete[] rand_bytes;
#ifdef DEBUG
    std::cerr << "Sent challenge, dport=" << dport << " to " << ipv4_to_string(pkt->getIpSource()) << ':' << pkt->getUdpSource() << std::endl;
#endif
}

void 
SpaListener::handlePacket(const NFQ::NfqPacket* p)
{
    const NFQ::NfqUdpPacket* packet = dynamic_cast<const NFQ::NfqUdpPacket*>(p);
    assert(packet != NULL);

    // FIXME: catch all exceptions

    try
    {
        HostRecord& host = getRecord(packet->getIpSource(), packet->getUdpSource());

        // we have already issued a challenge to this host;
        // check if this is a valid response
        if (checkResponse(packet, host))
        {
            openPort(host);
        }
        else
        {
            std::cout << "Incorrect response received from " << ipv4_to_string(packet->getIpSource()) << ':' << packet->getUdpSource() << std::endl;
            deleteState(host);
        }
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
            std::cout << "Incorrect request received from " << ipv4_to_string(packet->getIpSource()) << ':' << packet->getUdpSource() << ": " << e.what() << std::endl;
        }
    }
}


void 
SpaListener::getHash(boost::uint8_t buf[HASH_BYTES], const std::string& str)
{
    gcry_md_hash_buffer(GCRY_MD_SHA1, buf, str.c_str(), str.length());    
}


void 
SpaListener::getHash(boost::uint8_t buf[HASH_BYTES], const boost::uint8_t* str, size_t strlen)
{
    gcry_md_hash_buffer(GCRY_MD_SHA1, buf, str, strlen);    
}


void 
SpaListener::encryptPort(boost::uint8_t buf[CIPHER_BLOCK_BYTES], boost::uint16_t port, const boost::uint8_t pad[PORT_MESSAGE_PAD_BYTES], const std::string& keystr) THROW((CryptoException))
{
    boost::uint8_t hash[HASH_BYTES];
    PortMessage mess;
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


SpaListener::SpaListener(const SpaConfig& c)
: config(c), hostTable(), requestTable()
{
    // program the requests trie with all request strings
    const std::vector<SpaRequest>& requests = c.getRequests();

    for (std::vector<SpaRequest>::const_iterator i = requests.begin(); i != requests.end(); ++i)
    {
        requestTable.addString(i->getRequestString(), *i);
    }
}


SpaListener::~SpaListener()
{}


void 
SpaListener::operator() ()
{
    try
    {
        NFQ::NfqSocket sock(config.getNfQueueNum());
        sock.setCopyMode(NFQ::NfqSocket::PACKET);

        // loop forever, processing packets
        // FIXME: need to come up with some sort of exit strategy
        while (1)
        {
            try
            {
                sock.waitForPacket();
                NFQ::NfqPacket* packet = sock.recvPacket(true);

                // set the verdict first, so that we don't keep the kernel waiting
                packet->setVerdict(NFQ::NfqPacket::DROP);
                //packet->setNfMark(1);
                sock.sendResponse(packet);

                printPacketInfo(packet, std::cout);

                // handle the packet
                handlePacket(packet);

                delete packet;
            }
            catch (NFQ::NfqException& e)
            {
                std::cout << "Error processing packet: " << e.what() << std::endl;
            }
        }

        try
        {
            sock.close();
        }
        catch (NFQ::NfqException& e)
        {
            std::cout << "Error disconnecting from NFQUEUE: " << e.what() << std::endl;
        }
    }
    catch (NFQ::NfqException& e)
    {
        std::cout << "Error connecting to NFQUEUE: " << e.what() << std::endl;
    }
}


} // namespace Rknockd




int
main(const int argc, const char** argv)
{
    std::string config_file = "spaconfig.xml";
    
    try
    {
        // load configuration
        Rknockd::SpaConfig config(config_file);
#ifdef DEBUG
        config.printConfig(std::cout);
#endif
        
        try
        {
            // start up threads
            Rknockd::SpaListener k(config);
            boost::thread listener(k);

            // clean up
            listener.join();
        }
        catch (const boost::thread_resource_error& e)
        {
            std::cerr << "Error starting threads: " << e.what() << std::endl;
            std::exit(EXIT_FAILURE);
        }
    }
    catch (const Rknockd::ConfigException& e)
    {
        std::cerr <<  "Error loading configuration file: " << e.what() << std::endl;
        std::exit(EXIT_FAILURE);
    }
    
    return EXIT_SUCCESS;
}

