/* 
Killing this program *can* result in dropped packets.  Since they're sent to 
netlink from the kernel before this program knows about them, there's no way to 
avoid it.  SIGINT triggers a synchronous exit after any current packet has been 
processed; use SIGINT to shut down this program.

Note: this program uses asynchronous signal handlers.  If threading is added,
then these will need to be converted to synchronous signal handlers.
*/

// FIXME: drop root privileges after start-up
// FIXME: do something intelligent with memory used to hold passwords
// FIXME: implement the "address" config attribute

#define PROGNAME spaserver
#define VERSION 0.1

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
#include "PKConfig.hpp"
#include "Trie.hpp"
#include "Logmsg.hpp"
#include "Signals.hpp"
#include "spc_sanitize.h"
#include "drop_priv.h"


namespace Rknockd
{

enum Mode
{
    MODE_SPA,
    MODE_PK
};

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

    class SocketException : public std::runtime_error
    {
      public:
        SocketException(const std::string& s) : runtime_error(s) {}
    };

    typedef boost::array<boost::uint8_t, BITS_TO_BYTES(MAC_BITS)> SpaResponse;
    typedef std::tr1::unordered_map<AddressPair, HostRecord<SpaRequest, SpaResponse>, AddressPairHash, AddressPairEqual> HostTable;
    typedef LibWheel::Trie<boost::uint8_t, SpaRequest> RequestTable;

    const SpaConfig& config;
    HostTable hostTable;
    RequestTable requestTable;
    HostTableGC<HostTable> hostTableGC;

    HostRecord<SpaRequest, SpaResponse>& getRecord(const NFQ::NfqUdpPacket* pkt) THROW((UnknownHostException));
    bool checkResponse(const NFQ::NfqUdpPacket* pkt, const HostRecord<SpaRequest, SpaResponse>& host);
    void openPort(const HostRecord<SpaRequest, SpaResponse>& host) THROW((IOException));
    void deleteState(const HostRecord<SpaRequest, SpaResponse>& host);
    const SpaRequest& checkRequest(const NFQ::NfqUdpPacket* pkt) THROW((BadRequestException));
    void issueChallenge(const NFQ::NfqUdpPacket* pkt, const SpaRequest& req) THROW((CryptoException, IOException, SocketException));
    void handlePacket(const NFQ::NfqPacket* p) THROW((CryptoException));

  public:
    SpaListener(const SpaConfig& c, bool verbose_logging) THROW((IOException, NFQ::NfqException));
    ~SpaListener();
};


/* 
Looks up a host in the host hash table 
If an entry exists in the hash table matching *pkt, return it.  Otherwise, 
throw an UnknownHostException.
*/
SpaListener::HostRecord<SpaRequest, SpaListener::SpaResponse>& 
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
SpaListener::checkResponse(const NFQ::NfqUdpPacket* pkt, const HostRecord<SpaRequest, SpaResponse>& host)
{
    size_t payload_size;
    const boost::uint8_t* contents = pkt->getUdpPayload(payload_size);

    // make sure that we have a valid message
    if (payload_size != BITS_TO_BYTES(MAC_BITS))
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
SpaListener::openPort(const HostRecord<SpaRequest, SpaResponse>& host) THROW((IOException))
{
    struct ipt_remap remap;
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
    ret = write(remapFD, &remap, sizeof(remap));
    if (ret == -1)
        throw IOException(std::string("Error writing to /proc/"REMAP_PROC_FILE": ") + strerror(errno));
    else if (ret != sizeof(remap))
        throw IOException("Error writing to /proc/"REMAP_PROC_FILE": message truncated");
}


/* 
Remove an entry from the host hash table
*/
void 
SpaListener::deleteState(const HostRecord<SpaRequest, SpaResponse>& host)
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
    else if ((request_bytes < BITS_TO_BYTES(MIN_REQUEST_BITS)) || (request_bytes > BITS_TO_BYTES(MAX_REQUEST_BITS)))
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
    unsigned rand_len = config.getChallengeBytes() + BITS_TO_BYTES(PORT_MESSAGE_PAD_BITS) + 2;
    boost::uint8_t* rand_bytes;
    boost::uint16_t dport;
    int ret;

    // read some random data;
    rand_bytes = new boost::uint8_t[rand_len];
    ret = read(randomFD, rand_bytes, rand_len);
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
    ret = ::close(sock_fd);
    if (ret == -1)
        throw SocketException(std::string("Error closing socket: ") + std::strerror(errno));

    // create a record for this host
    HostRecord<SpaRequest, SpaResponse> hrec(pkt, dport, req, challenge+sizeof(SpaChallengeHeader), config.getChallengeBytes());
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
SpaListener::handlePacket(const NFQ::NfqPacket* p) THROW((CryptoException))
{
    const NFQ::NfqUdpPacket* packet = dynamic_cast<const NFQ::NfqUdpPacket*>(p);
    assert(packet != NULL);

    try
    {
        HostRecord<SpaRequest, SpaResponse>& host = getRecord(packet);

        // we have already issued a challenge to this host;
        // check if this is a valid response
        if (checkResponse(packet, host))
        {
            try
            {
                openPort(host);
            }
            catch (const IOException& e)
            {
                LibWheel::logmsg(LibWheel::logmsg_err, "I/O error: %s", e.what());
            }
        }
        else
        {
            LibWheel::logmsg(LibWheel::logmsg_notice, "Incorrect response received from %s:%hu", ipv4_to_string(packet->getIpSource()).c_str(), packet->getUdpSource());
        }
        deleteState(host);
    }
    catch (const UnknownHostException& e)
    {
        // check if this packet contains a valid request
        try
        {
            const SpaRequest& req = checkRequest(packet);

            // we got a valid request; issue a challenge
            issueChallenge(packet, req);
        }
        catch (const BadRequestException& e)
        {
            LibWheel::logmsg(LibWheel::logmsg_notice, "Incorrect request received from %s:%hu: %s", ipv4_to_string(packet->getIpSource()).c_str(), packet->getUdpSource(), e.what());
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
}


/* 
Constructor for SpaListener
Initialize, program the request matcher trie with all request strings
*/
SpaListener::SpaListener(const SpaConfig& c, bool verbose_logging) THROW((IOException, NFQ::NfqException))
: Listener(c, "/proc/"REMAP_PROC_FILE, verbose_logging), config(c), hostTable(), requestTable(), hostTableGC(hostTable, verbose_logging)
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
    std::cout << "Usage: "QUOTE(PROGNAME)" [-c <config file>] [-s|-p] [-D] [-V] [-h] [-v]\n"
              << "where -c <config file> - use the specified configuration file\n"
              << "      -s - use single packet authorization (default)\n"
              << "      -p - use port knocking\n"
              << "      -D - run the program as a daemon\n"
              << "      -V - enable verbose logging\n"
              << "      -h - print this message\n"
              << "      -v - print version information" << std::endl;
    return;
}


void parse_args(int argc, char** argv, std::string& config_file, Mode& mode, bool& daemon, bool& verbose)
{
    char* short_options = "c:spDhvV";
    static struct option long_options[] = {
        {"config", 1, 0, 'c'},
        {"spa", 0, 0, 's'},
        {"port-knock", 0, 0, 'p'},
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
            case 's':
                mode = MODE_SPA;
                break;
            case 'p':
                mode = MODE_PK;
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

inline Config* 
get_config(const Mode mode, const std::string& config_file) THROW((ConfigException, std::runtime_error))
{
    switch (mode)
    {
      case MODE_SPA:
        return new SpaConfig(config_file);
      case MODE_PK:
        return new PKConfig(config_file);
      default:
        throw std::runtime_error("Invalid mode");
    }
}

inline Listener*
get_listener(const Mode, const Config* config, const bool verbose)
{
    const SpaConfig* spaConfig;
    const PKConfig* pkConfig;
    
    assert(config != NULL);

    if ((spaConfig = dynamic_cast<const SpaConfig*>(config)) != NULL)
        return new SpaListener(*spaConfig, verbose);
    /*else if ((pkConfig = dynamic_cast<const PKConfig*>(config)) != NULL)
        return new PKListener(*pkConfig, verbose);*/
    else
        throw std::runtime_error("Invalid mode");
}

void sigint_handler()
{
    throw LibWheel::Interrupt();
}


} // namespace Rknockd


int
main(int argc, char** argv)
{
    std::string config_file = "spaconfig.xml";
    bool make_daemon = false;
    bool verbose = false;
    uid_t nobody_uid;
    gid_t nobody_gid;
    int ret = EXIT_SUCCESS;
    Rknockd::Mode mode = Rknockd::MODE_SPA;
    Rknockd::Config* config = NULL;
    Rknockd::Listener* listener = NULL;
    
    // initialize the logmsg facility (spc_sanitize_* needs it)
    LibWheel::logmsg.open(LibWheel::logmsg_stderr, 0, argv[0]);
    
    // sanitize the system
    spc_sanitize_environment(0, NULL);
    spc_sanitize_files();
    
    // parse command-line arguments
    Rknockd::parse_args(argc, argv, config_file, mode, make_daemon, verbose);
    
#ifdef DEBUG
    verbose = true;
    make_daemon = false;
#endif

    try
    {
        // load configuration
        //Rknockd::SpaConfig config(config_file);
        config = get_config(mode, config_file);
#ifdef DEBUG
        config->printConfig(std::cout);
#endif

std::exit(1);

        // make sure that we're running as root
        if (geteuid() != 0)
        {
            std::cerr << "This program requires superuser privileges" << std::endl;
            delete config;
            LibWheel::logmsg.close();
            return EXIT_FAILURE;
        }
        
        // get the uid and gid for "nobody"
        nobody_uid = get_user_uid("nobody");
        if (nobody_uid == (uid_t)-1)
        {
            std::cerr << "Error: user \"nobody\" does not exist" << std::endl;
            delete config;
            LibWheel::logmsg.close();
            return EXIT_FAILURE;
        }
        nobody_gid = get_group_gid("nobody");
        if (nobody_gid == (gid_t)-1)
        {
            std::cerr << "Error: group \"nobody\" does not exist" << std::endl;
            delete config;
            LibWheel::logmsg.close();
            return EXIT_FAILURE;
        }

        LibWheel::SignalQueue::setHandler(SIGINT, Rknockd::sigint_handler);
        
        try
        {
            //Rknockd::SpaListener listener(config, verbose);
            listener = get_listener(mode, config, verbose);
        
            // we've finished initializing; time to summon Beelzebub
            if (make_daemon)
            {
                // Ia Ia Cthulhu Fhtagn!
                daemon(0, 0);

                // stderr is closed; switch to syslog
                LibWheel::logmsg.open(LibWheel::logmsg_syslog, 0, argv[0]);
            }

            // drop privileges to nobody, nobody
            // NFQUEUE appears to require root privileges even after opening
            // FIXME: make this work
            //drop_priv(nobody_uid, nobody_gid);

            // run the listener
            (*listener)();
            
            listener->close();
        }
        catch (const NFQ::NfqException& e)
        {
            LibWheel::logmsg(LibWheel::logmsg_crit, "Error in NFQUEUE: %s", e.what());
            ret = EXIT_FAILURE;
        }
    }
    catch (const Rknockd::ConfigException& e)
    {
        std::cerr << "Error loading configuration file " << config_file << ": " << e.what() << std::endl;
        ret = EXIT_FAILURE;
    }
    catch (const Rknockd::IOException& e)
    {
        LibWheel::logmsg(LibWheel::logmsg_err, "I/O error: %s", e.what());
        ret = EXIT_FAILURE;
    }
        
    delete config;
    delete listener;
    LibWheel::logmsg.close();
    return ret;
}

