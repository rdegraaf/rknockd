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
// FIXME: auto_ptr

#define PROGNAME spaserver
#define VERSION 0.2

#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <map>
#include <vector>
#include <array>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cstddef>
#include <cctype>
#include <cstdint>
#include <tr1/unordered_map>
#include <gcrypt.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <getopt.h>
#include <boost/pointer_cast.hpp>
#include <linux/netfilter_ipv4/ipt_REMAP.h>
#include "Config.hpp"
#include "NFQ.hpp"
#include "Listener.hpp"
#include "PKListener.hpp"
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

class SpaListener : public Listener
{
  private:
    struct AddressPair
    {
        uint32_t saddr;
        uint32_t daddr;
        uint16_t sport;
        uint16_t dport;
        AddressPair(NFQ::NfqUdpPacket::const_ptr pkt);
        AddressPair(const Listener::HostRecordBase& host);
    };

    struct AddressPairHash
    {
        std::tr1::hash<uint32_t> uhash;
        std::tr1::hash<uint16_t> shash;
        std::size_t operator()(const AddressPair& a) const;
    };
    struct AddressPairEqual
    {
        bool operator() (const AddressPair& a, const AddressPair& b) const;
    };
            
    typedef std::array<uint8_t, BITS_TO_BYTES(MAC_BITS)> SpaResponse;
    class HostRecord : public HostRecordBase
    {
        const SpaRequest& request;
        SpaResponse response;
      public:
        HostRecord(NFQ::NfqUdpPacket::const_ptr pkt, uint16_t target, const SpaRequest& req, const uint8_t* challenge, size_t clen, uint32_t override_server_addr) THROW((CryptoException));
        const SpaRequest& getRequest() const;
        const SpaResponse& getResponse() const;
    };

    typedef std::tr1::unordered_map<AddressPair, HostRecord, AddressPairHash, AddressPairEqual> HostTable;
    typedef LibWheel::Trie<uint8_t, SpaRequest> RequestTable;

    const SpaConfig& config;
    HostTable hostTable;
    RequestTable requestTable;
    HostTableGC<HostTable> hostTableGC;

    HostRecord& getRecord(NFQ::NfqUdpPacket::const_ptr pkt) THROW((UnknownHostException));
    bool checkResponse(NFQ::NfqUdpPacket::const_ptr pkt, const HostRecord& host);
    void deleteState(const HostRecord& host);
    const SpaRequest& checkRequest(NFQ::NfqUdpPacket::const_ptr pkt) THROW((BadRequestException));
    void issueChallenge(NFQ::NfqUdpPacket::const_ptr pkt, const SpaRequest& req) THROW((CryptoException, IOException, SocketException));
    void handlePacket(NFQ::NfqPacket::const_ptr p) THROW((CryptoException));

  public:
    SpaListener(const SpaConfig& c, bool verbose_logging) THROW((IOException, NFQ::NfqException));
    ~SpaListener();
};

SpaListener::HostRecord::HostRecord(NFQ::NfqUdpPacket::const_ptr pkt, uint16_t target, const SpaRequest& req, const uint8_t* challenge, size_t clen, uint32_t override_server_addr) THROW((CryptoException))
: HostRecordBase(pkt, target), request(req), response()
{
    size_t resp_len;
    std::unique_ptr<uint8_t[]> resp(Listener::generateResponse(*this, challenge, clen, req.getIgnoreClientAddr(), override_server_addr, req.getRequestString(), resp_len));
    Listener::computeMAC(response, req.getSecret(), resp.get(), resp_len);
}

const SpaRequest&
SpaListener::HostRecord::getRequest() const
{
    return request;
}

const SpaListener::SpaResponse&
SpaListener::HostRecord::getResponse() const
{
    return response;
}

/*
Creates an AddressPair from a NfqUdpPacket 
*/
SpaListener::AddressPair::AddressPair(NFQ::NfqUdpPacket::const_ptr pkt)
: saddr(pkt->getIpSource()), daddr(pkt->getIpDest()), sport(pkt->getUdpSource()), dport(pkt->getUdpDest())
{}


/* 
Creates an AddressPair from a HostRecord
*/
SpaListener::AddressPair::AddressPair(const Listener::HostRecordBase& host)
: saddr(host.getSrcAddr()), daddr(host.getDstAddr()), sport(host.getSrcPort()), dport(host.getDstPort())
{}


std::size_t 
SpaListener::AddressPairHash::operator() (const AddressPair& a) const
{
    return uhash(a.saddr) ^ uhash(a.daddr) ^ shash(a.sport) ^ (shash(a.dport)<<16);
}

bool
SpaListener::AddressPairEqual::operator() (const AddressPair& a, const AddressPair& b) const 
{
    return ((a.saddr==b.saddr) && (a.daddr==b.daddr) && (a.sport==b.sport) && (a.dport==b.dport));
}


/* 
Looks up a host in the host hash table 
If an entry exists in the hash table matching *pkt, return it.  Otherwise, 
throw an UnknownHostException.
*/
SpaListener::HostRecord& 
SpaListener::getRecord(NFQ::NfqUdpPacket::const_ptr pkt) THROW((UnknownHostException))
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
SpaListener::checkResponse(NFQ::NfqUdpPacket::const_ptr pkt, const HostRecord& host)
{
    size_t payload_size;
    shared_ptr<const uint8_t[]> contents = pkt->getUdpPayload(payload_size);

    // make sure that we have a valid message
    if (payload_size != BITS_TO_BYTES(MAC_BITS))
        return false;

    // check if we received the expected response
    if (std::equal(host.getResponse().begin(), host.getResponse().end(), contents.get()))
        return true;
    else
        return false;
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
SpaListener::checkRequest(NFQ::NfqUdpPacket::const_ptr pkt) THROW((BadRequestException))
{
    assert(pkt != NULL);
    size_t payload_size;
    shared_ptr<const uint8_t[]> payload = pkt->getUdpPayload(payload_size);
    shared_ptr<const SpaRequestHeader> hdr = boost::reinterpret_pointer_cast<const SpaRequestHeader>(payload);
    shared_ptr<const uint8_t[]> contents = { payload, payload.get() + sizeof(SpaRequestHeader) };
    const SpaRequest* request;
    uint16_t request_bytes = ntohs(hdr->requestBytes);

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
    request = requestTable.search(contents.get(), request_bytes);
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
SpaListener::issueChallenge(NFQ::NfqUdpPacket::const_ptr pkt, const SpaRequest& req) THROW((CryptoException, IOException, SocketException))
{
    //std::unique_ptr<uint8_t[]> challenge;
    size_t challenge_len;
    uint16_t dport;
    
    std::unique_ptr<uint8_t[]> challenge(generateChallenge(config, req, challenge_len, req.getProtocol(), dport));
    sendMessage(pkt->getIpSource(), pkt->getUdpSource(), pkt->getUdpDest(), challenge.get(), challenge_len);

    // create a record for this host
    HostRecord hrec(pkt, dport, req, challenge.get()+sizeof(ChallengeHeader), config.getChallengeBytes(), config.getOverrideServerAddr());
    AddressPair haddr(hrec);
    hostTable.insert(std::make_pair(haddr, hrec));
    hostTableGC.schedule(haddr, TIMEOUT_SECS, TIMEOUT_USECS);

    if (verbose)
        LibWheel::logmsg(LibWheel::logmsg_info, "Sent challenge, dport=%hu to %s:%hu", dport, ipv4_to_string(pkt->getIpSource()).c_str(), pkt->getUdpSource());
}


/* 
Handle a packet received from Netlink
*/
void 
SpaListener::handlePacket(NFQ::NfqPacket::const_ptr p) THROW((CryptoException))
{
    NFQ::NfqUdpPacket::const_ptr packet = boost::dynamic_pointer_cast<const NFQ::NfqUdpPacket>(p);
    assert(packet != NULL);

    try
    {
        HostRecord& host = getRecord(packet);

        // we have already issued a challenge to this host;
        // check if this is a valid response
        if (checkResponse(packet, host))
        {
            try
            {
                openPort(host, host.getRequest());
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
: Listener(c, "/proc/" REMAP_PROC_FILE, verbose_logging), config(c), hostTable(), requestTable(), hostTableGC(hostTable, verbose_logging)
{
    // program the requests trie with all request strings
    const std::vector<SpaRequest>& requests = c.getRequests();
    for (std::vector<SpaRequest>::const_iterator i = requests.begin(); i != requests.end(); ++i)
    {
        requestTable.addString(i->getRequestString(), *i);
    }
    
    // set the SIGALRM handler
    LibWheel::SignalQueue::setHandler(SIGALRM, LibWheel::SignalQueue::HANDLE);
    LibWheel::SignalQueue::addHandler(SIGALRM, boost::ref(hostTableGC));
}


/* Destructor for SpaListener
*/
SpaListener::~SpaListener()
{
    LibWheel::SignalQueue::deleteHandler(SIGALRM, boost::ref(hostTableGC));
}


/* 
Prints version info
*/
void print_version()
{
    std::cout << QUOTE(PROGNAME) << ": " <<  QUOTE(VERSION)
#ifdef DEBUG
              << " (debug build)"
#endif
              << "\nCopyright (c) Rennie deGraaf, 2007.  All rights reserved."
              << std::endl;
}


/*
Print a help message
*/
void print_help()
{
    std::cout << "Usage: " QUOTE(PROGNAME) " [-c <config file>] [-s|-p] [-D] [-V] [-h] [-v]\n"
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
    const char* short_options = "c:spDhvV";
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
get_config(const Mode mode, const std::string& config_file) THROW((ConfigException, std::domain_error))
{
    switch (mode)
    {
      case MODE_SPA:
        return new SpaConfig(config_file);
      case MODE_PK:
        return new PKConfig(config_file);
      default:
        throw std::domain_error("Invalid mode");
    }
}

inline Listener*
get_listener(const Mode, const Config* config, const bool verbose) THROW((std::domain_error))
{
    const SpaConfig* spaConfig;
    const PKConfig* pkConfig;
    
    assert(config != NULL);

    if ((spaConfig = dynamic_cast<const SpaConfig*>(config)) != NULL)
        return new SpaListener(*spaConfig, verbose);
    else if ((pkConfig = dynamic_cast<const PKConfig*>(config)) != NULL)
        return new PKListener(*pkConfig, verbose);
    else
        throw std::domain_error("Invalid mode");
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
    if ((verbose == false) || (make_daemon = true))
        std::cerr << "This is a debug build; enabling verbose logging and disabling daemon mode" << std::endl;
    verbose = true;
    make_daemon = false;
#endif

    try
    {
        // load configuration
        config = get_config(mode, config_file);
#ifdef DEBUG
        //config->printConfig(std::cout);
#endif

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

        LibWheel::SignalQueue::setHandler(SIGINT, LibWheel::SignalQueue::HANDLE);
        LibWheel::SignalQueue::addHandler(SIGINT, Rknockd::sigint_handler);
        
        try
        {
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

