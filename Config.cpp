#include <fstream>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <libxml++/libxml++.h>
#include <boost/lexical_cast.hpp>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "Config.hpp"


namespace Rknockd
{

char
bintohex(boost::uint8_t c)
{
    static char hex_table[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',};
    if (c >= 16)
        return 'Z';
    return hex_table[c];
}

boost::uint8_t
hextobin(char c)
{
    switch (c)
    {
        case '0':
            return 0; break;
        case '1':
            return 1; break;
        case '2':
            return 2; break;
        case '3':
            return 3; break;
        case '4':
            return 4; break;
        case '5':
            return 5; break;
        case '6':
            return 6; break;
        case '7':
            return 7; break;
        case '8':
            return 8; break;
        case '9':
            return 9; break;
        case 'a': case 'A':
            return 10; break;
        case 'b': case 'B':
            return 11; break;
        case 'c': case 'C':
            return 12; break;
        case 'd': case 'D':
            return 13; break;
        case 'e': case 'E':
            return 14; break;
        case 'f': case 'F':
            return 15; break;
        default:
            return std::numeric_limits<uint8_t>::max();
    }
}

ConfigException::ConfigException(const std::string& d)
: runtime_error(d)
{}

const Protocol Protocol::TCP(IPPROTO_TCP, "TCP");
const Protocol Protocol::UDP(IPPROTO_UDP, "UDP");

Protocol::Protocol(const Protocol& p)
: number(p.number), name(p.name)
{}

Protocol&
Protocol::operator=(const Protocol& p)
{
    if (this == &p)
        return *this;
    
    number = p.number;
    name = p.name;
    
    return *this;
}

bool
Protocol::operator==(unsigned num) const
{
    return (number == num);
}

bool
Protocol::operator==(const Protocol& p) const
{
    return (number == p.number);
}

bool
Protocol::operator!=(unsigned num) const
{
    return !(*this == num);
}

bool
Protocol::operator!=(const Protocol& p) const
{
    return !(*this == p);
}

unsigned
Protocol::getNumber() const
{
    return number;
}

const std::string&
Protocol::getName() const
{
    return name;
}

Protocol::Protocol(unsigned num, const std::string& n)
: number(num), name(n)
{}

std::ostream& 
operator<<(std::ostream& out, const Protocol& p)
{
    out << p.name;
    return out;
}


RequestBase::RequestBase()
: proto(Protocol::TCP), port(), ttl(DEFAULT_TTL*1000), ignoreClientAddr(false), secret()
{}

RequestBase::~RequestBase()
{}

const Protocol&
RequestBase::getProtocol() const
{
    return proto;
}

const boost::uint16_t 
RequestBase::getPort() const
{
    return port;
}

const boost::uint32_t 
RequestBase::getAddr() const
{
    // FIXME: option not implemented
    return 0;
}

const boost::uint16_t 
RequestBase::getTTL() const
{
    return ttl;
}

const bool
RequestBase::getIgnoreClientAddr() const
{
    return ignoreClientAddr;
}

const std::string 
RequestBase::getSecret() const
{
    return secret;
}

void 
RequestBase::printRequest(std::ostream& os) const
{
    os   << "    port:        " << port
       << "\n    protocol:    " << proto
       << "\n    secret:      " << secret
       << "\n    TTL:         " << ttl/1000
       << std::endl;
}

/*RequestBase&
RequestBase::operator=(const Request& req)
{
    if (this != &req)
    {
        proto = req.proto;
        port = req.port;
        ignoreClientAddr = req.ignoreClientAddr;
        secret = req.secret;
    }
    return *this;
}*/

void
RequestBase::parseRequest(const xmlpp::Element* elmt, const Config* config) THROW((ConfigException))
{
    assert(elmt != NULL);
    
    const xmlpp::Element::AttributeList& attrs = elmt->get_attributes();
    const xmlpp::Node::NodeList& children = elmt->get_children();
    const xmlpp::TextNode* tnode;
    const xmlpp::CommentNode* cnode;
    bool have_port = false;
    bool have_request = false;

    // iterate over attributes
    for(xmlpp::Element::AttributeList::const_iterator iter = attrs.begin(); iter != attrs.end(); ++iter)
    {
        if ((*iter)->get_name() == "port") // required
        {
            try
            {
                port = boost::lexical_cast<boost::uint16_t>(std::string((*iter)->get_value()));
                have_port = true;
            }
            catch (boost::bad_lexical_cast& e)
            {
                throw ConfigException("Error parsing attribute \"port\" of element \"request\"");
            }
        }
        else if ((*iter)->get_name() == "secret") // required
        {
            secret = std::string((*iter)->get_value());
            if (secret.length() < MIN_KEY_SIZE)
                throw ConfigException("Key too short in element \"request\"");
            else if (secret.length() > MAX_KEY_SIZE)
                throw ConfigException("Key too long in element \"request\"");
        }
        else if ((*iter)->get_name() == "protocol") // not required
        {
            if ((*iter)->get_value() == "tcp")
                proto = Protocol::TCP;
            else if ((*iter)->get_value() == "udp")
                proto = Protocol::UDP;
            else
                throw ConfigException("Unknown protocol specified for element \"request\"");
        }
        else if ((*iter)->get_name() == "address") // not required
        {
            // FIXME: implement this
            throw ConfigException("Attribute \"address\" is not implemented");
        }
        else if ((*iter)->get_name() == "ignore_client_addr") // not required
        {
            if ((*iter)->get_value() == "true")
                ignoreClientAddr = true;
            else if ((*iter)->get_value() == "false")
                ignoreClientAddr = false;
            else
                throw ConfigException("Unknown value specified for element \"ignore_client_addr\"");
        }
        else if ((*iter)->get_name() == "ttl") // not required
        {
            try
            {
                ttl = boost::lexical_cast<boost::uint16_t>(std::string((*iter)->get_value()));
                if (ttl < MIN_TTL)
                    throw ConfigException("TTL too low in element \"request\"");
                else if (ttl > MAX_TTL)
                    throw ConfigException("TTL to high in element \"request\"");
                ttl *= 1000; // convert to milliseconds
            }
            catch (boost::bad_lexical_cast& e)
            {
                throw ConfigException("Error parsing attribute \"ttl\" of element \"request\"");
            }
        }
        else // unknown attribute
            throw ConfigException(std::string("Unknown attribute \"") + std::string((*iter)->get_name()) + std::string("\" of element \"rknockd\""));
    }

    // verify that all required attributes are present
    if (have_port == false)
        throw ConfigException("Missing required attribute \"port\" of element \"request\"");

    // get the request string
    for(xmlpp::Node::NodeList::const_iterator iter = children.begin(); iter != children.end(); ++iter)
    {
        // casting to all possible subclasses and checking which worked is an
        // ugly hack.  What's the proper way of doing this?
        tnode = dynamic_cast<xmlpp::TextNode*>(*iter);
        cnode = dynamic_cast<xmlpp::CommentNode*>(*iter);
        if (tnode) // text; parse knock values
        {
            if (tnode->is_white_space())
                continue;
            else
            {
                parseRequestString(std::string(tnode->get_content()), config);
                have_request = true;
            }
        }
        else if (cnode) // comment; ignore it
        {} 
        else
            throw ConfigException(std::string("Internal error at " __FILE__ ":" QUOTE(__LINE__) ": unexpected node type: ") + (*iter)->get_name());
    }

    if (have_request == false)
        throw ConfigException("Missing required contents of element \"request\"");
}



Config::Config(const std::string& filename)
: file(filename), basePort(DEFAULT_BASE_PORT), challengeBytes(BITS_TO_BYTES(DEFAULT_CHALLENGE_BITS)), randomDevice(DEFAULT_RANDOM_DEVICE), nfQueueNum(0), overrideServerAddr(false), serverAddr(0)
{
    // we can't load the config file here because in a constructor, we don't 
    // know what subclass we are
}

Config::~Config()
{}

const std::string& 
Config::getFile() const
{
    return file;
}

const std::string& 
Config::getRandomDevice() const
{
    return randomDevice;
}

const boost::uint16_t 
Config::getBasePort() const
{
    return basePort;
}

const unsigned 
Config::getChallengeBytes() const
{
    return challengeBytes;
}

const boost::uint16_t
Config::getNfQueueNum() const
{
    return nfQueueNum;
}

const boost::uint32_t
Config::getOverrideServerAddr() const
{
    if (overrideServerAddr)
        return serverAddr;
    else
        return 0;
}

void 
Config::printConfig(std::ostream& os) const
{
    os <<   "config file:           " << file 
       << "\nNFQUEUE number:        " << nfQueueNum
       << "\nrandom device:         " << randomDevice
       << "\nbase knock port:       " << basePort
       << "\nchallenge bytes:       " << challengeBytes;
    os << std::endl;
}   


void
Config::readFile() THROW((ConfigException))
{
    std::ifstream fin;
    xmlpp::DomParser parser;
    const xmlpp::Element* root;
    
    // open the configuration file
    fin.open(file.c_str(), std::ios::in);
    if (!fin)
        throw ConfigException("Error opening file");
    
    /* load the file */
    parser.set_substitute_entities(true);
    try
    {
        parser.parse_stream(fin);
        
        // get the root element
        root = parser.get_document()->get_root_node();
        if (static_cast<std::string>(root->get_name()) != "rknockd")
        {
            throw ConfigException("Invalid root element");
        }
        
        // get root attributes
        parseRknockdAttrs(root);
        
        // parse children
        parseRknockdChildren(root);
    }
    catch (const std::exception& e)
    {
        throw ConfigException(e.what());
    }
    
    fin.close();
}


// note: doesn't check for duplicate  or unknown attributes
void
Config::parseRknockdAttrs(const xmlpp::Element* elmt) THROW((ConfigException))
{
    assert(elmt != NULL);
    
    bool have_queue_num = false;
    const xmlpp::Element::AttributeList& attrs = elmt->get_attributes();
    
    // check all attributes
    for(xmlpp::Element::AttributeList::const_iterator iter = attrs.begin(); iter != attrs.end(); ++iter)
    {
        if ((*iter)->get_name() == "queue_num") // required
        {
            try
            {
                nfQueueNum = boost::lexical_cast<boost::uint16_t>(std::string((*iter)->get_value()));
                have_queue_num = true;
            }
            catch (boost::bad_lexical_cast& e)
            {
                throw ConfigException("Error parsing attribute \"queue_num\" of element \"rknockd\"");
            }
        }
        else if ((*iter)->get_name() == "base_port") // not required
        {
            try
            {
                basePort = boost::lexical_cast<boost::uint16_t>(std::string((*iter)->get_value()));
            }
            catch (boost::bad_lexical_cast& e)
            {
                throw ConfigException("Error parsing attribute \"base_port\" of element \"rknockd\"");
            }
        }
        else if ((*iter)->get_name() == "challenge_bytes") // not required
        {
            try
            {
                challengeBytes = boost::lexical_cast<unsigned>(std::string((*iter)->get_value()));
            }
            catch (boost::bad_lexical_cast& e)
            {
                throw ConfigException("Error parsing attribute \"challenge_bytes\" of element \"rknockd\"");
            }
        }
        else if ((*iter)->get_name() == "server_addr") // not required
        {
            struct hostent* host;
            
            host = gethostbyname((*iter)->get_value().c_str());
            if (host == NULL)
                throw ConfigException("Error resolving host address in attribute \"server_addr\" of element \"rknockd\"");
            else if ((host->h_addrtype != AF_INET) || (host->h_length != 4) || (host->h_addr_list[0] == NULL))
                throw ConfigException("Error resolving host address in attribute \"server_addr\" of element \"rknockd\"");
            serverAddr = ntohl(*(reinterpret_cast<boost::uint32_t*>(host->h_addr_list[0])));
            overrideServerAddr = true;
        }
        else if ((*iter)->get_name() == "random_dev") // not required
        {
            randomDevice = std::string((*iter)->get_value());
        }
    }
    
    // verify that all required attributes are present
    if (have_queue_num == false)
        throw ConfigException("Missing required attribute \"queue_num\" of element \"rknockd\"");
    
    // verify consistency
    if (challengeBytes < BITS_TO_BYTES(MIN_CHALLENGE_BITS))
        throw ConfigException("Value of \"challenge_bytes\" is too small for good security in element \"rknockd\"");
    else if (challengeBytes > BITS_TO_BYTES(MAX_CHALLENGE_BITS))
        throw ConfigException("Unreasonably large value of \"challenge_bytes\" in element \"rknockd\"");
}

void 
Config::parseRknockdChildren(const xmlpp::Element* elmt) THROW((ConfigException))
{
    assert(elmt != NULL);
    
    const xmlpp::Node::NodeList& children = elmt->get_children();
    const xmlpp::TextNode* tnode;
    const xmlpp::CommentNode* cnode;
    const xmlpp::Element* child;

    // iterate over all children
    for(xmlpp::Node::NodeList::const_iterator iter = children.begin(); iter != children.end(); ++iter)
    {
        // casting to all possible subclasses and checking which worked is an
        // ugly hack.  What's the proper way of doing this?
        tnode = dynamic_cast<xmlpp::TextNode*>(*iter);
        cnode = dynamic_cast<xmlpp::CommentNode*>(*iter);
        child = dynamic_cast<xmlpp::Element*>(*iter);
        if (tnode) // text; must be empty
        {
            if (!tnode->is_white_space())
                throw ConfigException("Unexpected text in element \"rknockd\"");
        }
        else if (cnode) // comment; ignore it
        {} 
        else if (child) // child element; must be "request"
        {
            if (static_cast<std::string>(child->get_name()) != "request")
                throw ConfigException(std::string("Invalid child element of element \"rknockd\": ") + child->get_name());

            addRequest(child);
        }
        else
            throw ConfigException(std::string("Internal error at " __FILE__ ":" QUOTE(__LINE__) ": unexpected node type: ") + (*iter)->get_name());
    }
    
}

} // namespace Rknockd
