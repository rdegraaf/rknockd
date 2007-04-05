#include <fstream>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <libxml++/libxml++.h>
#include <boost/lexical_cast.hpp>
#include <fcntl.h>
#include <unistd.h>
#include "Config.hpp"


namespace Rknockd
{

ConfigException::ConfigException(const std::string& d)
: runtime_error(d)
{}

Protocol Protocol::TCP(6, "TCP");
Protocol Protocol::UDP(17, "UDP");

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

Protocol::Protocol(unsigned num, const std::string& n)
: number(num), name(n)
{}

std::ostream& 
operator<<(std::ostream& out, const Protocol& p)
{
    out << p.name;
    return out;
}


Request::Request()
: proto(Protocol::TCP), port(), ignoreClientAddr(false), secret()
{}

Request::~Request()
{}

const Protocol&
Request::getProtocol() const
{
    return proto;
}

const boost::uint16_t 
Request::getPort() const
{
    return port;
}

const bool
Request::getIgnoreClientAddr() const
{
    return ignoreClientAddr;
}

const std::string 
Request::getSecret() const
{
    return secret;
}

void 
Request::printRequest(std::ostream& os) const
{
    os   << "    port:        " << port
       << "\n    protocol:    " << proto
       << "\n    secret:      " << secret
       << std::endl;
}

Request&
Request::operator=(const Request& req)
{
    if (this != &req)
    {
        proto = req.proto;
        port = req.port;
        ignoreClientAddr = req.ignoreClientAddr;
        secret = req.secret;
    }
    return *this;
}

void
Request::parseRequest(const xmlpp::Element* elmt, const Config* config) THROW((ConfigException))
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
        else if ((*iter)->get_name() == "ignore_client_addr") // not required
        {
            if ((*iter)->get_value() == "true")
                ignoreClientAddr = true;
            else if ((*iter)->get_value() == "false")
                ignoreClientAddr = false;
            else
                throw ConfigException("Unknown value specified for element \"ignore_client_addr\"");
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
                getRequestString(std::string(tnode->get_content()), config);
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



Config::Config(std::string& filename)
: file(filename), basePort(DEFAULT_BASE_PORT), challengeBytes(DEFAULT_CHALLENGE_BYTES), randomDevice(DEFAULT_RANDOM_DEVICE), randomFD(-1), nfQueueNum(0)
{
    // we can't load the config file here because in a constructor, we don't 
    // know what subclass we are
}

Config::~Config()
{
    if (randomFD != -1)
        close(randomFD);
}

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

const int
Config::getRandomFD() const
{
    return randomFD;
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
        else if ((*iter)->get_name() == "random_dev") // not required
        {
            randomDevice = std::string((*iter)->get_value());
        }
    }
    
    // verify that all required attributes are present
    if (have_queue_num == false)
        throw ConfigException("Missing required attribute \"queue_num\" of element \"rknockd\"");
    
    // verify consistency
    if (challengeBytes < MIN_CHALLENGE_BYTES)
        throw ConfigException("Value of \"challenge_bytes\" is too small for good security in element \"rknockd\"");
    else if (challengeBytes > MAX_CHALLENGE_BYTES)
        throw ConfigException("Unreasonably large value of \"challenge_bytes\" in element \"rknockd\"");
    
    // open the random device
    randomFD = open(randomDevice.c_str(), O_RDONLY);
    if (randomFD == -1)
        throw ConfigException(std::string("Error opening random device: " + std::string(strerror(errno))));
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
