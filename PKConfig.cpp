#include <cassert>
#include <libxml++/libxml++.h>
#include <boost/lexical_cast.hpp>
#include <boost/tokenizer.hpp>
#include "PKConfig.hpp"

namespace Rknockd
{

PKRequest::PKRequest(const xmlpp::Element* elmt, const PKConfig& config) THROW((ConfigException))
: Request(), knocks(), encodedKnocks()
{
    // this can't be called by the base class constructor, since it doesn't know 
    // what subclass it is
    parseRequest(elmt, &config);
}

const std::vector<boost::uint16_t>& 
PKRequest::getKnocks() const
{
    return knocks;
}

const std::set<boost::uint16_t>& 
PKRequest::getEncodedKnocks() const
{
    return encodedKnocks;
}

void
PKRequest::printRequest(std::ostream& os) const
{
    os << "request:  ";
    
    for (std::vector<boost::uint16_t>::const_iterator i=knocks.begin(); i!=knocks.end(); i++)
    {
        os << *i << ' ';
    }
    os << std::endl;

    // print the basics
    Request::printRequest(os);
}


void 
PKRequest::parseRequestString(const std::string& str, const Config* c) THROW((ConfigException))
{
    boost::tokenizer<> tokens(str);
    boost::uint16_t knock;
    const PKConfig* config = dynamic_cast<const PKConfig*>(c);
    assert(config != NULL);

    // parse the string and extract knock values
    for(boost::tokenizer<>::const_iterator tok=tokens.begin(); tok!=tokens.end();++tok)
    {
        try
        {
            knock = boost::lexical_cast<boost::uint16_t>(*tok);
            if (knock > (1 << config->getBitsPerKnock()))
                throw ConfigException(std::string("Knock value \"") + (*tok) + std::string("\" out of range in element \"request\""));
            knocks.push_back(knock);
        }
        catch (boost::bad_lexical_cast& e)
        {
            throw ConfigException("Error parsing knock value in element \"request\"");
        }
    }

    // make sure that we have a reasonable port sequence
    if (knocks.size()*config->getBitsPerKnock() < MIN_REQUEST_BITS)
        throw ConfigException("Too few knocks in element \"request\"");
    else if ((knocks.size()*config->getBitsPerKnock() > MAX_REQUEST_BITS) || (knocks.size() > config->getMaxKnocks()))
        throw ConfigException("Too many knocks in element \"request\"");

    // generate the encoded knock values, with sequence information
    for (unsigned i=0; i<knocks.size(); i++)
        encodedKnocks.insert(config->getBasePort() + knocks[i] + i*(1<<config->getBitsPerKnock()));
}


PKConfig::PKConfig(std::string& filename) THROW((ConfigException))
: Config(filename), maxKnocks(DEFAULT_MAX_KNOCKS), bitsPerKnock(DEFAULT_BITS_PER_KNOCK), requests()
{
    // this can't be called by the base class constructor, since it doesn't know 
    // what subclass it is
    readFile();
}

PKConfig::~PKConfig()
{}

const boost::uint8_t
PKConfig::getMaxKnocks() const
{
    return maxKnocks;
}

const unsigned 
PKConfig::getBitsPerKnock() const
{
    return bitsPerKnock;
}

const std::vector<PKRequest>&
PKConfig::getRequests() const
{
    return requests;
}

void 
PKConfig::printConfig(std::ostream& os) const
{
    // first, print the basics
    Config::printConfig(os);

    // print PKConfig-specific stuff
    os <<   "max knocks:            " << (unsigned)maxKnocks
       << "\nbits per knock:        " << bitsPerKnock
       << std::endl;
    
    // print the Requests
    for (std::vector<PKRequest>::const_iterator i=requests.begin(); i!=requests.end(); i++)
    {
        i->printRequest(os);
    }
}   

// note: doesn't check for duplicate or unknown attributes
void
PKConfig::parseRknockdAttrs(const xmlpp::Element* elmt) THROW((ConfigException))
{
    assert(elmt != NULL);
    
    // first, get the basics
    Config::parseRknockdAttrs(elmt);
    
    const xmlpp::Element::AttributeList& attrs = elmt->get_attributes();
    boost::uint16_t max_knocks; // for some reason, you can't lexical_cast to uint8_t
    
    // check all attributes
    for(xmlpp::Element::AttributeList::const_iterator iter = attrs.begin(); iter != attrs.end(); ++iter)
    {
        if ((*iter)->get_name() == "max_knocks") // not required
        {
            try
            {
                max_knocks = boost::lexical_cast<boost::uint16_t>((std::string)(*iter)->get_value());
                if (max_knocks > 256)
                    throw ConfigException("Value for attribute \"max_knocks\" of element \"rknocks\" is out of range");
                else
                    maxKnocks = max_knocks;
            }
            catch (boost::bad_lexical_cast& e)
            {
                throw ConfigException("Error parsing attribute \"max_knocks\" of element \"rknockd\"");
            }
        }
        else if ((*iter)->get_name() == "bits_per_knock") // not required
        {
            try
            {
                bitsPerKnock = boost::lexical_cast<unsigned>((std::string)(*iter)->get_value());
            }
            catch (boost::bad_lexical_cast& e)
            {
                throw ConfigException("Error parsing attribute \"bits_per_knock\" of element \"rknockd\"");
            }
        }
        //else // unknown attribute
        //    throw ConfigException(std::string("Unknown attribute \"") + (std::string)((*iter)->get_name()) + std::string("\" of element \"rknockd\""));
    }
    
    // verify consistency
    if ((bitsPerKnock == 0) || (bitsPerKnock > 16))
        throw ConfigException("Invalid value for attribute \"bits_per_knock\" of element \"rknockd\"");
    else if (basePort + maxKnocks*(1 << bitsPerKnock) - 1 > 65535)
        throw ConfigException("\"bits_per_knock\" too large for chosen \"base_port\" and \"max_knocks\" in element \"rknockd\"");
}

void 
PKConfig::addRequest(const xmlpp::Element* elmt) THROW((ConfigException))
{
    requests.push_back(PKRequest(elmt, *this));
}


} // namespace Rknockd
