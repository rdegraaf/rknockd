#include <cassert>
#include <libxml++/libxml++.h>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/trim.hpp>
#include "PKConfig.hpp"
#include "common.h"

#include <iostream>
namespace Rknockd
{

template<typename A, typename RequestPrinterType, typename C, typename D> const RequestPrinterType Request<A, RequestPrinterType, C, D>::requestPrinter = RequestPrinterType();
template<typename A, typename B, typename RequestParserType, typename D> const RequestParserType Request<A, B, RequestParserType, D>::requestParser = RequestParserType();

void 
PKRequestPrinter::operator() (std::ostream& os, const PKRequestString& requestStr) const
{
    os << "request:  ";
    
    for (PKRequestString::const_iterator i=requestStr.begin(); i!=requestStr.end(); i++)
    {
        os << *i << ' ';
    }
    os << std::endl;
}
void
PKRequestParser::operator() (PKRequestString& requestStr, const std::string& str, const Config* c) const THROW((ConfigException))
{
    std::vector<boost::uint8_t> bytes;
    std::vector<boost::uint16_t> plain_request;
    const PKConfig* config = dynamic_cast<const PKConfig*>(c);

    assert(config != NULL);

    // first, parse the input string into an array of binary bytes
    boost::uint8_t high;
    boost::uint8_t low;
    unsigned i = 0; // current index into string
    std::string tstr = boost::trim_copy(str);

    if ((tstr.length() > 2) && (tstr[0] == '0') && (tstr[1] == 'x'))
        i = 2; // starts with "0x"

    if ((tstr.length()-i > 0) && (tstr.length() & 0x01))
    {
        // string length is odd; get the first character
        low = hextobin(tstr[i]);
        if (low == std::numeric_limits<boost::uint8_t>::max())
            throw ConfigException(std::string("Value '") + tstr[i] + std::string("' out of range in element \"request\""));
        bytes.push_back(low);
        i++;
    }
    
    // we now have an even number of bytes remaining
    for (; i+1<tstr.length(); i+=2)
    {
        high = hextobin(tstr[i]);
        low = hextobin(tstr[i+1]);
        if (high == std::numeric_limits<boost::uint8_t>::max())
            throw ConfigException(std::string("Value '") + tstr[i] + std::string("' out of range in element \"request\""));
        else if  (low == std::numeric_limits<boost::uint8_t>::max())
            throw ConfigException(std::string("Value '") + tstr[i+1] + std::string("' out of range in element \"request\""));
        bytes.push_back((high<<4) | low);
    }

    
    // next, convert the array of binary bytes to a simple port knock sequence
    boost::uint32_t knock = 0;
    unsigned bits = 0;
    std::vector<boost::uint8_t>::iterator iter = bytes.begin();
    
    while (iter != bytes.end())
    {
        while ((bits < config->getBitsPerKnock()) && (iter != bytes.end()))
        {
            knock <<= 8;
            knock |= *iter;
            ++iter;
            bits += 8;
        }
        plain_request.push_back(knock >> (bits - config->getBitsPerKnock()));
        bits -= config->getBitsPerKnock();
        knock &= ((1<<bits)-1);
    }
    if (bits > 0)
        plain_request.push_back(knock >> (bits - config->getBitsPerKnock()));
    
    // finally, add sequencing information and create the final request
    for (unsigned i = 0; i < plain_request.size(); ++i)
        requestStr.insert(config->getBasePort() + plain_request[i] + i*(1<<config->getBitsPerKnock()));

    // make sure that we have a reasonable port sequence
    if (requestStr.size() * config->getBitsPerKnock() < MIN_REQUEST_BITS)
        throw ConfigException("Too few knocks in element \"request\"");
    else if ((requestStr.size() * config->getBitsPerKnock() > MAX_REQUEST_BITS) || (requestStr.size() > config->getMaxKnocks()))
        throw ConfigException("Too many knocks in element \"request\"");
}


PKConfig::PKConfig(const std::string& filename) THROW((ConfigException))
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
