#include <cassert>
#include <limits>
#include <libxml++/libxml++.h>
#include <boost/algorithm/string/trim.hpp>
#include "SpaConfig.hpp"

namespace Rknockd
{

void 
SpaRequestPrinter::operator() (std::ostream& os, const SpaRequestString& requestStr) const
{
    os << "request:  0x";
    
    for (std::vector<uint8_t>::const_iterator i=requestStr.begin(); i!=requestStr.end(); i++)
    {
        os << bintohex((*i)>>4) << bintohex((*i)&0xf);
    }
    os << std::endl;
}

template<typename A, typename RequestPrinterType, typename C, typename D> const RequestPrinterType Request<A, RequestPrinterType, C, D>::requestPrinter = RequestPrinterType();
template<typename A, typename B, typename RequestParserType, typename D> const RequestParserType Request<A, B, RequestParserType, D>::requestParser = RequestParserType();

void
SpaRequestParser::operator() (SpaRequestString& requestStr, const std::string& str, const Config*) const THROW((ConfigException))
{
    uint8_t high;
    uint8_t low;
    unsigned i = 0; // current index into string
    std::string tstr = boost::trim_copy(str);

    if ((tstr.length() > 2) && (tstr[0] == '0') && (tstr[1] == 'x'))
        i = 2; // starts with "0x"

    if ((tstr.length()-i > 0) && (tstr.length() & 0x01))
    {
        // string length is odd; get the first character
        low = hextobin(tstr[i]);
        if (low == std::numeric_limits<uint8_t>::max())
            throw ConfigException(std::string("Value '") + tstr[i] + std::string("' out of range in element \"request\""));
        requestStr.push_back(low);
        i++;
    }
    
    // we now have an even number of bytes remaining
    for (; i+1<tstr.length(); i+=2)
    {
        high = hextobin(tstr[i]);
        low = hextobin(tstr[i+1]);
        if (high == std::numeric_limits<uint8_t>::max())
            throw ConfigException(std::string("Value '") + tstr[i] + std::string("' out of range in element \"request\""));
        else if  (low == std::numeric_limits<uint8_t>::max())
            throw ConfigException(std::string("Value '") + tstr[i+1] + std::string("' out of range in element \"request\""));
        requestStr.push_back((high<<4) | low);
    }

    // make sure that we have a reasonable request string
    if (requestStr.size() < BITS_TO_BYTES(MIN_REQUEST_BITS))
        throw ConfigException("Request sequence too short in element \"request\"");
    else if (requestStr.size() > BITS_TO_BYTES(MAX_REQUEST_BITS))
        throw ConfigException("Request sequence too long in element \"request\"");
}

SpaConfig::SpaConfig(const std::string& filename) THROW((ConfigException))
: Config(filename), requests()
{
    // this can't be called by the base class constructor, since it doesn't know 
    // what subclass we are
    readFile();
}

SpaConfig::~SpaConfig()
{}

const std::vector<SpaRequest>&
SpaConfig::getRequests() const
{
    return requests;
}

void 
SpaConfig::printConfig(std::ostream& os) const
{
    // first, print the basics
    Config::printConfig(os);

    // print the Requests
    for (std::vector<SpaRequest>::const_iterator i=requests.begin(); i!=requests.end(); ++i)
    {
        i->printRequest(os);
    }
}   

// note: doesn't check for duplicate or unknown attributes
void
SpaConfig::parseRknockdAttrs(const xmlpp::Element* elmt) THROW((ConfigException))
{
    assert(elmt != NULL);
    
    // first, get the basics
    Config::parseRknockdAttrs(elmt);
}

void 
SpaConfig::addRequest(const xmlpp::Element* elmt) THROW((ConfigException))
{
    requests.push_back(SpaRequest(elmt, *this));
}



} // namespace Rknockd
