#include <cassert>
#include <limits>
#include <libxml++/libxml++.h>
#include <boost/algorithm/string/trim.hpp>
#include "SpaConfig.hpp"

namespace Rknockd
{

SpaRequest::SpaRequest(const xmlpp::Element* elmt, const SpaConfig& config) THROW((ConfigException))
: Request(), requestStr()
{
    // this can't be called by the base class constructor, since it doesn't know 
    // what subclass it is
    parseRequest(elmt, &config);
}

const std::vector<boost::uint8_t>&
SpaRequest::getRequestString() const
{
    return requestStr;
}

static char
bintohex(boost::uint8_t c)
{
    static char hex_table[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',};
    if (c >= 16)
        return 'Z';
    return hex_table[c];
}

static boost::uint8_t
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

void
SpaRequest::printRequest(std::ostream& os) const
{
    os << "request:  0x";
    
    for (std::vector<boost::uint8_t>::const_iterator i=requestStr.begin(); i!=requestStr.end(); i++)
    {
        os << bintohex((*i)>>4) << bintohex((*i)&0xf);
    }
    os << std::endl;

    // print the basics
    Request::printRequest(os);
}


void 
SpaRequest::getRequestString(const std::string& str, const Config*) THROW((ConfigException))
{
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
        requestStr.push_back(low);
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
        requestStr.push_back((high<<4) | low);
    }

    // make sure that we have a reasonable request string
    if (requestStr.size() < MIN_REQUEST_BYTES)
        throw ConfigException("Request sequence too short in element \"request\"");
    else if (requestStr.size() > MAX_REQUEST_BYTES)
        throw ConfigException("Request sequence too long in element \"request\"");
}

SpaConfig::SpaConfig(std::string& filename) THROW((ConfigException))
: Config(filename), requests()
{
    // this can't be called by the base class constructor, since it doesn't know 
    // what subclass it is
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
    for (std::vector<SpaRequest>::const_iterator i=requests.begin(); i!=requests.end(); i++)
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
