#include "Config.hpp"

namespace Rknockd
{
    template <typename RequestStrType, typename RequestPrinterType, typename RequestParserType, typename ConfigType>
    Request<RequestStrType, RequestPrinterType, RequestParserType, ConfigType>::Request(const xmlpp::Element* elmt, const ConfigType& config) THROW((ConfigException))
    : RequestBase(), requestStr()
    {
        // this can't be called by the base class constructor, since it doesn't know 
        // what subclass it is
        parseRequest(elmt, &config);
    }

    template <typename RequestStrType, typename RequestPrinterType, typename RequestParserType, typename ConfigType>
    const RequestStrType&
    Request<RequestStrType, RequestPrinterType, RequestParserType, ConfigType>::getRequestString() const
    {
        return requestStr;
    }

    template <typename RequestStrType, typename RequestPrinterType, typename RequestParserType, typename ConfigType>
    void
    Request<RequestStrType, RequestPrinterType, RequestParserType, ConfigType>::printRequest(std::ostream& os) const
    {
        requestPrinter(os, requestStr);

        // print the basics
        RequestBase::printRequest(os);
    }

    template <typename RequestStrType, typename RequestPrinterType, typename RequestParserType, typename ConfigType>
    void 
    Request<RequestStrType, RequestPrinterType, RequestParserType, ConfigType>::parseRequestString(const std::string& str, const Config* cfg) THROW((ConfigException))
    {
        requestParser(requestStr, str, cfg);
    }
    
} // namespace Rknockd
