#ifndef RKNOCKD_SPACONFIG_HPP
    #define RKNOCLD_SPACONFIG_HPP
    
    #include <libxml++/libxml++.h>
    #include "Config.hpp"

    namespace Rknockd
    {
        class SpaConfig; // forward declaration

        typedef std::vector<boost::uint8_t> SpaRequestString;
        
        struct SpaRequestPrinter
        {
            void operator() (std::ostream& os, const SpaRequestString& req) const;
        };
        
        struct SpaRequestParser
        {
            void operator() (SpaRequestString& req, const std::string& str, const Config*) const THROW((ConfigException));
        };
        
        typedef Request<SpaRequestString, SpaRequestPrinter, SpaRequestParser, SpaConfig> SpaRequest;

        class SpaConfig : public Config
        {
          public:
            SpaConfig(std::string& filename) THROW((ConfigException));
            virtual ~SpaConfig();
            const std::vector<SpaRequest>& getRequests() const;
            void printConfig(std::ostream& os) const;
          private:
            void parseRknockdAttrs(const xmlpp::Element* elmt) THROW((ConfigException));
            void addRequest(const xmlpp::Element* elmt) THROW((ConfigException));
            std::vector<SpaRequest> requests;
      
    
        };
        
    } //  namespace Rknockd

#endif /* RKNOCKD_SPACONFIG_HPP */
