#ifndef RKNOCKD_SPACONFIG_HPP
    #define RKNOCLD_SPACONFIG_HPP
    
    #include <libxml++/libxml++.h>
    #include "Config.hpp"

    namespace Rknockd
    {
        class SpaConfig; // forward declaration

        class SpaRequest : public Request
        {
          public:
            SpaRequest(const xmlpp::Element* elmt, const SpaConfig& config) THROW((ConfigException));
            const std::vector<boost::uint8_t>& getRequestString() const;
            void printRequest(std::ostream& os) const;
          private:
            void getRequestString(const std::string& str, const Config* config) THROW((ConfigException));
            std::vector<boost::uint8_t> requestStr;

        };

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
