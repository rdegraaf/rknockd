#include <libxml++/libxml++.h>
#include "Config.hpp"

#ifndef RKNOCKD_PKCONFIG_HPP
    #define RKNOCKD_PKCONFIG_HPP
    
    namespace Rknockd
    {
        typedef std::set<boost::uint16_t> PKRequestString;
        
        struct PKRequestPrinter
        {
            void operator() (std::ostream& os, const PKRequestString& req) const;
        };
        
        struct PKRequestParser
        {
            void operator() (PKRequestString& req, const std::string& str, const Config* config) const THROW((ConfigException));
        };
        
        class PKConfig; // forward declaration

        /*class PKRequest : public Request
        {
          public:
            PKRequest(const xmlpp::Element* elmt, const PKConfig& config) THROW((ConfigException));
            const std::vector<boost::uint16_t>& getKnocks() const;
            const std::set<boost::uint16_t>& getEncodedKnocks() const;
            void printRequest(std::ostream& os) const;
          private:
            void parseRequestString(const std::string& str, const Config* config) THROW((ConfigException));
            std::vector<boost::uint16_t> knocks;
            std::set<boost::uint16_t> encodedKnocks;

        };*/
        typedef Request<PKRequestString, PKRequestPrinter, PKRequestParser, PKConfig> PKRequest;


        class PKConfig : public Config
        {
          public:
            PKConfig(const std::string& filename) THROW((ConfigException));
            virtual ~PKConfig();
            const boost::uint8_t getMaxKnocks() const;
            const unsigned getBitsPerKnock() const;
            const std::vector<PKRequest>& getRequests() const;
            void printConfig(std::ostream& os) const;
          private:
            void parseRknockdAttrs(const xmlpp::Element* elmt) THROW((ConfigException));
            void addRequest(const xmlpp::Element* elmt) THROW((ConfigException));
            boost::uint8_t maxKnocks;
            unsigned bitsPerKnock;
            std::vector<PKRequest> requests;
      
    
        };

    } //  namespace Rknockd

#endif /* RKNOCKD_PKCONFIG_HPP */
