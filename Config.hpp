#ifndef RKNOCKD_CONFIG_HPP
    #define RKNOCKD_CONFIG_HPP

    #include <stdexcept>
    #include <string>
    #include <vector>
    #include <set>
    #include <iostream>
    #include <libxml++/libxml++.h>
    #include <boost/cstdint.hpp>
    #include "common.h"
    
    namespace Rknockd
    {
        class ConfigException : public std::runtime_error
        {
          public:
            ConfigException(const std::string& d);
        };
        
        class Protocol
        {
          public:
            static const Protocol TCP;
            static const Protocol UDP;
            
            Protocol(const Protocol& p);
            Protocol& operator=(const Protocol& p);
            bool operator==(unsigned num) const;
            bool operator==(const Protocol& p) const;
            bool operator!=(unsigned num) const;
            bool operator!=(const Protocol& p) const;
            unsigned getNumber() const;
            friend std::ostream& operator<<(std::ostream&, const Protocol&);  
          private:
            Protocol(unsigned num, const std::string& n);
            unsigned number;
            std::string name;
        };
        std::ostream& operator<<(std::ostream& out, const Protocol& p);
            
        
        class Config; // forward declaration
        
        class Request
        {
          public:
            Request();
            virtual ~Request();
            const Protocol& getProtocol() const;
            const boost::uint16_t getPort() const;
            const boost::uint32_t getAddr() const;
            const boost::uint16_t getTTL() const;
            const bool getIgnoreClientAddr() const;
            const std::string getSecret() const;
            virtual void printRequest(std::ostream& os) const;
            Request& operator=(const Request& req);
          protected:
            void parseRequest(const xmlpp::Element* elmt, const Config* config) THROW((ConfigException));
            virtual void getRequestString(const std::string& str, const Config* config) THROW((ConfigException)) = 0;
            
            Protocol proto;
            boost::uint16_t port;
            boost::uint16_t ttl;
            bool ignoreClientAddr;
            std::string secret;
        };
        
        class Config
        {
          public:
            Config(std::string& name);
            virtual ~Config();
            const std::string& getFile() const;
            const std::string& getRandomDevice() const;
            const int getRandomFD() const;
            const boost::uint16_t getBasePort() const;
            const unsigned getChallengeBytes() const;
            const boost::uint16_t getNfQueueNum() const;
            virtual void printConfig(std::ostream& os) const;
          protected:
            void readFile() THROW((ConfigException));
            virtual void parseRknockdAttrs(const xmlpp::Element* elmt) THROW((ConfigException));
            void parseRknockdChildren(const xmlpp::Element* elmt) THROW((ConfigException));
            virtual void addRequest(const xmlpp::Element* elmt) THROW((ConfigException)) = 0;
            
            std::string file;       // the name of the configuration file
            boost::uint16_t basePort;     // the low-numbered port of the knock range
            unsigned challengeBytes; // the number of bytes to send in a challenge
            std::string randomDevice;     // the name of the random number device
            int randomFD;
            boost::uint16_t nfQueueNum;
        };
        
    }

#endif // RKNOCKD_CONFIG_HPP
