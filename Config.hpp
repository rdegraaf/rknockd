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
            const std::string& getName() const;
            friend std::ostream& operator<<(std::ostream&, const Protocol&);  
          private:
            Protocol(unsigned num, const std::string& n);
            unsigned number;
            std::string name;
        };
        std::ostream& operator<<(std::ostream& out, const Protocol& p);
            
        
        class Config
        {
          public:
            Config(std::string& name);
            virtual ~Config();
            const std::string& getFile() const;
            const std::string& getRandomDevice() const;
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
            boost::uint16_t nfQueueNum;
        };
        
        
        class RequestBase
        {
          public:
            RequestBase();
            virtual ~RequestBase();
            const Protocol& getProtocol() const;
            const boost::uint16_t getPort() const;
            const boost::uint32_t getAddr() const;
            const boost::uint16_t getTTL() const;
            const bool getIgnoreClientAddr() const;
            const std::string getSecret() const;
            virtual void printRequest(std::ostream& os) const;
            //RequestBase& operator=(const RequestBase& req);
          protected:
            void parseRequest(const xmlpp::Element* elmt, const Config* config) THROW((ConfigException));
            virtual void parseRequestString(const std::string& str, const Config* config) THROW((ConfigException)) = 0;
            
            Protocol proto;
            boost::uint16_t port;
            boost::uint16_t ttl;
            bool ignoreClientAddr;
            std::string secret;
        };
        
        template <typename RequestStrType, typename RequestPrinterType, typename RequestParserType, typename ConfigType>
        class Request : public RequestBase
        {
          public:
            typedef RequestStrType RequestString;
            Request(const xmlpp::Element* elmt, const ConfigType& config) THROW((ConfigException));
            const RequestStrType& getRequestString() const;
            void printRequest(std::ostream& os) const;
          private:
            void parseRequestString(const std::string& str, const Config* config) THROW((ConfigException));
            RequestStrType requestStr;
            static const RequestPrinterType requestPrinter;
            static const RequestParserType requestParser;
        };
        

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
            Request::printRequest(os);
        }

        template <typename RequestStrType, typename RequestPrinterType, typename RequestParserType, typename ConfigType>
        void 
        Request<RequestStrType, RequestPrinterType, RequestParserType, ConfigType>::parseRequestString(const std::string& str, const Config* cfg) THROW((ConfigException))
        {
            requestParser(requestStr, str, cfg);
        }
    }

#endif // RKNOCKD_CONFIG_HPP
