#ifndef RKNOCKD_PKCONFIG_HPP
    #define RKNOCKD_PKCONFIG_HPP
    
    #include <set>
    #include <stdexcept>
    #include <boost/cstdint.hpp>
    #include <boost/lexical_cast.hpp>
    #include <boost/static_assert.hpp>
    #include <libxml++/libxml++.h>
    #include "Config.hpp"

    namespace Rknockd
    {
        typedef std::set<boost::uint16_t> KnockSequence;
        
        struct KnockSequencePrinter
        {
            void operator() (std::ostream& os, const KnockSequence& req) const;
        };
        
        struct KnockSequenceParser
        {
            void operator() (KnockSequence& req, const std::string& str, const Config* config) const THROW((ConfigException));

            template <typename Container>
            static void generateKnockSequence(KnockSequence& seq, const Container& cont, boost::uint16_t base_port, unsigned bits_per_knock) THROW((std::out_of_range));
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
        typedef Request<KnockSequence, KnockSequencePrinter, KnockSequenceParser, PKConfig> PKRequest;


        class PKConfig : public Config
        {
          public:
            typedef std::vector<PKRequest> RequestList;
            PKConfig(const std::string& filename) THROW((ConfigException));
            virtual ~PKConfig();
            const boost::uint8_t getMaxKnocks() const;
            const unsigned getBitsPerKnock() const;
            const RequestList& getRequests() const;
            void printConfig(std::ostream& os) const;
          private:
            void parseRknockdAttrs(const xmlpp::Element* elmt) THROW((ConfigException));
            void addRequest(const xmlpp::Element* elmt) THROW((ConfigException));
            boost::uint8_t maxKnocks;
            unsigned bitsPerKnock;
            std::vector<PKRequest> requests;
      
    
        };

        template <typename Container>
        void
        KnockSequenceParser::generateKnockSequence(KnockSequence& seq, const Container& cont, boost::uint16_t base_port, unsigned bits_per_knock) THROW((std::out_of_range))
        {
            unsigned bits = 0;
            unsigned knock = 0;
            unsigned tmp;
            int count=0;

            assert(bits_per_knock <= 16);
            BOOST_STATIC_ASSERT(sizeof(typename Container::value_type) == sizeof(boost::uint8_t));

            for (typename Container::const_iterator iter=cont.begin(); iter!=cont.end(); )
            {
                while ((bits < bits_per_knock) && (iter != cont.end()))
                {
                    knock <<= 8;
                    knock |= *iter;
                    iter++;
                    bits += 8;
                }
                if (bits >= bits_per_knock)
                {
                    tmp = base_port + (knock >> (bits - bits_per_knock)) + count*(1<<bits_per_knock);
                    if (tmp > 65535)
                        throw std::out_of_range(std::string("Knock value ") + boost::lexical_cast<std::string, unsigned>(tmp) + " out of range");
                    count++;
                    bits -= bits_per_knock;
                    knock &= ((1<<bits)-1);
                    seq.insert(tmp);
                }
            }
            if (bits > 0)
            {
                tmp = base_port + knock + count*(1<<bits_per_knock);
                if (tmp > 65535)
                    throw std::out_of_range(std::string("Knock value ") + boost::lexical_cast<std::string, unsigned>(tmp) + " out of range");
                seq.insert(tmp);
            }
        }


    } //  namespace Rknockd

#endif /* RKNOCKD_PKCONFIG_HPP */
