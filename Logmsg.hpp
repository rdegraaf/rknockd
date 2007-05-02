#ifndef LOGMSG_HPP
    #define LOGMSG_HPP
    
    #include <boost/utility.hpp>
    #include "logmsg.h"
        
    namespace LibWheel
    {
        class Logmsg : public boost::noncopyable
        {
          public:
            bool isOpen() const;
            int open(logmsg_facility_t facility, unsigned options, const char* name);
            int operator() (logmsg_priority_t priority, const char* format, ...) __attribute__((format (printf, 3, 4)));
            int close();
            static Logmsg logmsg;
          private:
            Logmsg();
            ~Logmsg();
            bool isopen;
        };
#ifndef LOGMSG_CPP
        static Logmsg& logmsg = Logmsg::logmsg;
#endif
    
    } // namespace LibWheel
    
#endif /* LOGMSG_HPP */
