#define LOGMSG_CPP

#include <cstdarg>
#include "Logmsg.hpp"

namespace LibWheel
{
    Logmsg Logmsg::logmsg;

    Logmsg::Logmsg()
    : isopen(false)
    {}
    
    Logmsg::~Logmsg()
    {
        if (isopen)
            close();
    }

    bool
    Logmsg::isOpen() const
    {
        return isopen;
    }
    
    int
    Logmsg::open(logmsg_facility_t facility, unsigned options, const char* name)
    {
        int ret;
        
        // if logmsg is already open, close it and re-open
        if (isopen)
        {
            ret = logmsg_close();
            if (ret)
                return ret;
        }
        
        ret = logmsg_open(facility, options, name);
        if (ret == 0)
            isopen = true;
        return ret;
    }
    
    int Logmsg::close()
    {
        if (isopen)
        {
            isopen = false;
            return logmsg_close();
        }
        return 0;
    }
    
    int
    Logmsg::operator() (logmsg_priority_t priority, const char* format, ...)
    {
        if (isopen)
        {
            va_list args;
            int ret;
        
            va_start(args, format);
            ret = vlogmsg(priority, format, args);
            va_end(args);
            return ret;
        }
        return -1;
    }

} // namespace LibWheel
