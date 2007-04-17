#include "SignalTranslator.hpp"

namespace LibWheel
{
    SignalException::SignalException(const char* desc, const siginfo_t* info) throw()
    : description(desc), siginfo(info)
    {}
    
    SignalException::~SignalException() throw() 
    {}
    
    const siginfo_t* 
    SignalException::getInfo() const throw()
    {
        return siginfo;
    }
    
    const char* 
    SignalException::what() const throw()
    {
        return description.c_str();
    }

    Interrupt::Interrupt(const siginfo_t* info) throw()
    : SignalException("SIGINT received", info)
    {}
    
    int 
    Interrupt::getSignalNumber()
    {
        return SIGINT;
    }

} // namespace LibWheel
