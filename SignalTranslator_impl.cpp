#include "SignalTranslator.hpp"

namespace LibWheel
{

    template <typename SignalExceptionClass> 
    SignalTranslator<SignalExceptionClass>::Translator::Translator() throw(std::invalid_argument)
    {
        struct sigaction handler;
        int ret;

        handler.sa_flags = SA_SIGINFO;
        handler.sa_sigaction = signalHandler;
        sigemptyset(&handler.sa_mask);

        ret = sigaction(SignalExceptionClass::getSignalNumber(), &handler, NULL);
        if (ret == -1)
            throw std::invalid_argument("Invalid signal number");

    }
    
    template <typename SignalExceptionClass> 
    void 
    SignalTranslator<SignalExceptionClass>::Translator::signalHandler(int, siginfo_t* info, void*)
    {
        throw SignalExceptionClass(info);
    }

    template <typename SignalExceptionClass> 
    SignalTranslator<SignalExceptionClass>::SignalTranslator()
    {
        static Translator translator;
    }
    
}
