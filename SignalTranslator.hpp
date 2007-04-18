#ifndef SIGNAL_TRANSLATOR_HPP
    #define SIGNAL_TRANSLATOR_HPP
    #include <exception>
    #include <string>
    #include <stdexcept>
    #include <csignal>
    #include <boost/utility.hpp>

    namespace LibWheel
    {
        template <typename SignalExceptionClass> class SignalTranslator : public boost::noncopyable
        {
            class Translator
            {
              public:
                Translator() throw(std::invalid_argument);
                static void signalHandler(int, siginfo_t* info, void*);
            };
          public:
            SignalTranslator();
        };

        class SignalException : public std::exception
        {
            const std::string description;
            const siginfo_t* siginfo;

          protected:
            SignalException(const char* desc, const siginfo_t* info) throw();

          public:
            virtual ~SignalException() throw();
            const siginfo_t* getInfo() const throw();
            virtual const char* what() const throw();
        };

        class Interrupt : public SignalException
        {
          public:
            explicit Interrupt(const siginfo_t* info) throw();
            static int getSignalNumber();
        };

    } // namespace LibWheel
    
    #include "SignalTranslator_impl.cpp"
#endif /* SIGNAL_TRANSLATOR_HPP */
