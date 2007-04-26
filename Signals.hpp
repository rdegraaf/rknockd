#ifndef SIGNALS_HPP
    #define SIGNALS_HPP
    #include <string>
    #include <stdexcept>
    #include <csignal>
    #include <boost/function.hpp>
    #include <sys/select.h>

    namespace LibWheel
    {
        class SignalException : public std::exception
        {
            const std::string description;
            const siginfo_t* siginfo;
            const int number;

          protected:
            SignalException(int signum) throw();
            SignalException(int signum, const char* desc) throw();
            SignalException(int signum, const char* desc, const siginfo_t* info) throw();

          public:
            virtual ~SignalException() throw();
            const siginfo_t* getInfo() const throw();
            virtual const char* what() const throw();
            int getSignalNumber() const throw();
        };

        class Interrupt : public SignalException
        {
          public:
            Interrupt() throw();
            explicit Interrupt(const siginfo_t* info) throw();
            static int getSignalNumber();
        };

        namespace SignalQueue
        {
            enum Action {DEFAULT, IGNORE};
            void setHandler(int sig, Action act) throw(std::invalid_argument);
            void setHandler(int sig, boost::function<void()> act) throw(std::invalid_argument);
            void handleNext();
            void handleAll();
            bool pending() throw(std::runtime_error);
            int getReadFD();
            int select(int n, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout);
        } // namespace SignalQueue

    } // namespace LibWheel
    
#endif /* SIGNAL_HPP */
