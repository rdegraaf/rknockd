#ifndef LIBWHEEL_SIGNALS_HPP
    #define LIBWHEEL_SIGNALS_HPP
    
    #include <list>
    #include <string>
    #include <stdexcept>
    #include <csignal>
    #include <boost/function.hpp>
    #include <sys/select.h>

    #ifndef THROW
        #ifdef DEBUG
            #define THROW(x) throw x
        #else
            #define THROW(x)
        #endif
    #endif

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
            enum Action {DEFAULT, IGNORE, HANDLE};
            void setHandler(int sig, Action act) THROW((std::domain_error, std::invalid_argument));
            void addHandler(int sig, boost::function<void()> act) THROW((std::invalid_argument));
            template <typename T> void deleteHandler(int sig, const T& act) THROW((std::invalid_argument));
            void deleteHandlers(int sig) THROW((std::invalid_argument));
            void handleNext();
            void handleAll();
            bool pending() THROW((std::runtime_error));
            int getReadFD();
            int select(int n, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout);


        std::list<boost::function<void()> >* getSignalTable();

        template <typename T>
        void 
        deleteHandler(int sig, const T& act) THROW((std::invalid_argument))
        {
            if ((sig < 1) || (sig > _NSIG))
                throw std::invalid_argument("Invalid signal number");
            
            std::list<boost::function<void()> >& list = getSignalTable()[sig];
            for (std::list<boost::function<void()> >::iterator i = list.begin(); i != list.end(); )
            {
                if (boost::function_equal(*i, act))
                    i = list.erase(i);
                else
                    ++i;
            }
        }


        } // namespace SignalQueue

    } // namespace LibWheel
    
#endif /* LIBWHEEL_SIGNAL_HPP */
