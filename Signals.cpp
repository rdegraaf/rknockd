/*#ifdef DEBUG
    #include <iostream>
#endif*/
#include <stdexcept>
#include <cerrno>
#include <cstring>
#include <csignal>
#include <boost/function.hpp>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include "Signals.hpp"

extern "C" void SignalQueue_signalHandler(int signum, siginfo_t*, void*);

namespace LibWheel
{
    SignalException::SignalException(int signum, const char* desc, const siginfo_t* info) throw()
    : description(desc), siginfo(info), number(signum)
    {}
    
    SignalException::SignalException(int signum, const char* desc) throw()
    : description(desc), siginfo(NULL), number(signum)
    {}
    
    SignalException::SignalException(int signum) throw()
    : description(), siginfo(NULL), number(signum)
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
    
    int
    SignalException::getSignalNumber() const throw()
    {
        return number;
    }

    Interrupt::Interrupt(const siginfo_t* info) throw()
    : SignalException(SIGINT, "SIGINT received", info)
    {}
    
    Interrupt::Interrupt() throw()
    : SignalException(SIGINT, "SIGINT received")
    {}
    
    int 
    Interrupt::getSignalNumber()
    {
        return SIGINT;
    }

    namespace SignalQueue
    {
    
        struct Pipe
        {
            int fds[2];
            Pipe() throw(std::runtime_error);
            ~Pipe();
          private:
            Pipe(const Pipe&);
            Pipe& operator= (const Pipe&);
        };

        Pipe::Pipe() throw(std::runtime_error)
        {
            int ret = pipe(fds);
            if (ret == -1)
                throw std::runtime_error(strerror(errno));
            ret = fcntl(fds[0], F_SETFL, O_NONBLOCK);
            if (ret == -1)
                throw std::runtime_error(strerror(errno));
            ret = fcntl(fds[1], F_SETFL, O_NONBLOCK);
            if (ret == -1)
                throw std::runtime_error(strerror(errno));
        }

        Pipe::~Pipe()
        {
            close(fds[0]);
            close(fds[1]);
        }

        static const Pipe& 
        getPipe()
        {
            static Pipe pipe;
            return pipe;
        }

        static boost::function<void()>* 
        getSignalTable()
        {
            static boost::function<void()> sigs[_NSIG];
            return sigs;
        }

        static int
        getWriteFD()
        {
            return getPipe().fds[1];
        }

        void 
        setHandler(int sig, Action act) throw(std::invalid_argument)
        {
            sighandler_t handler;

            switch (act)
            {
              case DEFAULT:
                handler = SIG_DFL;
                break;
              case IGNORE:
                handler = SIG_IGN;
                break;
              default:
                throw std::invalid_argument("Invalid action");
            }

            getSignalTable()[sig] = NULL;
            handler = signal(sig, handler);
            if (handler == SIG_ERR)
                throw std::invalid_argument("Invalid signal number");
        }


        void 
        setHandler(int sig, boost::function<void()> act) throw(std::invalid_argument)
        {
            struct sigaction handler;
            int ret;

            if ((sig < 1) || (sig > _NSIG))
                throw std::invalid_argument("Invalid signal number");

            getSignalTable()[sig] = act;

            // make sure that everything has been constructed
            (void)getPipe();

            // register the signal handler
            handler.sa_flags = SA_SIGINFO;
            handler.sa_sigaction = SignalQueue_signalHandler;
            sigemptyset(&handler.sa_mask);
            ret = sigaction(sig, &handler, NULL);
            if (ret == -1)
                throw std::invalid_argument("Invalid signal number");
        }

        void
        handleNext()
        {
            int ret;
            unsigned char signal;

            // get the signal 
            ret = read(getReadFD(), &signal, 1);
            if (ret != 1)
            {
                if (errno == EAGAIN)
                    return;
                else
                    throw std::runtime_error(strerror(errno));
            }
    
/*#ifdef DEBUG
            std::cout << "signal " << (int)signal << " received" << std::endl;
#endif*/
            if (getSignalTable()[signal] != NULL)
                (getSignalTable()[signal])();
        }

        void 
        handleAll()
        {
            while (pending())
                handleNext();
        }

        bool
        pending() throw(std::runtime_error)
        {
            struct timeval timeout;
            fd_set readfds;
            int ret;

            // call select() with a zero timeout to check if data is ready
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;
            FD_ZERO(&readfds);
            FD_SET(getReadFD(), &readfds);
            ret = ::select(getReadFD()+1, &readfds, NULL, NULL, &timeout);
            if (ret == -1)
                throw std::runtime_error(strerror(errno));
            else if (ret == 1)
                return true;
            else
                return false;
        }

        int 
        getReadFD()
        {
            return getPipe().fds[0];
        }

        int
        select(int n, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout)
        {
            fd_set rfd;
            int ret;
            int max_fd = (getReadFD() >= n) ? getReadFD()+1 : n;

            while (1)
            {
                if (readfds != NULL)
                    std::memcpy(&rfd, readfds, sizeof(rfd));
                else
                    FD_ZERO(&rfd);
                FD_SET(getReadFD(), &rfd);

                do
                {
                    ret = ::select(max_fd, &rfd, writefds, exceptfds, timeout);
                }
                while ((ret == -1) && (errno == EINTR));
                if (ret == -1)
                    return ret;
                else if (FD_ISSET(getReadFD(), &rfd))
                {
                    handleAll();
                    if (ret > 1)
                        return ret-1;
                }
                else
                    return ret;
            }
        }

    } // namespace SignalQueue

} // namespace LibWheel


// C++ signal handler conventions require that this be in the global namespace
extern "C" void SignalQueue_signalHandler(int signum, siginfo_t*, void*)
{
    char buf[1];
    buf[0] = signum;
    write(LibWheel::SignalQueue::getWriteFD(), buf, 1);
}

