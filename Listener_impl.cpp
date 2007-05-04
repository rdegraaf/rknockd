#include "Listener.hpp"

namespace Rknockd
{

    template <typename ReqType, typename RespType>
    Listener::HostRecord<ReqType, RespType>::HostRecord(const NFQ::NfqUdpPacket* pkt, boost::uint16_t target, const ReqType& req, const uint8_t* challenge, size_t clen) THROW((CryptoException))
    : HostRecordBase(pkt, target), request(req), response()
    {
        Listener::computeMAC(response, req.getSecret(), challenge, clen, saddr, daddr, req.getRequestString(), req.getIgnoreClientAddr());
    }

    template <typename ReqType, typename RespType>
    const ReqType&
    Listener::HostRecord<ReqType, RespType>::getRequest() const
    {
        return request;
    }

    template <typename ReqType, typename RespType>
    const RespType&
    Listener::HostRecord<ReqType, RespType>::getResponse() const
    {
        return response;
    }

    template <typename HostTableType>
    Listener::HostTableGC<HostTableType>::HostTableGC(HostTableType& table, bool verbose_logging)
    : table(table), gcQueue(), verbose(verbose_logging)
    {}


    template <typename HostTableType>
    void 
    Listener::HostTableGC<HostTableType>::schedule(AddressPair& addr, long secs, long usecs)
    {
        struct timeval time;
        struct itimerval itime;

        // calculate the GC execution time    
        (void)gettimeofday(&time, NULL);
        time.tv_usec += usecs;
        time.tv_sec += secs;
        if (time.tv_usec >= 1000000)
        {
            time.tv_sec += (time.tv_usec / 1000000);
            time.tv_usec %= 1000000;
        }

        // schedule the GC
        // it's safe to schedule before pushing to the queue, because the timer
        // interrupt is handled synchronously
        if (gcQueue.size() == 0)
        {
            itime.it_interval.tv_sec = 0;
            itime.it_interval.tv_usec = 0;
            itime.it_value.tv_sec = secs;
            itime.it_value.tv_usec = usecs;
            (void)setitimer(ITIMER_REAL, &itime, NULL);
        }
        gcQueue.push(std::make_pair(time, addr));
    }


    template <typename HostTableType>
    void
    Listener::HostTableGC<HostTableType>::operator()()
    {
        struct timeval curtime;

        (void)gettimeofday(&curtime, NULL);

        // delete old junk
        while (!gcQueue.empty() && (LibWheel::cmptime(&gcQueue.front().first, &curtime) < 0))
        {
            if (verbose && (table.find(gcQueue.front().second) != table.end()))
                LibWheel::logmsg(LibWheel::logmsg_info, "GC: deleting stale entry");
            table.erase(gcQueue.front().second);
            gcQueue.pop();
        }

        // schedule the next GC run
        if (!gcQueue.empty())
        {
            struct itimerval itime;
            itime.it_interval.tv_sec = 0;
            itime.it_interval.tv_usec = 0;
            LibWheel::subtime(&itime.it_value, &gcQueue.front().first, &curtime);
            (void)setitimer(ITIMER_REAL, &itime, NULL);
        }
    }

} // namespace Rknockd
