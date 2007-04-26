#ifndef LIBWHEEL_TIME_H
    #define LIBWHEEL_TIME_H

    #include <sys/time.h>

    #ifdef __cplusplus
    namespace LibWheel
    {
    #define LIBWHEEL_IDENT(name) name
    #else
    #define LIBWHEEL_IDENT(name) libwheel_ ## name
    #endif
    

    inline void LIBWHEEL_IDENT(addtime) (struct timeval* r, const struct timeval* a, const struct timeval* b)
    {
        r->tv_sec = a->tv_sec + b->tv_sec;
        r->tv_usec = a->tv_usec + b->tv_usec;
        if (r->tv_usec > 1000000)
        {
            r->tv_sec += (r->tv_usec / 1000000);
            r->tv_usec %= 1000000;
        }
    }
    
    inline void LIBWHEEL_IDENT(subtime) (struct timeval* r, const struct timeval* a, const struct timeval* b)
    {
        r->tv_sec = a->tv_sec - b->tv_sec;
        r->tv_usec = a->tv_usec - b->tv_usec;
        if (r->tv_usec < 0)
        {
            /* pentium 4 returns negative remainders for negative divisors... */
            r->tv_sec -= (1 - r->tv_usec / 1000000);
            r->tv_usec = r->tv_usec % 1000000 + 1000000;
        }
        if (r->tv_sec < 0)
        {
            r->tv_sec = 0;
            r->tv_usec = 0;
        }
    }
    
    inline int LIBWHEEL_IDENT(cmptime) (const struct timeval* a, const struct timeval* b)
    {
        if (a->tv_sec == b->tv_sec)
        {
            if (a->tv_usec == b->tv_usec)
                return 0;
            else if (a->tv_usec < b->tv_usec)
                return -1;
            else
                return 1;
        }
        else if (a->tv_sec < b->tv_sec)
            return -1;
        else
            return 1;
    }


    #ifdef __cplusplus
    }
    #endif
    #undef LIBWHEEL_IDENT

#endif /* LIBWHEEL_TIME_H */
