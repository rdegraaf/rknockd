/*************************************************
* logmsg.c
* Copyright (c) Rennie deGraaf, 2005-2007.  All rights reserved.
* $Id: logmsg.c 14 2005-07-26 02:00:59Z degraaf $
*
* Generic system for logging error or status messages to various targets.
* Currently, valid targets are stdout, stderr, syslog, or any file.  The 
* default target is stderr.  Messages are formatted along syslog conventions.
*
* Note: this facility is not re-entrant.  Be careful using it in a multi-
* threaded environment.
*
* logmsg_open() - open the logmsg facility
* logmsg() - write a message to the current log
* logmsg_close() - close the logmsg facility
*
* This file is part of the libwheel project.
*
* libwheel is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* libwheel is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with libwheel; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
**************************************************/

#include <syslog.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include "logmsg.h"

/* internal logmsg configuration object */
typedef struct 
{
    logmsg_facility_t facility;
    unsigned options;
    const char* name;
    FILE* file;
} logmsg_t;

/* string equivalents for values of logmsg_priority_t */
static const char* _priority_tag[] = 
{
    "Emergency:",
    "Alert:",
    "Critical:",
    "Error:",
    "Warning:",
    "Notice:",
    "Info:",
    "Debug:"
};

/* syslog priority equivalents for values of logmsg_priority_t */
static const int _priority_id[] = 
{
    LOG_EMERG,
    LOG_ALERT,
    LOG_CRIT,
    LOG_ERR,
    LOG_WARNING,
    LOG_NOTICE,
    LOG_INFO,
    LOG_DEBUG
};

/* global logmsg configuration object */
static logmsg_t _log_config = {logmsg_stderr, 0, "", NULL};


/*****************************
int logmsg_open(logmst_facility_t, unsigned, const char*)
Initializes the logmsg facility.
PARAMS:  logmsg_facility_t facility - the logging facility to use
         unsigned options - a set of option flags
         const char* name - a string whose purpose is determined by the value 
            of facility:
            file -> the name of the file to use
            syslog, stdout, stderr -> a string to prepend to each log message
RETURNS: 0 on success
         1 on failure, with errno set appropriately.
*/
int logmsg_open(logmsg_facility_t facility, unsigned options, const char* name)
{
    int syslog_opt = 0;
    _log_config.facility = facility;
    _log_config.options = options;
    _log_config.name = name;
    _log_config.file = NULL;
    
    switch (_log_config.facility)
    {
        case logmsg_stdout:
            _log_config.file = stdout;
            break;
        case logmsg_stderr:
            _log_config.file = stderr;
            break;
        case logmsg_syslog:
            if (_log_config.options & LOGMSG_PID)
                syslog_opt |= LOG_PID;
            openlog(name, syslog_opt, LOG_USER);
            break;
        case logmsg_file:
            _log_config.file = fopen(name, "a");
            if (_log_config.file == NULL)
                return -1;
            break;
    }
    
    return 0;
}


/*****************************
int logmsg(logmsg_priority_t, const char*, ...)
Prints a message to the appropriate destination.  The message is formatted 
according to syslog() conventions.
PARAMS:  logmsg_priority_t priority - the priority of the message.  How this is 
            interpreted depends on the facility:
            file, stdout, stderr -> prepends a string indicating the priority
            syslog -> uses te equivalent syslog priority
         const char* format - a printf()-style format string, followed by 
            arguments.
Returns: 0 on success
         -1 on failure
*/
int logmsg(logmsg_priority_t priority, const char* format, ...)
{
    va_list args;
    int ret;
    
    va_start(args, format);
    ret = vlogmsg(priority, format, args);
    va_end(args);
    
    return ret;
}


/*****************************
int vlogmsg(logmsg_priority_t, const char*, va_list)
Prints a message to the appropriate destination.  The message is formatted 
according to syslog() conventions.
PARAMS:  logmsg_priority_t priority - the priority of the message.  How this is 
            interpreted depends on the facility:
            file, stdout, stderr -> prepends a string indicating the priority
            syslog -> uses te equivalent syslog priority
         const char* format - a printf()-style format string
         va_list args - arguments to *format
Returns: 0 on success
         -1 on failure
*/
int vlogmsg(logmsg_priority_t priority, const char* format, va_list args)
{
    time_t t;
    struct tm tm;
    char timebuf[100];
    int ret;
    
    /* safety check, in case logmsg is called without first calling logmsg_open */
    if (_log_config.file == NULL)
        _log_config.file = stderr;
    
    switch (_log_config.facility)
    {
        case logmsg_stdout:
        case logmsg_stderr:
        case logmsg_file:
            /* print the time */
            t = time(NULL);
            localtime_r(&t, &tm);
            strftime(timebuf, 100, "%b %d %T ", &tm);
            ret = fputs(timebuf, _log_config.file);
            if (ret == EOF) return -1;
        
            /* print name for stdout and stderr */
            if (_log_config.facility == logmsg_stdout || _log_config.facility == logmsg_stderr)
            {
                ret = fputs(_log_config.name, _log_config.file);
                if (ret == EOF) return -1;
                ret = fputc(' ', _log_config.file);
                if (ret == EOF) return -1;
            }

            /* print the PID, if LOGMSG_PID is set */
            if (_log_config.options & LOGMSG_PID)
            {
                char buf[30];
                snprintf(buf, 30, "[%i] ", getpid());
                ret = fputs(buf, _log_config.file);
                if (ret == EOF) return -1;
            }
            
            /* print the priority */
            ret = fputs(_priority_tag[priority], _log_config.file);
            if (ret == EOF) return -1;           
            ret = fputc(' ', _log_config.file);
            if (ret == EOF) return -1;
            
            /* print the actual message */
            ret = vfprintf(_log_config.file, format, args);
            if (ret < 0) return -1;
            ret = fputc('\n', _log_config.file);
            if (ret == EOF) return -1;
            break;
        case logmsg_syslog:
            vsyslog(_priority_id[priority], format, args);
            break;
    }
    
    return 0;
}    


/*****************************
void logmsg_close()
Shuts down the logmsg facility, in a manner appropriate to the facility
Returns: 0 on success
         EOF on failure, with errno set appropriately
*/
int logmsg_close()
{
    switch (_log_config.facility)
    {
        case logmsg_stdout:
            return 0;
        case logmsg_stderr:
            return 0;
        case logmsg_syslog:
            closelog();
            return 0;
        case logmsg_file:
            return fclose(_log_config.file);
        default:
            return EOF;
    }
}
