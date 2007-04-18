/*************************************************
* logmsg.h
* Copyright (c) Rennie deGraaf, 2005-2007.  All rights reserved.
* $Id: logmsg.h 14 2005-07-26 02:00:59Z degraaf $
*
* Generic system for logging error or status messages to various targets.
* See logmsg.c for further details.
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

#ifndef LOGMSG_H
#define LOGMSG_H

#ifdef __cplusplus
    #include <cstring>
    #include <cstdarg>
    #include <cerrno>
    using std::strerror;
    using std::va_list;
#else
    #include <errno.h>
    #include <string.h>
    #include <stdarg.h>
#endif

#ifdef __cplusplus
namespace LibWheel
{
#endif

/* valid log facilities */
typedef enum
{
    logmsg_stderr,
    logmsg_stdout,
    logmsg_syslog,
    logmsg_file
} logmsg_facility_t;

/* valid log priorities */
typedef enum
{
    logmsg_emerg,
    logmsg_alert,
    logmsg_crit,
    logmsg_err,
    logmsg_warning,
    logmsg_notice,
    logmsg_info,
    logmsg_debug
} logmsg_priority_t;

/* flags for logmsg options */
#define LOGMSG_PID 1

#ifdef __cplusplus
extern "C" {
#endif

#if (!defined LOGMSG_HPP || defined LOGMSG_CPP) /* don't pollute the C++ namespace */
int logmsg_open(logmsg_facility_t facility, unsigned options, const char* name);
int logmsg(logmsg_priority_t priority, const char* format, ...) __attribute__((format(printf, 2, 3)));
int vlogmsg(logmsg_priority_t priority, const char* format, va_list args);
int logmsg_close();
#endif

/* shortcut to log library function errors */
#define LOGMSG_LIB(FUNC) logmsg(logmsg_err, "%s: %s (%s:%i)", #FUNC, strerror(errno), __FILE__, __LINE__)

/* shortcut to log a fatal exit message */
#define LOGMSG_FATAL_EXIT() logmsg(logmsg_notice, "Exiting due to fatal error")

#ifdef __cplusplus
}}
#endif

#endif /* LOGMSG_H */
