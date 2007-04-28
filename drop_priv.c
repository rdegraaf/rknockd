/*************************************************
* drop_priv.c
* Copyright (c) Rennie deGraaf, 2005.  All rights reserved.
* $Id: drop_priv.c 15 2005-07-26 07:02:21Z degraaf $
*
* Functions to drop process privileges
* get_user_uid() - get a UID for a user name
* get_group_gid() - get a GID for a group name
* drop_priv() - set the current PID and GID
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

#define _BSD_SOURCE /* for setgroups(), setreuid(), setregid(), setegid(), seteuid() */

#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "logmsg.h"

/*****************************
uid_t get_user_uid(const char*)
Looks up the UID for a given user name
PARAMS:  const char* name - the user name to look up
RETURNS: the UID of the user name on success
         -1 on failure
Note: - not re-entrant 
*/
uid_t get_user_uid(const char* name)
{
    struct passwd* pw;
    pw = getpwnam(name);
    if (pw == NULL)
        return -1;
    return pw->pw_uid;
}

/*****************************
gid_t get_group_gid(const char*)
Looks up the GID for a given group name
PARAMS:  const char* name - the group name to look up
RETURNS: the UID of the group name on success
         -1 on failure
Note: - not re-entrant 
*/
gid_t get_group_gid(const char* name)
{
    struct group* gr;
    gr = getgrnam(name);
    if (gr == NULL)
        return -1;
    return gr->gr_gid;
}

/*****************************
void drop_priv(const uid_t, const gid_t)
Drops privileges to the given UID and GID.
PARAMS:  const uid_t newuid - the new UID to set, or -1 to leave unchanged
         const gid_t newgid - the new GID to set, or -1 to leave unchanged
Note: - This was designed to permanently drop privileges from a superuser 
    process.  It may also work for permanently dropping privileges in a 
    SETUID process.
    - This function may not work properly on BSD.
    - aborts on failure, sends error messages through the logmsg facility.
*/
void drop_priv(const uid_t newuid, const gid_t newgid)
{
    uid_t olduid;
    gid_t oldgid;
    int retval;
    
    /* get current user and group */
    olduid = geteuid();
    oldgid = getegid();
    
    if (newgid != (gid_t)-1)
    {
        /* if we have superuser privileges, drop ancillary groups */
        if (olduid == 0)
        {
            retval = setgroups(1, &newgid);
            if (retval == -1)
            {
                LOGMSG_LIB(setgroups);
                LOGMSG_FATAL_EXIT();
                abort();
            }
        }
        
        /* make sure it isn't the current gid */
        if (newgid != oldgid)
        {        
            /* change gid */
            retval = setregid(newgid, newgid);
            if (retval == -1)
            {
                LOGMSG_LIB(setregid);
                LOGMSG_FATAL_EXIT();
                abort();
            }
        }
    }

    if (newuid != (uid_t)-1)
    {
        /* make sure it isn't the current uid */
        if (newuid != olduid)
        {
            /* change uid */
            retval = setreuid(newuid, newuid);
            if (retval == -1)
            {
                LOGMSG_LIB(setreuid);
                LOGMSG_FATAL_EXIT();
                abort();
            }
        }
    }
    
    /* make sure privileges cannot be regained */
    if (newgid != (gid_t)-1 && oldgid != newgid && newuid != 0)
    {
        if (setegid(oldgid) != -1 || getegid() != newgid)
        {
            logmsg(logmsg_crit, "drop_priv: new GID not set correctly (%s:%i)", __FILE__, __LINE__);
            LOGMSG_FATAL_EXIT();
            abort();
        }
    }
    if (newuid != (uid_t)-1 && olduid != newuid)
    {
        if (seteuid(olduid) != -1 || geteuid() != newuid)
        {
            logmsg(logmsg_crit, "drop_priv: new UID not set correctly (%s:%i)", __FILE__, __LINE__);
            LOGMSG_FATAL_EXIT();
            abort();
        }
    }
}
