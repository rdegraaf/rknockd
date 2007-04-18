/*
Copyright (c) 2003, Matt Messier, John Viega.  All rights reserved.
Copyright (c) 2005, Rennie deGraaf.  All rights reserved.
$Id: spc_sanitize.h 14 2005-07-26 02:00:59Z degraaf $

Functions to sanitize the system environment
See spc_sanitize.c for further details.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met: 

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

3. Neither the name of the author nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
Taken from "Secure Programming Cookbook for C and C++ by Matt Messier and 
John Viega, on-line source at 
http://www.secureprogramming.com/?action=downloads&bookid=1
Modified by Rennie deGraaf, 2005/07/22 
*/

#ifndef LIBWHEEL_H
#define LIBWHEEL_H

#ifdef __cplusplus
extern "C" {
#endif

void spc_sanitize_environment(int preservec, char **preservev);
void spc_sanitize_files(void); 

#ifdef __cplusplus
}
#endif

#endif /* LIBWHEEL_H */
