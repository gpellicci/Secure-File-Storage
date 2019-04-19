STRCPY(3)                  Linux Programmer's Manual                 STRCPY(3)

NNAAMMEE
       strcpy, strncpy - copy a string

SSYYNNOOPPSSIISS
       ##iinncclluuddee <<ssttrriinngg..hh>>

       cchhaarr **ssttrrccppyy((cchhaarr **_d_e_s_t,, ccoonnsstt cchhaarr **_s_r_c));;

       cchhaarr **ssttrrnnccppyy((cchhaarr **_d_e_s_t,, ccoonnsstt cchhaarr **_s_r_c,, ssiizzee__tt _n));;

DDEESSCCRRIIPPTTIIOONN
       The  ssttrrccppyy()  function  copies the string pointed to by _s_r_c, including
       the terminating null byte ('\0'), to the buffer  pointed  to  by  _d_e_s_t.
       The  strings  may  not overlap, and the destination string _d_e_s_t must be
       large enough to receive the copy.  _B_e_w_a_r_e  _o_f  _b_u_f_f_e_r  _o_v_e_r_r_u_n_s_!   (See
       BUGS.)

       The  ssttrrnnccppyy()  function is similar, except that at most _n bytes of _s_r_c
       are copied.  WWaarrnniinngg: If there is no null byte among the first _n  bytes
       of _s_r_c, the string placed in _d_e_s_t will not be null-terminated.

       If  the  length of _s_r_c is less than _n, ssttrrnnccppyy() writes additional null
       bytes to _d_e_s_t to ensure that a total of _n bytes are written.

       A simple implementation of ssttrrnnccppyy() might be:

           char *
           strncpy(char *dest, const char *src, size_t n)
           {
               size_t i;

               for (i = 0; i < n && src[i] != '\0'; i++)
                   dest[i] = src[i];
               for ( ; i < n; i++)
                   dest[i] = '\0';

               return dest;
           }

RREETTUURRNN VVAALLUUEE
       The ssttrrccppyy() and ssttrrnnccppyy() functions return a pointer to  the  destina‐
       tion string _d_e_s_t.

AATTTTRRIIBBUUTTEESS
       For   an   explanation   of   the  terms  used  in  this  section,  see
       aattttrriibbuutteess(7).

       ┌────────────────────┬───────────────┬─────────┐
       │IInntteerrffaaccee           │ AAttttrriibbuuttee     │ VVaalluuee   │
       ├────────────────────┼───────────────┼─────────┤
       │ssttrrccppyy(), ssttrrnnccppyy() │ Thread safety │ MT-Safe │
       └────────────────────┴───────────────┴─────────┘
CCOONNFFOORRMMIINNGG TTOO
       POSIX.1-2001, POSIX.1-2008, C89, C99, SVr4, 4.3BSD.

NNOOTTEESS
       Some programmers consider ssttrrnnccppyy() to be inefficient and error  prone.
       If  the  programmer knows (i.e., includes code to test!)  that the size
       of _d_e_s_t is greater than the length of _s_r_c, then ssttrrccppyy() can be used.

       One valid (and intended) use of ssttrrnnccppyy() is to copy a C  string  to  a
       fixed-length  buffer  while  ensuring both that the buffer is not over‐
       flowed and that unused bytes in the target buffer are zeroed out  (per‐
       haps  to  prevent  information  leaks if the buffer is to be written to
       media or transmitted to another process via an interprocess  communica‐
       tion technique).

       If  there  is  no  terminating  null  byte in the first _n bytes of _s_r_c,
       ssttrrnnccppyy() produces an unterminated string in _d_e_s_t.  If _b_u_f  has  length
       _b_u_f_l_e_n, you can force termination using something like the following:

           strncpy(buf, str, buflen - 1);
           if (buflen > 0)
               buf[buflen - 1]= '\0';

       (Of  course, the above technique ignores the fact that, if _s_r_c contains
       more than _b_u_f_l_e_n _- _1 bytes, information  is  lost  in  the  copying  to
       _d_e_s_t.)

   ssttrrllccppyy(())
       Some  systems  (the  BSDs,  Solaris,  and others) provide the following
       function:

           size_t strlcpy(char *dest, const char *src, size_t size);

       This function is similar to ssttrrnnccppyy(), but it  copies  at  most  _s_i_z_e_-_1
       bytes  to  _d_e_s_t,  always adds a terminating null byte, and does not pad
       the target with (further) null bytes.  This function fixes some of  the
       problems  of  ssttrrccppyy()  and ssttrrnnccppyy(), but the caller must still handle
       the possibility of data loss if _s_i_z_e is too small.  The return value of
       the function is the length of _s_r_c, which allows truncation to be easily
       detected: if the return value is greater than or equal to _s_i_z_e, trunca‐
       tion  occurred.   If loss of data matters, the caller _m_u_s_t either check
       the arguments before the call,  or  test  the  function  return  value.
       ssttrrllccppyy() is not present in glibc and is not standardized by POSIX, but
       is available on Linux via the _l_i_b_b_s_d library.

BBUUGGSS
       If the destination string of a ssttrrccppyy() is not large enough, then  any‐
       thing  might  happen.   Overflowing  fixed-length  string  buffers is a
       favorite cracker technique for taking complete control of the  machine.
       Any  time  a  program  reads  or copies data into a buffer, the program
       first needs to check that there's enough space.  This may  be  unneces‐
       sary  if you can show that overflow is impossible, but be careful: pro‐
       grams can get changed over time, in ways that may make  the  impossible
       possible.

SSEEEE AALLSSOO
       bbccooppyy(3),  mmeemmccccppyy(3),  mmeemmccppyy(3),  mmeemmmmoovvee(3),  ssttppccppyy(3), ssttppnnccppyy(3),
       ssttrrdduupp(3), ssttrriinngg(3), wwccssccppyy(3), wwccssnnccppyy(3)

CCOOLLOOPPHHOONN
       This page is part of release 4.15 of the Linux  _m_a_n_-_p_a_g_e_s  project.   A
       description  of  the project, information about reporting bugs, and the
       latest    version    of    this    page,    can     be     found     at
       https://www.kernel.org/doc/man-pages/.

GNU                               2017-09-15                         STRCPY(3)
