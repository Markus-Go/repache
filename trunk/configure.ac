#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(repache, 0.3, matthias.reif@iupr.dfki.de)
AM_INIT_AUTOMAKE(repache, 0.3)
AC_OUTPUT(Makefile src/Makefile man/Makefile)
AC_CONFIG_SRCDIR(src/RawTcpSocket.h)
AM_CONFIG_HEADER(config.h)

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB(pthread, pthread_create)
AC_CHECK_LIB(pcap, pcap_open_live)

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h sys/socket.h sys/time.h unistd.h],,AC_MSG_ERROR(header missing))

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_HEADER_STDC
AC_FUNC_MKTIME
AC_CHECK_FUNCS([gettimeofday inet_ntoa memset socket],,AC_MSG_ERROR(function missing))

AC_OUTPUT
