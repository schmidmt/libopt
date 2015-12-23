AM_CFLAGS = $(MORE_CFLAGS)
AM_CPPFLAGS = $(MORE_CPPFLAGS)
AM_LDFLAGS = $(MORE_LDFLAGS)

instdir = $(PREFIX)/lib
inst_LIBRARIES = libotp.a

lib_LTLIBRARIES = libotp.la

libotp_a_SOURCES  = otp.h otp.c
libotp_a_CFLAGS   = $(AM_CFLAGS) @OPENSSL_CFLAGS@
# otp_a_LDFLAGS  = $(AM_LDFLAGS) @OPENSSL_LIBS@

libotp_la_SOURCES = otp.h otp.c
libotp_la_CFLAGS = $(AM_CFLAGS) @OPENSSL_CFLAGS@
libotp_la_LIBADD = @OPENSSL_LIBS@

include_HEADERS = otp.h
