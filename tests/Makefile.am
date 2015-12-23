TESTS = check_hotp

check_PROGRAMS = check_hotp

check_hotp_SOURCES = check_hotp.c $(top_builddir)/src/otp.h
check_hotp_CFLAGS = @CHECK_CFLAGS@
check_hotp_LDADD = @OPENSSL_LIBS@ $(top_builddir)/src/libotp.a @CHECK_LIBS@
