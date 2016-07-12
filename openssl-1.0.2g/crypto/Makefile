#
# OpenSSL/crypto/Makefile
#

DIR=		crypto
TOP=		..
CC=		cc
INCLUDE=	-I. -I$(TOP) -I../include $(ZLIB_INCLUDE)
# INCLUDES targets sudbirs!
INCLUDES=	-I.. -I../.. -I../modes -I../asn1 -I../evp -I../../include $(ZLIB_INCLUDE)
CFLAG=		-g
MAKEDEPPROG=	makedepend
MAKEDEPEND=	$(TOP)/util/domd $(TOP) -MD $(MAKEDEPPROG)
MAKEFILE=       Makefile
RM=             rm -f
AR=		ar r

RECURSIVE_MAKE=	[ -n "$(SDIRS)" ] && for i in $(SDIRS) ; do \
		    (cd $$i && echo "making $$target in $(DIR)/$$i..." && \
		    $(MAKE) -e TOP=../.. DIR=$$i INCLUDES='$(INCLUDES)' $$target ) || exit 1; \
		done;

PEX_LIBS=
EX_LIBS=
 
CFLAGS= $(INCLUDE) $(CFLAG)
ASFLAGS= $(INCLUDE) $(ASFLAG)
AFLAGS=$(ASFLAGS)
CPUID_OBJ=mem_clr.o

LIBS=

GENERAL=Makefile README crypto-lib.com install.com
TEST=constant_time_test.c

LIB= $(TOP)/libcrypto.a
SHARED_LIB= libcrypto$(SHLIB_EXT)
LIBSRC=	cryptlib.c mem.c mem_clr.c mem_dbg.c cversion.c ex_data.c cpt_err.c \
	ebcdic.c uid.c o_time.c o_str.c o_dir.c o_fips.c o_init.c fips_ers.c
LIBOBJ= cryptlib.o mem.o mem_dbg.o cversion.o ex_data.o cpt_err.o ebcdic.o \
	uid.o o_time.o o_str.o o_dir.o o_fips.o o_init.o fips_ers.o $(CPUID_OBJ)

SRC= $(LIBSRC)

EXHEADER= crypto.h opensslv.h opensslconf.h ebcdic.h symhacks.h \
	ossl_typ.h
HEADER=	cryptlib.h buildinf.h md32_common.h o_time.h o_str.h o_dir.h \
	constant_time_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	@(cd ..; $(MAKE) DIRS=$(DIR) all)

all: shared

buildinf.h: ../Makefile
	$(PERL) $(TOP)/util/mkbuildinf.pl "$(CC) $(CFLAGS)" "$(PLATFORM)" >buildinf.h

x86cpuid.s:	x86cpuid.pl perlasm/x86asm.pl
	$(PERL) x86cpuid.pl $(PERLASM_SCHEME) $(CFLAGS) $(PROCESSOR) > $@

applink.o:	$(TOP)/ms/applink.c
	$(CC) $(CFLAGS) -c -o $@ $(TOP)/ms/applink.c

uplink.o:	$(TOP)/ms/uplink.c applink.o
	$(CC) $(CFLAGS) -c -o $@ $(TOP)/ms/uplink.c

uplink-x86.s:	$(TOP)/ms/uplink-x86.pl
	$(PERL) $(TOP)/ms/uplink-x86.pl $(PERLASM_SCHEME) > $@

x86_64cpuid.s: x86_64cpuid.pl;	$(PERL) x86_64cpuid.pl $(PERLASM_SCHEME) > $@
ia64cpuid.s: ia64cpuid.S;	$(CC) $(CFLAGS) -E ia64cpuid.S > $@
ppccpuid.s:	ppccpuid.pl;	$(PERL) ppccpuid.pl $(PERLASM_SCHEME) $@
pariscid.s:	pariscid.pl;	$(PERL) pariscid.pl $(PERLASM_SCHEME) $@
alphacpuid.s:	alphacpuid.pl
	(preproc=$$$$.$@.S; trap "rm $$preproc" INT; \
	$(PERL) alphacpuid.pl > $$preproc && \
	$(CC) -E -P $$preproc > $@ && rm $$preproc)

testapps:
	[ -z "$(THIS)" ] || (	if echo $(SDIRS) | fgrep ' des '; \
				then cd des && $(MAKE) -e des; fi )
	[ -z "$(THIS)" ] || ( cd pkcs7 && $(MAKE) -e testapps );
	@if [ -z "$(THIS)" ]; then $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; fi

subdirs:
	@target=all; $(RECURSIVE_MAKE)

files:
	$(PERL) $(TOP)/util/files.pl "CPUID_OBJ=$(CPUID_OBJ)" Makefile >> $(TOP)/MINFO
	@target=files; $(RECURSIVE_MAKE)

links:
	@$(PERL) $(TOP)/util/mklink.pl ../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../apps $(APPS)
	@target=links; $(RECURSIVE_MAKE)

# lib: $(LIB): are splitted to avoid end-less loop
lib:	$(LIB)
	@touch lib
$(LIB):	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	test -z "$(FIPSLIBDIR)" || $(AR) $(LIB) $(FIPSLIBDIR)fipscanister.o
	$(RANLIB) $(LIB) || echo Never mind.

shared: buildinf.h lib subdirs
	if [ -n "$(SHARED_LIBS)" ]; then \
		(cd ..; $(MAKE) $(SHARED_LIB)); \
	fi

libs:
	@target=lib; $(RECURSIVE_MAKE)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ;\
	do \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;
	@target=install; $(RECURSIVE_MAKE)

lint:
	@target=lint; $(RECURSIVE_MAKE)

update: local_depend
	@[ -z "$(THIS)" ] || (set -e; target=update; $(RECURSIVE_MAKE) )
	@if [ -z "$(THIS)" ]; then $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; fi

depend: local_depend
	@[ -z "$(THIS)" ] || (set -e; target=depend; $(RECURSIVE_MAKE) )
	@if [ -z "$(THIS)" ]; then $(MAKE) -f $(TOP)/Makefile reflect THIS=$@; fi
local_depend:
	@[ -z "$(THIS)" -o -f buildinf.h ] || touch buildinf.h # fake buildinf.h if it does not exist
	@[ -z "$(THIS)" ] || $(MAKEDEPEND) -- $(CFLAG) $(INCLUDE) $(DEPFLAG) -- $(PROGS) $(LIBSRC)
	@[ -z "$(THIS)" -o -s buildinf.h ] || rm buildinf.h

clean:
	rm -f buildinf.h *.s *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff
	@target=clean; $(RECURSIVE_MAKE)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)
	rm -f opensslconf.h
	@target=dclean; $(RECURSIVE_MAKE)

# DO NOT DELETE THIS LINE -- make depend depends on it.

cpt_err.o: ../include/openssl/bio.h ../include/openssl/crypto.h
cpt_err.o: ../include/openssl/e_os2.h ../include/openssl/err.h
cpt_err.o: ../include/openssl/lhash.h ../include/openssl/opensslconf.h
cpt_err.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
cpt_err.o: ../include/openssl/safestack.h ../include/openssl/stack.h
cpt_err.o: ../include/openssl/symhacks.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
cpt_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
cpt_err.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
cpt_err.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
cpt_err.o: cpt_err.c
cryptlib.o: ../e_os.h ../include/openssl/bio.h ../include/openssl/buffer.h
cryptlib.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
cryptlib.o: ../include/openssl/err.h ../include/openssl/lhash.h
cryptlib.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
cryptlib.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
cryptlib.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
cryptlib.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
cryptlib.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
cryptlib.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
cryptlib.o: cryptlib.c cryptlib.h
cversion.o: ../e_os.h ../include/openssl/bio.h ../include/openssl/buffer.h
cversion.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
cversion.o: ../include/openssl/err.h ../include/openssl/lhash.h
cversion.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
cversion.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
cversion.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
cversion.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
cversion.o: buildinf.h
cversion.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
cversion.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
cversion.o: cryptlib.h cversion.c
ebcdic.o: ../include/openssl/e_os2.h ../include/openssl/opensslconf.h ebcdic.c
ex_data.o: ../e_os.h ../include/openssl/bio.h ../include/openssl/buffer.h
ex_data.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
ex_data.o: ../include/openssl/err.h ../include/openssl/lhash.h
ex_data.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
ex_data.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
ex_data.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
ex_data.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
ex_data.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
ex_data.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
ex_data.o: cryptlib.h ex_data.c
fips_ers.o: ../include/openssl/opensslconf.h fips_ers.c
mem.o: ../e_os.h ../include/openssl/bio.h ../include/openssl/buffer.h
mem.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
mem.o: ../include/openssl/err.h ../include/openssl/lhash.h
mem.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
mem.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
mem.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
mem.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
mem.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
mem.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
mem.o: cryptlib.h mem.c
mem_clr.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
mem_clr.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
mem_clr.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
mem_clr.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
mem_clr.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
mem_clr.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
mem_clr.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
mem_clr.o: mem_clr.c
mem_dbg.o: ../e_os.h ../include/openssl/bio.h ../include/openssl/buffer.h
mem_dbg.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
mem_dbg.o: ../include/openssl/err.h ../include/openssl/lhash.h
mem_dbg.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
mem_dbg.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
mem_dbg.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
mem_dbg.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
mem_dbg.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
mem_dbg.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
mem_dbg.o: cryptlib.h mem_dbg.c
o_dir.o: ../e_os.h ../include/openssl/e_os2.h ../include/openssl/opensslconf.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/dirent.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
o_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
o_dir.o: LPdir_unix.c
o_dir.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
o_dir.o: o_dir.c o_dir.h
o_fips.o: ../e_os.h ../include/openssl/bio.h ../include/openssl/buffer.h
o_fips.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
o_fips.o: ../include/openssl/err.h ../include/openssl/lhash.h
o_fips.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
o_fips.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
o_fips.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
o_fips.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
o_fips.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
o_fips.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
o_fips.o: cryptlib.h o_fips.c
o_init.o: ../e_os.h ../include/openssl/bio.h ../include/openssl/crypto.h
o_init.o: ../include/openssl/e_os2.h ../include/openssl/err.h
o_init.o: ../include/openssl/lhash.h ../include/openssl/opensslconf.h
o_init.o: ../include/openssl/opensslv.h ../include/openssl/ossl_typ.h
o_init.o: ../include/openssl/safestack.h ../include/openssl/stack.h
o_init.o: ../include/openssl/symhacks.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
o_init.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
o_init.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
o_init.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
o_init.o: o_init.c
o_str.o: ../e_os.h ../include/openssl/e_os2.h ../include/openssl/opensslconf.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/ctype.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
o_str.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
o_str.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
o_str.o: o_str.c o_str.h
o_time.o: ../include/openssl/e_os2.h ../include/openssl/opensslconf.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
o_time.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
o_time.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
o_time.o: o_time.c o_time.h
uid.o: ../include/openssl/crypto.h ../include/openssl/e_os2.h
uid.o: ../include/openssl/opensslconf.h ../include/openssl/opensslv.h
uid.o: ../include/openssl/ossl_typ.h ../include/openssl/safestack.h
uid.o: ../include/openssl/stack.h ../include/openssl/symhacks.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
uid.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
uid.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
uid.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
uid.o: uid.c
