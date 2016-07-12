#
# crypto/camellia/Makefile
#

DIR= camellia
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CMLL_ENC= camellia.o cmll_misc.o cmll_cbc.o

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
#TEST=camelliatest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=camellia.c cmll_misc.c cmll_ecb.c cmll_cbc.c cmll_ofb.c \
	   cmll_cfb.c cmll_ctr.c cmll_utl.c

LIBOBJ= cmll_ecb.o cmll_ofb.o cmll_cfb.o cmll_ctr.o cmll_utl.o $(CMLL_ENC)

SRC= $(LIBSRC)

EXHEADER= camellia.h
HEADER= cmll_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

cmll-x86.s:	asm/cmll-x86.pl ../perlasm/x86asm.pl
	$(PERL) asm/cmll-x86.pl $(PERLASM_SCHEME) $(CFLAGS) $(PROCESSOR) > $@
cmll-x86_64.s:  asm/cmll-x86_64.pl
	$(PERL) asm/cmll-x86_64.pl $(PERLASM_SCHEME) > $@
cmllt4-sparcv9.s: asm/cmllt4-sparcv9.pl ../perlasm/sparcv9_modes.pl
	$(PERL) asm/cmllt4-sparcv9.pl $(CFLAGS) > $@

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

update: depend

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.s *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

camellia.o: ../../include/openssl/opensslconf.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
camellia.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
camellia.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
camellia.o: camellia.c camellia.h cmll_locl.h
cmll_cbc.o: ../../include/openssl/camellia.h ../../include/openssl/modes.h
cmll_cbc.o: ../../include/openssl/opensslconf.h
cmll_cbc.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
cmll_cbc.o: cmll_cbc.c
cmll_cfb.o: ../../include/openssl/camellia.h ../../include/openssl/modes.h
cmll_cfb.o: ../../include/openssl/opensslconf.h
cmll_cfb.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
cmll_cfb.o: cmll_cfb.c
cmll_ctr.o: ../../include/openssl/camellia.h ../../include/openssl/modes.h
cmll_ctr.o: ../../include/openssl/opensslconf.h
cmll_ctr.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
cmll_ctr.o: cmll_ctr.c
cmll_ecb.o: ../../include/openssl/camellia.h
cmll_ecb.o: ../../include/openssl/opensslconf.h
cmll_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
cmll_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/assert.h
cmll_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
cmll_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
cmll_ecb.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
cmll_ecb.o: cmll_ecb.c cmll_locl.h
cmll_misc.o: ../../include/openssl/camellia.h ../../include/openssl/crypto.h
cmll_misc.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
cmll_misc.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cmll_misc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
cmll_misc.o: ../../include/openssl/symhacks.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
cmll_misc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
cmll_misc.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
cmll_misc.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
cmll_misc.o: cmll_locl.h cmll_misc.c
cmll_ofb.o: ../../include/openssl/camellia.h ../../include/openssl/modes.h
cmll_ofb.o: ../../include/openssl/opensslconf.h
cmll_ofb.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
cmll_ofb.o: cmll_ofb.c
cmll_utl.o: ../../include/openssl/camellia.h ../../include/openssl/crypto.h
cmll_utl.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
cmll_utl.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cmll_utl.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
cmll_utl.o: ../../include/openssl/symhacks.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
cmll_utl.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
cmll_utl.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
cmll_utl.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
cmll_utl.o: cmll_locl.h cmll_utl.c
