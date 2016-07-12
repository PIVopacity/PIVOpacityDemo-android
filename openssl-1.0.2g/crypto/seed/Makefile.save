#
# crypto/seed/Makefile
#

DIR=	seed
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=seed.c seed_ecb.c seed_cbc.c seed_cfb.c seed_ofb.c
LIBOBJ=seed.o seed_ecb.o seed_cbc.o seed_cfb.o seed_ofb.o

SRC= $(LIBSRC)

EXHEADER= seed.h
HEADER= seed_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

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
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

seed.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
seed.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
seed.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
seed.o: ../../include/openssl/seed.h ../../include/openssl/stack.h
seed.o: ../../include/openssl/symhacks.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
seed.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
seed.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
seed.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
seed.o: seed.c seed_locl.h
seed_cbc.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
seed_cbc.o: ../../include/openssl/modes.h ../../include/openssl/opensslconf.h
seed_cbc.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
seed_cbc.o: ../../include/openssl/safestack.h ../../include/openssl/seed.h
seed_cbc.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
seed_cbc.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
seed_cbc.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
seed_cbc.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
seed_cbc.o: seed_cbc.c
seed_cfb.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
seed_cfb.o: ../../include/openssl/modes.h ../../include/openssl/opensslconf.h
seed_cfb.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
seed_cfb.o: ../../include/openssl/safestack.h ../../include/openssl/seed.h
seed_cfb.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
seed_cfb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
seed_cfb.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
seed_cfb.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
seed_cfb.o: seed_cfb.c
seed_ecb.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
seed_ecb.o: ../../include/openssl/opensslconf.h
seed_ecb.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
seed_ecb.o: ../../include/openssl/safestack.h ../../include/openssl/seed.h
seed_ecb.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
seed_ecb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
seed_ecb.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
seed_ecb.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
seed_ecb.o: seed_ecb.c
seed_ofb.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
seed_ofb.o: ../../include/openssl/modes.h ../../include/openssl/opensslconf.h
seed_ofb.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
seed_ofb.o: ../../include/openssl/safestack.h ../../include/openssl/seed.h
seed_ofb.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
seed_ofb.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
seed_ofb.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
seed_ofb.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
seed_ofb.o: seed_ofb.c
