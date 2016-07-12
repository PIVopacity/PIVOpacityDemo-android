#
# OpenSSL/crypto/txt_db/Makefile
#

DIR=	txt_db
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=txt_db.c
LIBOBJ=txt_db.o

SRC= $(LIBSRC)

EXHEADER= txt_db.h
HEADER=	$(EXHEADER)

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
	@[ -n "$(MAKEDEPEND)" ] # should be set by top Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

txt_db.o: ../../e_os.h ../../include/openssl/bio.h
txt_db.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
txt_db.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
txt_db.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
txt_db.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
txt_db.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
txt_db.o: ../../include/openssl/symhacks.h ../../include/openssl/txt_db.h
txt_db.o: ../cryptlib.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
txt_db.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
txt_db.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
txt_db.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
txt_db.o: txt_db.c
