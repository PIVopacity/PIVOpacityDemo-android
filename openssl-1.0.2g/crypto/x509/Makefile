#
# OpenSSL/crypto/x509/Makefile
#

DIR=	x509
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile README
TEST=verify_extra_test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	x509_def.c x509_d2.c x509_r2x.c x509_cmp.c \
	x509_obj.c x509_req.c x509spki.c x509_vfy.c \
	x509_set.c x509cset.c x509rset.c x509_err.c \
	x509name.c x509_v3.c x509_ext.c x509_att.c \
	x509type.c x509_lu.c x_all.c x509_txt.c \
	x509_trs.c by_file.c by_dir.c x509_vpm.c
LIBOBJ= x509_def.o x509_d2.o x509_r2x.o x509_cmp.o \
	x509_obj.o x509_req.o x509spki.o x509_vfy.o \
	x509_set.o x509cset.o x509rset.o x509_err.o \
	x509name.o x509_v3.o x509_ext.o x509_att.o \
	x509type.o x509_lu.o x_all.o x509_txt.o \
	x509_trs.o by_file.o by_dir.o x509_vpm.o

SRC= $(LIBSRC)

EXHEADER= x509.h x509_vfy.h
HEADER=	$(EXHEADER) vpm_int.h

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

by_dir.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
by_dir.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
by_dir.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
by_dir.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
by_dir.o: ../../include/openssl/err.h ../../include/openssl/evp.h
by_dir.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
by_dir.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
by_dir.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
by_dir.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
by_dir.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
by_dir.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
by_dir.o: ../../include/openssl/x509_vfy.h ../cryptlib.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/endian.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stat.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/endian.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/stat.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
by_dir.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
by_dir.o: by_dir.c
by_dir.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
by_dir.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
by_file.o: ../../e_os.h ../../include/openssl/asn1.h
by_file.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
by_file.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
by_file.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
by_file.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
by_file.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
by_file.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
by_file.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
by_file.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
by_file.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
by_file.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
by_file.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
by_file.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
by_file.o: ../cryptlib.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
by_file.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
by_file.o: by_file.c
by_file.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
by_file.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509_att.o: ../../e_os.h ../../include/openssl/asn1.h
x509_att.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_att.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_att.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_att.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_att.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_att.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_att.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_att.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_att.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_att.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_att.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_att.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_att.o: ../cryptlib.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509_att.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509_att.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509_att.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509_att.o: x509_att.c
x509_cmp.o: ../../e_os.h ../../include/openssl/asn1.h
x509_cmp.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_cmp.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_cmp.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_cmp.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_cmp.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_cmp.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_cmp.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_cmp.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_cmp.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_cmp.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_cmp.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_cmp.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_cmp.o: ../cryptlib.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/ctype.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509_cmp.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509_cmp.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509_cmp.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509_cmp.o: x509_cmp.c
x509_d2.o: ../../e_os.h ../../include/openssl/asn1.h
x509_d2.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_d2.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_d2.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_d2.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_d2.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_d2.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_d2.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
x509_d2.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
x509_d2.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
x509_d2.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
x509_d2.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
x509_d2.o: ../cryptlib.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509_d2.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509_d2.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509_d2.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509_d2.o: x509_d2.c
x509_def.o: ../../e_os.h ../../include/openssl/asn1.h
x509_def.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_def.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_def.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_def.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_def.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_def.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_def.o: ../../include/openssl/opensslconf.h
x509_def.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_def.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_def.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_def.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_def.o: ../../include/openssl/x509_vfy.h ../cryptlib.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509_def.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509_def.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509_def.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509_def.o: x509_def.c
x509_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
x509_err.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x509_err.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_err.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_err.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_err.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_err.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_err.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_err.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_err.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_err.o: ../../include/openssl/x509_vfy.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509_err.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509_err.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509_err.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509_err.o: x509_err.c
x509_ext.o: ../../e_os.h ../../include/openssl/asn1.h
x509_ext.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_ext.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_ext.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_ext.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_ext.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_ext.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_ext.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_ext.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_ext.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_ext.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_ext.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_ext.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_ext.o: ../cryptlib.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509_ext.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509_ext.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509_ext.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509_ext.o: x509_ext.c
x509_lu.o: ../../e_os.h ../../include/openssl/asn1.h
x509_lu.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_lu.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_lu.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_lu.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_lu.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_lu.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_lu.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_lu.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_lu.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_lu.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_lu.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_lu.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_lu.o: ../cryptlib.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509_lu.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509_lu.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509_lu.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509_lu.o: x509_lu.c
x509_obj.o: ../../e_os.h ../../include/openssl/asn1.h
x509_obj.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_obj.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_obj.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_obj.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_obj.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_obj.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_obj.o: ../../include/openssl/opensslconf.h
x509_obj.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_obj.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_obj.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_obj.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_obj.o: ../../include/openssl/x509_vfy.h ../cryptlib.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509_obj.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509_obj.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509_obj.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509_obj.o: x509_obj.c
x509_r2x.o: ../../e_os.h ../../include/openssl/asn1.h
x509_r2x.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
x509_r2x.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
x509_r2x.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_r2x.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_r2x.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_r2x.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_r2x.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_r2x.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_r2x.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_r2x.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_r2x.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_r2x.o: ../../include/openssl/x509_vfy.h ../cryptlib.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509_r2x.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509_r2x.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509_r2x.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509_r2x.o: x509_r2x.c
x509_req.o: ../../e_os.h ../../include/openssl/asn1.h
x509_req.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
x509_req.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
x509_req.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_req.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_req.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_req.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_req.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_req.o: ../../include/openssl/opensslconf.h
x509_req.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_req.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
x509_req.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_req.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_req.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_req.o: ../../include/openssl/x509_vfy.h ../cryptlib.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509_req.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509_req.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509_req.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509_req.o: x509_req.c
x509_set.o: ../../e_os.h ../../include/openssl/asn1.h
x509_set.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_set.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_set.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_set.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_set.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_set.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_set.o: ../../include/openssl/opensslconf.h
x509_set.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_set.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_set.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_set.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_set.o: ../../include/openssl/x509_vfy.h ../cryptlib.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509_set.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509_set.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509_set.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509_set.o: x509_set.c
x509_trs.o: ../../e_os.h ../../include/openssl/asn1.h
x509_trs.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_trs.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_trs.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_trs.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_trs.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_trs.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_trs.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_trs.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_trs.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_trs.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_trs.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_trs.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_trs.o: ../cryptlib.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509_trs.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509_trs.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509_trs.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509_trs.o: x509_trs.c
x509_txt.o: ../../e_os.h ../../include/openssl/asn1.h
x509_txt.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_txt.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509_txt.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509_txt.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509_txt.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509_txt.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509_txt.o: ../../include/openssl/opensslconf.h
x509_txt.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_txt.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_txt.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_txt.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_txt.o: ../../include/openssl/x509_vfy.h ../cryptlib.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509_txt.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509_txt.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509_txt.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509_txt.o: x509_txt.c
x509_v3.o: ../../e_os.h ../../include/openssl/asn1.h
x509_v3.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_v3.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_v3.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_v3.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_v3.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_v3.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_v3.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_v3.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_v3.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_v3.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_v3.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_v3.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_v3.o: ../cryptlib.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509_v3.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509_v3.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509_v3.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509_v3.o: x509_v3.c
x509_vfy.o: ../../e_os.h ../../include/openssl/asn1.h
x509_vfy.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_vfy.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_vfy.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_vfy.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_vfy.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_vfy.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_vfy.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_vfy.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_vfy.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_vfy.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_vfy.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_vfy.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_vfy.o: ../cryptlib.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509_vfy.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509_vfy.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509_vfy.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509_vfy.o: vpm_int.h x509_vfy.c
x509_vpm.o: ../../e_os.h ../../include/openssl/asn1.h
x509_vpm.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509_vpm.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
x509_vpm.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x509_vpm.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x509_vpm.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x509_vpm.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x509_vpm.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
x509_vpm.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509_vpm.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509_vpm.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509_vpm.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509_vpm.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x509_vpm.o: ../cryptlib.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509_vpm.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509_vpm.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509_vpm.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509_vpm.o: vpm_int.h x509_vpm.c
x509cset.o: ../../e_os.h ../../include/openssl/asn1.h
x509cset.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509cset.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509cset.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509cset.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509cset.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509cset.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509cset.o: ../../include/openssl/opensslconf.h
x509cset.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509cset.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509cset.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509cset.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509cset.o: ../../include/openssl/x509_vfy.h ../cryptlib.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509cset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509cset.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509cset.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509cset.o: x509cset.c
x509name.o: ../../e_os.h ../../include/openssl/asn1.h
x509name.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509name.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509name.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509name.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509name.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509name.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509name.o: ../../include/openssl/opensslconf.h
x509name.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509name.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509name.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509name.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509name.o: ../../include/openssl/x509_vfy.h ../cryptlib.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509name.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509name.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509name.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509name.o: x509name.c
x509rset.o: ../../e_os.h ../../include/openssl/asn1.h
x509rset.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509rset.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509rset.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509rset.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509rset.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509rset.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509rset.o: ../../include/openssl/opensslconf.h
x509rset.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509rset.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509rset.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509rset.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509rset.o: ../../include/openssl/x509_vfy.h ../cryptlib.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509rset.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509rset.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509rset.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509rset.o: x509rset.c
x509spki.o: ../../e_os.h ../../include/openssl/asn1.h
x509spki.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509spki.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509spki.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509spki.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509spki.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509spki.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509spki.o: ../../include/openssl/opensslconf.h
x509spki.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509spki.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509spki.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509spki.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509spki.o: ../../include/openssl/x509_vfy.h ../cryptlib.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509spki.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509spki.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509spki.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509spki.o: x509spki.c
x509type.o: ../../e_os.h ../../include/openssl/asn1.h
x509type.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
x509type.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
x509type.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
x509type.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
x509type.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
x509type.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
x509type.o: ../../include/openssl/opensslconf.h
x509type.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
x509type.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
x509type.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x509type.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x509type.o: ../../include/openssl/x509_vfy.h ../cryptlib.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x509type.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x509type.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x509type.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x509type.o: x509type.c
x_all.o: ../../e_os.h ../../include/openssl/asn1.h ../../include/openssl/bio.h
x_all.o: ../../include/openssl/buffer.h ../../include/openssl/conf.h
x_all.o: ../../include/openssl/crypto.h ../../include/openssl/dsa.h
x_all.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
x_all.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
x_all.o: ../../include/openssl/err.h ../../include/openssl/evp.h
x_all.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
x_all.o: ../../include/openssl/objects.h ../../include/openssl/ocsp.h
x_all.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
x_all.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
x_all.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
x_all.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
x_all.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
x_all.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
x_all.o: ../cryptlib.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/alloca.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/android/api-level.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/bitsperlong.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno-base.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/errno.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/int-ll64.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/posix_types.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/siginfo.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/signal-defs.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm-generic/types.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/bitsperlong.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/errno.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/posix_types.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/sigcontext.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/siginfo.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/signal.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/asm/types.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/errno.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/limits.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/compiler.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/errno.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/limits.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/posix_types.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/signal.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/stddef.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/time.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/linux/types.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/machine/wchar_limits.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/malloc.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/memory.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/pathconf.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/signal.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdint.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdio.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/stdlib.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/string.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/strings.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/cdefs_elf.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/limits.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/select.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysconf.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/syslimits.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/sysmacros.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/time.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/types.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/ucontext.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/sys/user.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/time.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/unistd.h
x_all.o: C:/Users/jkoehring.EXPONENT/AppData/Local/Android/sdk/ndk-bundle/platforms/android-23/arch-arm/usr/include/xlocale.h
x_all.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stdarg.h
x_all.o: c:\users\jkoehring.exponent\appdata\local\android\sdk\ndk-bundle\toolchains\arm-linux-androideabi-4.9\prebuilt\windows-x86_64\lib\gcc\arm-linux-androideabi\4.9\include\stddef.h
x_all.o: x_all.c
