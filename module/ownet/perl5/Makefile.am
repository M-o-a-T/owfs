EXTRA_DIST = OWNet/README OWNet/MANIFEST OWNet/Changes OWNet/Makefile.PL OWNet/lib/OWNet.pm OWNet/t/OWNet.t examples/test.pl examples/test2.pl

all: OWNet/Makefile
	$(MAKE) -C OWNet all

# Can't really install the perl-modules under prefix-directory.. it should be site-global.
OWNet/Makefile: OWNet/Makefile.PL
if HAVE_DEBIAN
	cd OWNet; $(PERL) Makefile.PL INSTALLDIRS=vendor
else
	cd OWNet; $(PERL) Makefile.PL
endif

install-data-local: OWNet/Makefile
if HAVE_DEBIAN
	$(MAKE) -C OWNet install_vendor DESTDIR="$(DESTDIR)"
else
	$(MAKE) -C OWNet install DESTDIR="$(DESTDIR)"
endif
#	$(MAKE) -C OWNet install DESTDIR="$(DESTDIR)"
#	cd OWNet; $(MAKE) ; $(MAKE) test; $(MAKE) install

clean-generic:
	-test ! -f OWNet/Makefile || $(MAKE) -C OWNet clean
	@RM@ -f OWNet/Makefile.old OWNet/Makefile

