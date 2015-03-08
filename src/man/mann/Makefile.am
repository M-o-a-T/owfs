## man sources
MANFILES = \
    owtcl.man
## .so includes
SOFILES = \
    description.nso seealso.nso
## man files that need no preprocessing
dist_man3_MANS = \
    ow.3
## file to include in distribution
EXTRA_DIST = $(SOFILES) $(MANFILES)


if SOELIM

man3_MANS = $(addsuffix .3,$(basename $(MANFILES)))
CLEANFILES = $(man3_MANS)

# preproc man pages via soelim
$(man3_MANS): $(MANFILES) $(SOFILES)
%.3 :: %.man
	$(SOELIM) -r -I $(srcdir)/.. $< > $@

else !SOELIM

man3_MANS = $(MANFILES) $(SOFILES)

endif !SOELIM
