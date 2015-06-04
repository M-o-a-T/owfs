EXTRA_DIST = setup.py MANIFEST.in Readme.txt Readme_pypi.txt examples/check_ow.py examples/temperatures.py ownet/__init__.py ownet/connection.py

install-data-local:
#	OpenSUSE is buggy and install libraries at /usr/local.
#	Need to add call "install_lib --install-dir" or call "install --install-lib"
#	$(PYTHON) setup.py install_lib --install-dir="/$(DESTDIR)$(PYSITEDIR)"
	set -e ; set -x ; for p in $$(pyversions -r ../../../debian/control) ; do \
		$$p setup.py install --install-layout=deb --root=$(DESTDIR) ; \
	done
# Other options are (but not needed): --install-data="/$(DESTDIR)$(PYSITEDIR)" --install-script="/$(DESTDIR)$(PYSITEDIR)" --install-header=

clean-local:
	@RM@ -rf build
