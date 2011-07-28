
.PHONY: build test debian-sid debian-dapper debian-feisty debian-sarge
.PHONY: debian-edgy debian-etch

build:
	python setup.py build

TRIAL=trial
TEST=foolscap
test:
	$(TRIAL) $(TEST)

test-figleaf:
	rm -f .figleaf
	PYTHONPATH=misc/testutils $(TRIAL) --reporter=bwverbose-figleaf $(TEST)

test-poll:
	$(MAKE) test TRIAL="trial -r poll"
test-figleaf-poll:
	$(MAKE) test-figleaf TRIAL="trial -r poll"

figleaf-output:
	rm -rf coverage-html
	PYTHONPATH=misc/testutils python misc/testutils/figleaf2html -d coverage-html -r . -x misc/testutils/figleaf.excludes
	@echo "now point your browser at coverage-html/index.html"
.figleaf.el: .figleaf
	PYTHONPATH=misc/testutils python misc/testutils/figleaf2el.py .figleaf .

debian-sid:
	rm -f debian
	ln -s misc/sid/debian debian
	chmod a+x debian/rules
	debuild -uc -us

debian-etch:
	rm -f debian
	ln -s misc/etch/debian debian
	chmod a+x debian/rules
	debuild -uc -us

debian-dapper:
	rm -f debian
	ln -s misc/dapper/debian debian
	chmod a+x debian/rules
	debuild -uc -us

debian-edgy:
	rm -f debian
	ln -s misc/edgy/debian debian
	chmod a+x debian/rules
	debuild -uc -us

debian-feisty:
	rm -f debian
	ln -s misc/feisty/debian debian
	chmod a+x debian/rules
	debuild -uc -us

debian-gutsy:
	rm -f debian
	ln -s misc/gutsy/debian debian
	chmod a+x debian/rules
	debuild -uc -us

debian-hardy:
	rm -f debian
	ln -s misc/hardy/debian debian
	chmod a+x debian/rules
	debuild -uc -us

debian-sarge:
	rm -f debian
	ln -s misc/sarge/debian debian
	chmod a+x debian/rules
	debuild -uc -us

LORE=lore
DOC_TEMPLATE=doc/template.tpl
docs:
	$(LORE) -p --config template=$(DOC_TEMPLATE) --config ext=.html \
	--config baseurl='api/%s-class.html' \
	`find doc -name '*.xhtml'`
doc/%.html: doc/%.xhtml
	$(LORE) -p --config template=$(DOC_TEMPLATE) --config ext=.html \
	--config baseurl='api/%s-class.html' \
	$<

api-docs:
	rm -rf doc/api
	PYTHONPATH=. epydoc -v -o doc/api --html -n Foolscap -u http://foolscap.lothar.com --exclude foolscap.test foolscap

pyflakes:
	pyflakes bin foolscap |sort |uniq

find-trailing-spaces:
	find-trailing-spaces -r bin foolscap


	
# lore2sphinx
lore2rest:
	lore2sphinx -c doc_rst/lore2sphinx.conf
	
	
############################################################3
# Makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
PAPER         =
BUILDDIR      = doc_html

# Internal variables.
PAPEROPT_a4     = -D latex_paper_size=a4
PAPEROPT_letter = -D latex_paper_size=letter
ALLSPHINXOPTS   = -d $(BUILDDIR)/doctrees $(PAPEROPT_$(PAPER)) $(SPHINXOPTS) doc_rst

.PHONY: help clean html dirhtml singlehtml pickle json htmlhelp qthelp devhelp epub latex latexpdf text man changes linkcheck doctest

help:
	@echo "Please use \`make <target>' where <target> is one of"
	@echo "  html       to make standalone HTML files"
	@echo "  dirhtml    to make HTML files named index.html in directories"
	@echo "  singlehtml to make a single large HTML file"
	@echo "  pickle     to make pickle files"
	@echo "  json       to make JSON files"
	@echo "  htmlhelp   to make HTML files and a HTML help project"
	@echo "  qthelp     to make HTML files and a qthelp project"
	@echo "  devhelp    to make HTML files and a Devhelp project"
	@echo "  epub       to make an epub"
	@echo "  latex      to make LaTeX files, you can set PAPER=a4 or PAPER=letter"
	@echo "  latexpdf   to make LaTeX files and run them through pdflatex"
	@echo "  text       to make text files"
	@echo "  man        to make manual pages"
	@echo "  changes    to make an overview of all changed/added/deprecated items"
	@echo "  linkcheck  to check all external links for integrity"
	@echo "  doctest    to run all doctests embedded in the documentation (if enabled)"

clean:
	-rm -rf $(BUILDDIR)/*

html:
	$(SPHINXBUILD) -b html $(ALLSPHINXOPTS) $(BUILDDIR)/html
	@echo
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/html."

dirhtml:
	$(SPHINXBUILD) -b dirhtml $(ALLSPHINXOPTS) $(BUILDDIR)/dirhtml
	@echo
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/dirhtml."

singlehtml:
	$(SPHINXBUILD) -b singlehtml $(ALLSPHINXOPTS) $(BUILDDIR)/singlehtml
	@echo
	@echo "Build finished. The HTML page is in $(BUILDDIR)/singlehtml."

pickle:
	$(SPHINXBUILD) -b pickle $(ALLSPHINXOPTS) $(BUILDDIR)/pickle
	@echo
	@echo "Build finished; now you can process the pickle files."

json:
	$(SPHINXBUILD) -b json $(ALLSPHINXOPTS) $(BUILDDIR)/json
	@echo
	@echo "Build finished; now you can process the JSON files."

htmlhelp:
	$(SPHINXBUILD) -b htmlhelp $(ALLSPHINXOPTS) $(BUILDDIR)/htmlhelp
	@echo
	@echo "Build finished; now you can run HTML Help Workshop with the" \
	      ".hhp project file in $(BUILDDIR)/htmlhelp."

qthelp:
	$(SPHINXBUILD) -b qthelp $(ALLSPHINXOPTS) $(BUILDDIR)/qthelp
	@echo
	@echo "Build finished; now you can run "qcollectiongenerator" with the" \
	      ".qhcp project file in $(BUILDDIR)/qthelp, like this:"
	@echo "# qcollectiongenerator $(BUILDDIR)/qthelp/Foolscap.qhcp"
	@echo "To view the help file:"
	@echo "# assistant -collectionFile $(BUILDDIR)/qthelp/Foolscap.qhc"

devhelp:
	$(SPHINXBUILD) -b devhelp $(ALLSPHINXOPTS) $(BUILDDIR)/devhelp
	@echo
	@echo "Build finished."
	@echo "To view the help file:"
	@echo "# mkdir -p $$HOME/.local/share/devhelp/Foolscap"
	@echo "# ln -s $(BUILDDIR)/devhelp $$HOME/.local/share/devhelp/Foolscap"
	@echo "# devhelp"

epub:
	$(SPHINXBUILD) -b epub $(ALLSPHINXOPTS) $(BUILDDIR)/epub
	@echo
	@echo "Build finished. The epub file is in $(BUILDDIR)/epub."

latex:
	$(SPHINXBUILD) -b latex $(ALLSPHINXOPTS) $(BUILDDIR)/latex
	@echo
	@echo "Build finished; the LaTeX files are in $(BUILDDIR)/latex."
	@echo "Run \`make' in that directory to run these through (pdf)latex" \
	      "(use \`make latexpdf' here to do that automatically)."

latexpdf:
	$(SPHINXBUILD) -b latex $(ALLSPHINXOPTS) $(BUILDDIR)/latex
	@echo "Running LaTeX files through pdflatex..."
	make -C $(BUILDDIR)/latex all-pdf
	@echo "pdflatex finished; the PDF files are in $(BUILDDIR)/latex."

text:
	$(SPHINXBUILD) -b text $(ALLSPHINXOPTS) $(BUILDDIR)/text
	@echo
	@echo "Build finished. The text files are in $(BUILDDIR)/text."

man:
	$(SPHINXBUILD) -b man $(ALLSPHINXOPTS) $(BUILDDIR)/man
	@echo
	@echo "Build finished. The manual pages are in $(BUILDDIR)/man."

changes:
	$(SPHINXBUILD) -b changes $(ALLSPHINXOPTS) $(BUILDDIR)/changes
	@echo
	@echo "The overview file is in $(BUILDDIR)/changes."

linkcheck:
	$(SPHINXBUILD) -b linkcheck $(ALLSPHINXOPTS) $(BUILDDIR)/linkcheck
	@echo
	@echo "Link check complete; look for any errors in the above output " \
	      "or in $(BUILDDIR)/linkcheck/output.txt."

doctest:
	$(SPHINXBUILD) -b doctest $(ALLSPHINXOPTS) $(BUILDDIR)/doctest
	@echo "Testing of doctests in the sources finished, look at the " \
	      "results in $(BUILDDIR)/doctest/output.txt."
