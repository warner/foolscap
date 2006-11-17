
.PHONY: build test debian-sid debian-dapper

build:
	python setup.py build

test:
	trial foolscap

debian-sid:
	rm -f debian
	ln -s misc/sid/debian debian
	chmod a+x debian/rules
	debuild -uc -us

debian-dapper:
	rm -f debian
	ln -s misc/dapper/debian debian
	chmod a+x debian/rules
	debuild -uc -us

debian-sarge:
	rm -f debian
	ln -s misc/sarge/debian debian
	chmod a+x debian/rules
	debuild -uc -us

DOC_TEMPLATE=doc/template.tpl
docs:
	lore -p --config template=$(DOC_TEMPLATE) --config ext=.html \
	`find doc -name '*.xhtml'`
