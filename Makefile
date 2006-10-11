
.PHONY: build test debian-sid debian-dapper

build:
	python setup.py build

test:
	trial foolscap

debian-sid:
	rm -f debian
	ln -s misc/debs/sid/debian debian
	debuild -uc -us

debian-dapper:
	rm -f debian
	ln -s misc/debs/dapper/debian debian
	debuild -uc -us
