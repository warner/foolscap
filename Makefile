
PYTHON=python
TRIAL=trial
TEST=foolscap

.PHONY: build test

build:
	$(PYTHON) setup.py build

test:
	$(TRIAL) $(TEST)

test-poll:
	$(MAKE) test TRIAL="trial -r poll"

api-docs:
	rm -rf doc/api
	PYTHONPATH=. epydoc -v -o doc/api --html -n Foolscap -u http://foolscap.lothar.com --exclude foolscap.test foolscap

pyflakes:
	pyflakes setup.py src |sort |uniq

find-trailing-spaces:
	find-trailing-spaces -r src

setup-test-from-tarball:
	rm -rf sdist-test
	$(PYTHON) setup.py sdist -d sdist-test
	cd sdist-test && tar xf *.tar.gz
	rm sdist-test/*.tar.gz
	cd sdist-test && ln -s * srcdir

test-from-tarball:
	cd sdist-test/srcdir && trial foolscap
