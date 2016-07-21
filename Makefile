
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

.PHONY: release _release
release:
	@if [ "X${VERSION}" = "X" ]; then echo "must pass VERSION="; else $(MAKE) _release; fi

_release:
	git tag -s -u AF1B4A2A -m "release foolscap-${VERSION}" foolscap-${VERSION}
	python setup.py sdist bdist_wheel
	cd dist && gpg -u AF1B4A2A -ba foolscap-${VERSION}.tar.gz
	cd dist && gpg -u AF1B4A2A -ba foolscap-${VERSION}-py2-none-any.whl
	echo "manual steps:"
	@echo "git push warner master foolscap-${VERSION}"
	@echo "update 'latest-release' tag, push -f"
	@echo "twine register dist/foolscap-${VERSION}-py2-none-any.whl"
	@echo "twine upload dist/foolscap-${VERSION}*"
