
.PHONY: build test

build:
	python setup.py build

TRIAL=trial
TEST=foolscap
test:
	$(TRIAL) $(TEST)

test-poll:
	$(MAKE) test TRIAL="trial -r poll"

api-docs:
	rm -rf doc/api
	PYTHONPATH=. epydoc -v -o doc/api --html -n Foolscap -u http://foolscap.lothar.com --exclude foolscap.test foolscap

pyflakes:
	pyflakes bin foolscap |sort |uniq

find-trailing-spaces:
	find-trailing-spaces -r bin foolscap
