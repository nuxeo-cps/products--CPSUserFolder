.PHONY: clean check

check:
	pychecker2 *.py

clean:
	find . -name '*~' | xargs rm -f
	find . -name '*pyc' | xargs rm -f

