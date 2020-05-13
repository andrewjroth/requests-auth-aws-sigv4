.PHONY: clean
clean:
	rm -vrf build/
	rm -vrf dist/
	find . -name *.pyc -delete -print
	rm -vrf *.egg-info
	rm -vrf */__pycache__

.PHONY: build3
build3:
	python3 setup.py sdist bdist_wheel

.PHONY: publish
publish:
	pip install twine
	twine upload dist/*

