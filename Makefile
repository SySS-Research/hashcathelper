SSH_TARGET ?= hashcat01

help:
	@echo "clean - remove all build, test, coverage and Python artifacts"
	@echo "lint - check style with flake8"
	@echo "test - run tests"
	@echo "deploy - package and upload a release to hashcat01"
	@echo "release - tag a new release and update changelog"
	@echo "install - install the package to the user's Python's site-packages"
	@echo "help - show this help and exit"

deploy: hashcathelper.pyz
	@echo scp hashcathelper.pyz $(SSH_TARGET):.local/bin/hashcathelper

hashcathelper.pyz: hashcathelper/
	@$(eval TEMP_DIR := $(shell mktemp -d --suffix=.hashcathelper))
	python3 -m pip install --system . --upgrade --target "${TEMP_DIR}"
	@python3 -m zipapp "${TEMP_DIR}" -m hashcathelper.__main__:main -p '/usr/bin/env python3' --output hashcathelper.pyz
	@rm -rf "${TEMP_DIR}"

clean:
	@rm -rf build dist *.egg-info
	@find . -type f -name '*.pyc' -delete
	@find . -type d -name '__pycache__' | xargs rm -rf
	@rm -rf .tox
	@rm -f src/*.egg*
	@rm -f hashcathelper.pyz

lint:
	@flake8 hashcathelper

test:
	@rm -rf .tox
	@tox

docs:
	@echo "Not yet implemented"

install:
	python3 setup.py install --user

# \n in sed only works in GNU sed
release:
	@read -p "Enter version string: " version; \
    echo "Version Bump: $$version"; \
	date=$$(date +%F); \
	sed -i "s/^__version__ = '.*'/__version__ = '$$version'/" hashcathelper/_meta.py && \
	sed -i "s/^## \[Unreleased\]/## [Unreleased]\n\n## [$$version] - $$date/" CHANGELOG.md && \
	git add CHANGELOG.md hashcathelper/_meta.py && \
	git commit -m "Version bump: $$version" && \
	read -p "Committed. Do you want to tag and push the new version? [y/n] " ans && \
	if [ $$ans = 'y' ] ; then git tag $$version && git push && git push origin tag $$version && echo "Tagged and pushed." ; else echo "Tag it and push it yourself then." ; fi


.PHONY: build clean lint test docs deploy install help release
