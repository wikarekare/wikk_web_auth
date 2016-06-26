#!/bin/sh
#Copy up to rubygem.org
VERSION="0.1.1"
git tag -a ${VERSION} -m "Gem release ${VERSION}"
/usr/local/bin/rake release VERSION=${VERSION} #--trace

