#
# See the COPYING file for license information
#

clean:
	rm -rf tmp

preview:
	mkdir -p tmp
	xmlto -o tmp html handbook.xml
	firefox ./tmp/index.html

publish:
	git checkout gh-pages
	git merge master
	xmlto html *.xml
	git add *.html
	git commit -m'publishing it'
	git push
	git checkout master

.PHONY: clean preview publish