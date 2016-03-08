lib:
	cargo build

clean:
	cargo clean

doc: clean
	cargo doc

upload_docs: doc
	git init target/doc
	cd target/doc && git add -A .
	cd target/doc && git remote add origin git@github.com:richo/capstone-rs.git
	cd target/doc && git commit -m 'doc build on $(pwd)'
	cd target/doc && git push --force origin HEAD:gh-pages

.PHONY: lib doc upload_docs clean
