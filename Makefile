lib:
	cargo build

demo: demo.rs lib
	rustc -L target/debug $< -o $@

.PHONY: lib
