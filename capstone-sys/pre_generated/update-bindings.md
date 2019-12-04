# Update bindings

In order to update the pre-generated bindings:

1. Update pre-generated bindings

    ~~~
    UPDATE_CAPSTONE_BINDINGS=1 cargo build --features use_bindgen
    ~~~

2. If needed, format the result (might be necessary; sometimes the source has been one big line).

    ~~~
    rustfmt pre_generated/*.rs
    ~~~

3. Commit bindings update.

    ~~~
    git commit "pre_generated/*.rs"
    ~~~


## Notes

* We used to separately fix-up the documentation after updating the
  pre-generated bindings, but now bindgen correctly parses comments.
