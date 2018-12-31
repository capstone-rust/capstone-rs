# Update bindings

In order to update the pre-generated bindings:

1. Update pre-generated bindings

    ~~~
    UPDATE_CAPSTONE_BINDINGS=1 cargo build --features use_bindgen
    ~~~

2. Format the result (it comes out on one big line).

    ~~~
    rustfmt pre_generated/capstone.rs
    ~~~

3. Commit bindings update.

4. Fixup/add any more documentation comments.

5. Commit documentation fixups.

    ~~~
    git commit pre_generated/capstone.rs
    ~~~


## Notes

* We want to keep the pre-generated bindings and documentation update in
  separate commits.
    * Allows us to more easily cherry-pick changes (such as the documentation)
