# Update bindings

In order to update the pre-generated bindings:

1. Update pre-generated bindings

    ~~~
    UPDATE_CAPSTONE_BINDINGS=1 cargo build --features use_bindgen
    ~~~

2. Commit bindings update.

3. Find documentation comment commit.

    ~~~
    git log pre_generated/capstone.rs
    ~~~

4. Re-apply documentation comments patch

    ~~~
    commit=a9792c5ebeb6c857783a6695982f4882170a3c54; \
        git diff ${commit}^ ${commit} | \
        ./scripts/add_doc_comments.py --doc-patch - \
        --fs-path pre_generated/capstone.rs -o pre_generated/capstone.doc.rs
    ~~~

5. Fixup/add any more documentation comments.

6. Overwrite pre-generated bindings with the fixed-up version.

    ~~~
    cp pre_generated/capstone.doc.rs pre_generated/capstone.rs
    ~~~

7. Commit documentation fixups.

    ~~~
    git commit pre_generated/capstone.rs
    ~~~


## Notes

* We want to keep the pre-generated bindings and documentation update in
  separate commits.
    * Allows us to more easily cherry-pick changes (such as the documentation)
