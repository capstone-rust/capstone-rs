# Update bindings

In order to update the pre-generated bindings:

1. Update pre-generated bindings

    ~~~
    UPDATE_CAPSTONE_BINDINGS=1 cargo build
    ~~~

2. Commit bindings update.

3. Re-apply documentation comments patch

    ~~~
    git diff e67b72b8^ e67b72b8 | \
        ./scripts/add_doc_comments.py --doc-patch - \
        --fs-path pre_generated/capstone.rs -o pre_generated/capstone.doc.rs
    ~~~

4. Fixup/add any more documentation comments.

5. Commit documentation fixups.


## Notes

* We want to keep the pre-generated bindings and documentation update in
  separate commits.
    * Allows us to cherry-pick changes (such as the documentation)
