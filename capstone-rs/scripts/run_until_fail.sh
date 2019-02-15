#!/usr/bin/env bash
# Run command for MAX_ITER iterations or until the command fails.

iter=0
MAX_ITER=${MAX_ITER:-1000}

while [ $iter -lt $MAX_ITER ]
do
    # Print message every 100 iterations
    if [ $(expr $iter % 100) = 0 ]; then
        echo iter $iter
    fi

    if ! output="$("$@" 2>&1)"; then
        echo "$output"
        echo
        echo "Failed after $iter tests"
        exit 1
    fi

    iter=$(expr $iter + 1)
done
