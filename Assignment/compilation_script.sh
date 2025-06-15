#!/bin/bash

# Array of P4 source files (without extensions)
P4_FILES=("l2switch" "label_forwarder" "ingress" "teste_r4")

# Loop over each file and compile
for file in "${P4_FILES[@]}"; do
    echo "Compiling ${file}.p4..."
    p4c-bm2-ss --std p4-16 p4/${file}.p4 -o json/${file}.json --p4runtime-files json/${file}.p4info.txt
    if [ $? -ne 0 ]; then
        echo "Error compiling ${file}.p4"
        exit 1
    fi
done

echo "Compilation finished successfully."