#!/bin/bash

# Generate 

# Set the shell to exit immediately if any command fails
set -e

# Check if a file argument was passed; exit if the file doesn't exist.
if [[ ! -f ${1} ]]; then
  exit -1
fi

# Generate an unsigned character array from .text section of the file
echo "unsigned char payload[] = {"
objcopy --dump-section .text=/dev/stdout ${1} | xxd -i
echo "};"

# Print the size of the payload array
echo "unsigned payload_len = sizeof(payload);"