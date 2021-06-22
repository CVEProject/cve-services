#!/bin/bash
input="./src/testOutput.txt"
result="Tests passed"

while IFS= read -r line
do
  if grep -q "failed" <<< "$line"; then
    result="Tests failed"
  fi
done < "$input"
echo "$result"
