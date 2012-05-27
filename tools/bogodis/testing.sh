#!/bin/sh
objdump -d -M intel ./bogodis | awk -f distill.awk > input.dis
./bogodis -i -l 15 < input.dis > output.dis
diff -Eb input.dis output.dis > result.dis 
