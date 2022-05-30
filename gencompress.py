#!/usr/bin/env python
import gzip
import sys

with open(sys.argv[1], 'rb') as fd:
    b = gzip.compress(fd.read())
    sys.stdout.buffer.write(len(b).to_bytes(4, 'little') + b)
