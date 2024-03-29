#!/bin/bash
if [ $# -gt 0 -a $1 == '-i' ]; then
  interactive=1
  shift
else
  interactive=0
fi
if [ $# -lt 2 ]; then
  exit 99
fi
infile="$1"
shift
host="$1"
shift
if [ $# -gt 0 ]; then
  jump="-J $host"
  host="$1"
  shift
else
  jump=''
fi

prog=$'\'import sys;
import gzip;
import os;
exec(gzip.decompress(sys.stdin.buffer.read(int.from_bytes(sys.stdin.buffer.read(4),"little"))).decode("UTF-8"));\''

if [ $interactive -ne 0 ]; then
  (python3 gencompress.py "$infile"; cat) | ssh $jump $host python3 -c $prog
  exit $?
else
  python3 gencompress.py "$infile" | ssh $jump $host python3 -c $prog
  exit $?
fi
exit 1
