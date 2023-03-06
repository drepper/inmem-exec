#!/bin/bash
f=$(file ${@: -1})
case "$f" in
  *32-bit*UCB*) suf=riscv32 ;;
  *64-bit*UCB*) suf=riscv64 ;;
  *80386*) suf=i386 ;;
  *x86-64*) suf=x86-64 ;;
  *32-bit*ARM*) suf=arm ;;
  *ARM*aarch64*) suf=aarch64 ;;
  *MSB*Xtensa*) suf=xtensaeb ;;
  *) printf '???\n'; exit 1 ;;
esac

exec qemu-"$suf" -singlestep -d in_asm,cpu "$@"
