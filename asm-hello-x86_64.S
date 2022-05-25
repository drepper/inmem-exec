.section .rodata
str: .asciz "Hello World\n"
.text
	.globl _start
_start:
      	mov    $0x1,%eax
      	mov    $0x1,%edi
      	lea    str,%rsi

      	mov    $0xc,%edx
      	syscall
      	mov    $0xe7,%eax
      	mov    $0x0,%edi
      	syscall

