from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

exe = './vuln'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Lib-C library, can use pwninit/patchelf to patch binary
# libc = ELF("./libc.so.6")
# ld = ELF("./ld-2.27.so")

offset = 72

io = start()

def malloc(id, size, data):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'> ', str(id).encode())
    io.sendlineafter(b'> ', str(size).encode())
    io.sendafter(b'> ', data)
    
def view(id):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'> ', str(id).encode())

def edit(id, data):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'> ', str(id).encode())
    io.sendlineafter(b'> ', data)

def free(id):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'> ', str(id).encode())

def malloc():
    io.sendlineafter(b':', b'1')
    
def free(id):
    io.sendlineafter(b':', b'2')
    io.sendlineafter(b':', str(id).encode())

def call(id):
    io.sendlineafter(b':', b'3')
    io.sendlineafter(b':', str(id).encode())


io.sendlineafter(b'>', payload)
io.recvuntil(b'Thank you!')

io.interactive()
