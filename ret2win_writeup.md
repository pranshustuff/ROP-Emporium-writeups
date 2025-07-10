# ROP Emporium | ret2win

### Stack Buffer Overflow

So I finished the "Hello World" of ROP (Return Oriented Programming) as they call it. I'd like to explain this in simpler terms for ease of understanding.

---

### Step 1: What does executing `ret2win` do?

![Normal execution](/Screenshots/normal.png)

####  If we enter too many character:
![Segfault](/Screenshots/segfault.png)

---

### Step 2: Main Function in Cutter

Let's open Cutter and see what the `main` function looks like:

![Main_func](/Screenshots/main.png)

The `main` function calls a function `pwnme()`. In that function, we can see our strings and where it reads our input.

![pwnme_func](/Screenshots/pwnme.png)

As we can see, the `edx` register (where the user input size is defined) is assigned **32 bytes**, but further down it actually **reads 56 bytes** of user input. What does this mean for us?

---

### Step 3: Stack Layout

The **stack pointer (RSP)** controls which line of code the system reads and moves **upwards** in memory as we move deeper into function calls.

- The **32-byte buffer** (`buf`) is allocated on the stack.
- The **base pointer (RBP)** points to the base of the current function's stack frame.
- **8 bytes above RBP** is the **return address**, where the program will continue after the function ends (normally back to `main`).

![stack](/Screenshots/stack.jpg)

---

### Step 4: Exploiting the Overflow

There’s a function called `ret2win()` that returns the flag. We don’t care about the 32-byte buffer or the value of `rbp`.

Our goal: **overwrite the return address** with the **address of `ret2win()`**.

Since the program reads **56 bytes**, and only 32 bytes are used for the buffer, the extra **24 bytes** overwrite:

- 8 bytes for saved `rbp`
- 8 bytes for the return address
- (remaining 8 bytes might be ignored or reserved)

![stack](/Screenshots/l32.jpg)
![stack](/Screenshots/g32.jpg)


**Input structure:**
```
[32 bytes]  buffer (junk)
[8 bytes]   saved rbp (junk)
[8 bytes]   return address → address of ret2win()
```

---

### Step 5: Pwning It

We can write an exploit script using pwntools:

```python
from pwn import * 

ret2win_addr = p64(0x00400757)

payload = b'A' * 32 # fill the buffer
payload += b'B'* 8 # fill the RBP
payload += ret2win_addr #replace the return addr

io = process('./ret2win')
io.sendline(payload)
io.interactive()
```

---

### Step 6: Why `0x400757` Works (but not `0x400756`)

The address of `ret2win` is `0x400756`. But jumping directly to it starts at a `push rbp`, which **resets the stack** and can break the flow.

Instead, jumping to `0x400757` starts at `mov rbp, rsp`, skipping the push and keeping the stack stable.

Therefore, we jump to `0x400757`, and it works perfectly — returning the flag.

#### With `addr` as `0x400756`
![756](/Screenshots/756.png)

#### With `addr` as `0x400757`
![stack](/Screenshots/757.png)

