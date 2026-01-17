---
title: "SignMeUp - GlacierCTF 2024"
lastUpdated: 2024-11-23T00:00:00.000Z
draft: false
math: true
tags:
  - ECDSA
  - LLL
  - SHA1
  - Elliptic Curve
  - GlacierCTF
  - Cryptography
author: "Garab"
---


## Writeup for GlacierCTF Challenge: SignMeUp

### Challenge Overview

This challenge involves exploiting a custom EdDSA signature implementation that uses SHA1 instead of SHA512. The vulnerability comes from the mismatch between the hash output size (160 bits) and the curve order (252 bits).

### The Challenge Code

```rust
pub fn sign(
        &self,
        message: &[u8],
    ) -> (CompressedEdwardsY, Scalar)
    {
        let mut h = HashType::new();
        h.update(&self.hash_prefix);
        h.update(message);
        let mut hash_val = [0u8; 64];
        hash_val[0..HASH_LEN].copy_from_slice(h.finalize().as_slice());
        let r_scalar = Scalar::from_bytes_mod_order_wide(&hash_val); // r = H(prefix || m)
        let r: CompressedEdwardsY = EdwardsPoint::mul_base(&r_scalar).compress(); // R = H(prefix || m)*B

        let mut h = HashType::new();
        h.update(r.as_bytes()); // H(R)
        h.update(self.public_key.compressed.as_bytes()); // H(R || A)
        h.update(message); // H(R || A || m)

        let mut hash_val = [0u8; 64];
        hash_val[0..HASH_LEN].copy_from_slice(h.finalize().as_slice()); // H(R || A || m)

        let h_scalar = Scalar::from_bytes_mod_order_wide(&hash_val); // h = H(R || A || m)
        let s: Scalar = (h_scalar * self.secret_scalar) + r_scalar; // s = h * a + r
        (r, s)
    }
```

### Initial Analysis: The False Lead

`HashType` is defined as SHA1. My first thought was to use an identical-chosen-prefix attack (like SHAttered) to create a collision on `r_scalar` and directly recover the secret. However, this was a dead end - we cannot control the prefix (it's part of the secret key), making collision attacks impractical.

## The Real Attack: Lattice Reduction

### Understanding the Vulnerability

SHA1 outputs **160 bits**, but the curve order is **252 bits**. This means the nonce $r$ has only 160 bits of entropy instead of the full 252 bits. This weakness allows us to use **lattice reduction (LLL)** to recover the secret key.

### The Mathematics

The signature equation in this scheme is:

$$
s = h \cdot a + r \mod l
$$

Where:
- $s$ is the signature scalar (we can observe this)
- $h = H(R \parallel A \parallel m)$ is the hash value (we can compute this)
- $a$ is the **secret key** (what we want to find)
- $r = H(\text{prefix} \parallel m)$ is the nonce (unknown, but constrained: $r < 2^{160}$)
- $l$ is the order of the curve ($2^{252} + 27742317777372353535851937790883648493$)

For multiple signatures (indexed by $i$), we can rearrange:

$$
r_i = s_i - h_i \cdot a \mod l
$$

The key insight: each $r_i$ is **small** (< $2^{160}$) compared to $l$ (≈ $2^{252}$).

### Building the Lattice

We construct a lattice where finding a short vector reveals the secret key. The lattice basis matrix is:

$$
M = \begin{pmatrix}
l & 0 & \cdots & 0 & 0 & 0 \\\\
0 & l & \cdots & 0 & 0 & 0 \\\\
\vdots & \vdots & \ddots & \vdots & \vdots & \vdots \\\\
0 & 0 & \cdots & l & 0 & 0 \\\\
-h_1 & -h_2 & \cdots & -h_n & \frac{B}{n} & 0 \\\\
s_1 & s_2 & \cdots & s_n & 0 & B
\end{pmatrix}
$$

Where $B = 2^{160}$ is the upper bound for all $r_i$ values, and $n$ is the number of signatures.

**Why this works:** A short vector in this lattice has the form:

$$
\vec{v} = (r_1, r_2, \ldots, r_n, a \cdot \frac{B}{n}, B)
$$

The LLL algorithm finds this short vector, and from it we can extract $a$ (the secret key) by looking at the second-to-last component.

## Implementation

### Step 1: Collect Multiple Signatures

We need to collect several signatures to build our lattice. For each signature, we compute the hash $h_i = H(R \parallel A \parallel m_i)$:

```python
from pwn import *
from sage.all import *
import hashlib

order = 2**252 + 27742317777372353535851937790883648493 #order of the curve

re = remote('challs.glacierctf.com', 13373)

public_key = re.recvuntil(b'msg> ')
public_key = bytes.fromhex(public_key.split(b'\n')[0].split(b': ')[1].decode())


all_values = []
result = None
dim = 10
for i in range(dim):
    msg = str(i).encode()
    re.sendline(msg)
    result = re.recvuntil(b'msg>').split(b'\n')[0].split(b': ')[1].split(b' ')
    rhash = bytes.fromhex(result[0].decode())
    s = bytes.fromhex(result[1].decode())
    s = int.from_bytes(s, 'little')
    hash = hashlib.sha1()
    hash.update(rhash)
    hash.update(public_key)
    hash.update(msg)

    h = int.from_bytes(hash.digest(), 'little') % order

    all_values.append((h, s))
```

### Step 2: Construct the Lattice Matrix and Apply LLL

Now we build the matrix $M$ as described above and run the LLL algorithm to find a short vector:

```python
# Build the lattice for solving: s_i = h_i*a + r_i (mod l)
# where r_i < 2^160

B = 1 << 160  # Upper bound for r_i
M = Matrix(QQ, dim + 2, dim + 2, 0)
for i in range(dim):
    M[i,i] = order
for i in range(dim):
    M[dim,i] = all_values[i][0]
    M[dim + 1,i] = -all_values[i][1]
M[dim,dim] = QQ(B)/QQ(order)
M[dim + 1,dim + 1] = B

# Run LLL to find short vectors
for v in M.LLL():
    # Look for the vector with B in the last position
    if v[dim+1] == B:
        if v[0] < 0:
            v = -v
        # Extract the secret key a from the second-to-last component
        scalar_find = v[dim] * QQ(order) / QQ(B)
        print("Found secret key:", scalar_find - 1)
        scalar_find = scalar_find - 1
        break
```

### Step 3: Forge a Signature to Get the Flag

With the recovered secret key $a$, we can now forge a valid signature for any message:

```python
# Forge a signature using the recovered secret key
re.sendline()
needtosign = re.recvuntil(b'signature> ')
needtosign = needtosign.split(b'\n')[0].split(b': ')[1]

# Use r = 0 for simplicity (point at infinity)
r_scalar = 0
r = 1  # Compressed Edwards Y coordinate of the point at infinity
r_signature = r.to_bytes(32, 'little')

# Compute h = H(R || A || m)
hash = hashlib.sha1()
hash.update(r_signature)
hash.update(public_key)
hash.update(needtosign)
h = int.from_bytes(hash.digest(), 'little') % order

# Compute s = h*a + r (mod order)
s = (h * scalar_find + r_scalar) % order
s_signature = s.to_bytes(32, 'little')

# Send the forged signature
re.sendline(r_signature.hex() + ' ' + s_signature.hex())
print(re.recvall())
```

## Key Takeaways

1. **Hash Function Matters**: Using SHA1 (160 bits) with a 252-bit curve creates a significant information leak
2. **LLL is Powerful**: Lattice reduction can exploit small hidden values in modular equations
3. **Multiple Samples**: The attack requires collecting multiple signatures (10 was sufficient here)
4. **Nonce Reuse Isn't Required**: Unlike some signature attacks, we don't need nonce reuse - the weakness comes from reduced entropy

## Further Reading

- [Twenty Years of Attacks on the RSA Cryptosystem](https://www.ams.org/notices/199902/boneh.pdf) - Dan Boneh (similar lattice attacks on RSA)
- [A Lattice Attack on DSA Signatures with Partially Known Nonces](https://eprint.iacr.org/2020/728.pdf)
- SageMath LLL documentation: `Matrix.LLL()`
