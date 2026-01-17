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


## Writeup du Challenge GlacierCTF : SignMeUp

### Vue d'ensemble du Challenge

Ce challenge implique l'exploitation d'une implémentation EdDSA personnalisée qui utilise SHA1 au lieu de SHA512. La vulnérabilité provient du décalage entre la taille de sortie du hash (160 bits) et l'ordre de la courbe (252 bits).

### Le Code du Challenge

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

### Analyse Initiale : La Fausse Piste

`HashType` est défini comme SHA1. Ma première idée était d'utiliser une attaque par collision avec préfixe choisi identique (comme SHAttered) pour créer une collision sur `r_scalar` et récupérer directement le secret. Cependant, c'était une impasse - on ne peut pas contrôler le préfixe (il fait partie de la clé secrète), rendant les attaques par collision impraticables.

## L'Attaque Réelle : Réduction de Réseau

### Comprendre la Vulnérabilité

SHA1 produit **160 bits**, mais l'ordre de la courbe est de **252 bits**. Cela signifie que le nonce $r$ n'a que 160 bits d'entropie au lieu des 252 bits complets. Cette faiblesse nous permet d'utiliser la **réduction de réseau (LLL)** pour récupérer la clé secrète.

### Les Mathématiques

L'équation de signature dans ce schéma est :

$$
s = h \cdot a + r \mod l
$$

Où :
- $s$ est le scalaire de signature (on peut l'observer)
- $h = H(R \parallel A \parallel m)$ est la valeur de hash (on peut la calculer)
- $a$ est la **clé secrète** (ce qu'on veut trouver)
- $r = H(\text{prefix} \parallel m)$ est le nonce (inconnu, mais contraint : $r < 2^{160}$)
- $l$ est l'ordre de la courbe ($2^{252} + 27742317777372353535851937790883648493$) ([Curve Ed25519](https://ed25519.cr.yp.to/ed25519-20110926.pdf))

Pour plusieurs signatures (indexées par $i$), on peut réarranger :

$$
r_i = s_i - h_i \cdot a \mod l
$$

L'intuition clé : chaque $r_i$ est **petit** (< $2^{160}$) comparé à $l$ (≈ $2^{252}$).

### Construction du Réseau

On construit un réseau où trouver un vecteur court révèle la clé secrète. La matrice de base du réseau est :

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

Où $B = 2^{160}$ est la borne supérieure pour toutes les valeurs de $r_i$, et $n$ est le nombre de signatures.

**Pourquoi ça marche :** Un vecteur court dans ce réseau a la forme :

$$
\vec{v} = (r_1, r_2, \ldots, r_n, a \cdot \frac{B}{n}, B)
$$

L'algorithme LLL trouve ce vecteur court, et on peut en extraire $a$ (la clé secrète) en regardant l'avant-dernière composante.

## Implémentation

### Étape 1 : Collecter Plusieurs Signatures

On doit collecter plusieurs signatures pour construire notre réseau. Pour chaque signature, on calcule le hash $h_i = H(R \parallel A \parallel m_i)$ :

```python
from pwn import *
from sage.all import *
import hashlib

order = 2**252 + 27742317777372353535851937790883648493 #ordre de la courbe

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

### Étape 2 : Construire la Matrice du Réseau et Appliquer LLL

Maintenant on construit la matrice $M$ comme décrit ci-dessus et on exécute l'algorithme LLL pour trouver un vecteur court :

```python
# Construction du réseau pour résoudre : s_i = h_i*a + r_i (mod l)
# où r_i < 2^160

B = 1 << 160  # Borne supérieure pour r_i
M = Matrix(QQ, dim + 2, dim + 2, 0)
for i in range(dim):
    M[i,i] = order
for i in range(dim):
    M[dim,i] = all_values[i][0]
    M[dim + 1,i] = -all_values[i][1]
M[dim,dim] = QQ(B)/QQ(order)
M[dim + 1,dim + 1] = B

# Exécuter LLL pour trouver des vecteurs courts
for v in M.LLL():
    # Chercher le vecteur avec B à la dernière position
    if v[dim+1] == B:
        if v[0] < 0:
            v = -v
        # Extraire la clé secrète a de l'avant-dernière composante
        scalar_find = v[dim] * QQ(order) / QQ(B)
        print("Clé secrète trouvée:", scalar_find - 1)
        scalar_find = scalar_find - 1
        break
```

### Étape 3 : Forger une Signature pour Obtenir le Flag

Avec la clé secrète $a$ récupérée, on peut maintenant forger une signature valide pour n'importe quel message :

```python
# Forger une signature en utilisant la clé secrète récupérée
re.sendline()
needtosign = re.recvuntil(b'signature> ')
needtosign = needtosign.split(b'\n')[0].split(b': ')[1]

# Utiliser r = 0 pour simplifier (point à l'infini)
r_scalar = 0
r = 1  # Coordonnée Y compressée d'Edwards du point à l'infini
r_signature = r.to_bytes(32, 'little')

# Calculer h = H(R || A || m)
hash = hashlib.sha1()
hash.update(r_signature)
hash.update(public_key)
hash.update(needtosign)
h = int.from_bytes(hash.digest(), 'little') % order

# Calculer s = h*a + r (mod order)
s = (h * scalar_find + r_scalar) % order
s_signature = s.to_bytes(32, 'little')

# Envoyer la signature forgée
re.sendline(r_signature.hex() + ' ' + s_signature.hex())
print(re.recvall())
```

## Points Clés à Retenir

1. **La Fonction de Hachage Compte** : Utiliser SHA1 (160 bits) avec une courbe de 252 bits crée une fuite d'information significative
2. **LLL est Puissant** : La réduction de réseau peut exploiter de petites valeurs cachées dans des équations modulaires
3. **Plusieurs Échantillons** : L'attaque nécessite de collecter plusieurs signatures (10 étaient suffisantes ici)
4. **Pas Besoin de Réutilisation de Nonce** : Contrairement à certaines attaques sur les signatures, on n'a pas besoin de réutilisation de nonce - la faiblesse vient de l'entropie réduite

## Pour Aller Plus Loin

- [Twenty Years of Attacks on the RSA Cryptosystem](https://www.ams.org/notices/199902/boneh.pdf) - Dan Boneh (attaques par réseau similaires sur RSA)
- [A Lattice Attack on DSA Signatures with Partially Known Nonces](https://eprint.iacr.org/2020/728.pdf)
- Documentation SageMath LLL : `Matrix.LLL()`
