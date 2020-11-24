---
layout: post
title:  "Bit Flip I - WriteUp"
description: "Solución del reto Bit Flip I de Dragon CTF 2020"
author: alguien
date:   2020-11-22 18:00:00 -0500
categories: writeup
image: uploads/DragonCTF2020/dragonctf2020.png
---

<!--more-->

## Descripción

![]({{ 'uploads/DragonCTF2020/bitflip1.png' | relative_url }})

Descarga: [task.tgz]({{ 'uploads/DragonCTF2020/bitflip1.tgz' | relative_url }})

## Análisis

Alice y Bob utilizan Diffie Hellman para establecer una clave compartida (`alice.shared`) la
cual se emplea para cifrar el flag con AES. El programa nos entrega el flag cifrado y el IV.
Entonces para descifrar el flag únicamente necesitamos la clave compartida.

> ### Diffie Hellman
> Para que Alice y Bob puedan establecer un secreto compartido con Diffie Hellman necesitan dos
> números primos $p$ y $g$ conocidos como el módulo y la base. Luego Alice y Bob deben elegir
> cada uno un exponente privado ($a$ y $b$ respectivamente) y calcular sus claves públicas como sigue:
>
> $A = g ^ a (p)$
>
> $B = g ^ b (p)$
>
> Entonces Alice y Bob intercambian sus clave públicas $A$ y $B$ y calculan el secreto compartido
> $K$ como se muestra:
>
> $K = B^a (p) = A^b (p) = g^{a*b} (p)$

Para calcular la clave compartida, el programa nos entrega la clave pública de Bob ($B$) y en el
código podemos ver que la base es $5$. Por lo que nos faltan el módulo $p$ y el exponente privado de
Alice $a$. Ambos números se generan aleatoriamente utilizando un PRNG. El PRNG se inicializa con
una semilla que depende de la variable `alice_seed` y una entrada dada por nosotros. La variable
`alice_seed` contiene 16 bytes aleatorios que no cambian durante la ejecución del programa. Si
logramos obtener el valor de `alice_seed`, podemos inicializar el PRNG correctamente y generar los
parámetros $p$ y $a$ que nos faltan.

El programa nos deja jugar con el PRNG haciendole XOR a la semilla con un valor enviado por
nosotros y nos muestra el número de iteraciones que fueron necesarias hasta que el PRNG generó
un número primo aleatorio de 512 bits. Además podemos repetir esta operación tantas veces
como queramos.

$$
seed = alice\_seed \oplus input \\
PRNG( seed )
$$

El PRNG internamente usa SHA256 para generar bits aleatorios. Básicamente entrega el hash SHA256 del
seed. Así que en cada llamada solo puede generar 256 bits aleatorios. Luego de cada llamada el seed
se incrementa en 1. Entonces, para generar números de 512 bits son necesarias 2 llamadas al PRNG.
Luego, si $p_n$ es el número primo generado por el PRNG, se habrán necesitado $n+1$ iteraciones y
serían como se muestra a continuación:

$$
p_0 = SHA256(seed)\ |\ SHA256(seed + 1) \\
p_1 = SHA256(seed + 2)\ |\ SHA256(seed + 3) \\
p_2 = SHA256(seed + 4)\ |\ SHA256(seed + 5) \\
... \\
p_n = SHA256(seed + 2n)\ |\ SHA256(seed + 2n + 1)
$$

La idea es extraer el valor de `alice_seed` bit a bit utilizando la operación XOR. Se hacen dos consultas
al PRNG: una invirtiendo el valor del bit que se desea extraer (haciendole XOR con 1) y otra con el valor
del bit sin modificar (haciendole XOR con 0) y se observa como cambia el número de iteraciones que realiza
el programa. Sin embargo es necesario asignar convenientemente los bits conocidos de modo que la variación
en el número de iteraciones sea predecible.

> **Nota:** El bit menos significativo no se puede extraer con este método. Por lo que al final tendremos
> dos posibles valores para `alice_seed` y simplemente probaremos con ambos.

Suponiendo que $x$ son bits desconocidos, $y$ es el bit que se desea extraer, $1$ y $0$ son bits que ya se
obtuvieron y $z$ es el bit menos significativo (que no se puede obtener). Entonces:

**Primera consulta:** Se envía un $input$ de modo que $y$ no se modifique y los bits en posiciones menos
significativas (ya conocidos) cambien a $0$ a excepción de $z$ que debe conservar su valor.

$$
alice\_seed = ...xxxxy10z \\
input = ...00000100 \\
seed = alice\_seed \oplus input = ...xxxxy00z
$$

**Segunda consulta:** Se envía un $input$ tal que $y$ invierta su valor y los bits menos significativos
cambien a $1$ excepto $z$ que debe mantenerse igual.

$$
alice\_seed = ...xxxxy10z \\
input = ...00001010 \\
seed = alice\_seed \oplus input = ...xxxx\overline{y}11z
$$

De este modo hemos conseguido que el seed pasado al PRNG sea $...xxxxy00z$ en la primera consulta y
$...xxxx\overline{y}11z$ en la segunda. Si $y$ fuera $1$ los seeds serían $...xxxx100z$ y $...xxxx011z$.
Es decir, su diferencia es exactamente 2. Esto lo observaremos como una iteración adicional en la segunda
consulta. Por otra parte si $y$ fuera $0$ los seeds serían $...xxxx000z$ y $...xxxx100z$. Es decir, su
diferencia irá aumentando exponencialmente conforme se consulten bits más significativos y no es posible
predecir como cambiará el número de iteraciones.

## Solución

Programamos un script que utiliza el comportamiento descrito anteriormente para obtener el valor de
`alice_seed`. Por claridad, he omitido el código de resolución de la prueba de trabajo con hashcash.

```python
from Crypto.Util.number import long_to_bytes
import socket
import base64
import re

def get_iters(data):
    return int(re.findall(b'Generated after ([0-9]+) iterations', data)[0])

def send_data(sock, n):
    sock.send(base64.b64encode(long_to_bytes(n)) + b'\n')
    data = sock.recv(2048)
    print(data.decode())
    return get_iters(data)

target = ('bitflip1.hackable.software', 1337)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(target)

# solve_proof_of_work(sock)
print(sock.recv(2048).decode())

seed = 0
for exp in range(1, 16*8):
    base = send_data(sock, seed)
    comp = send_data(sock, ((1 << (exp + 1)) - 1) ^ seed ^ 1)
    if (comp - base) == 1:
        seed = seed + (1 << exp)

print('Posible SEEDs: ')
print(seed)
print(seed ^ 1)

sock.close()
```

**Salida:**
```text
Resolviendo prueba de trabajo: ambmccwu
Solucion: 1:28:201123:ambmccwu::751bjy4nvizlNxIn:00000000DQxpq
bit-flip str:

Generated after 443 iterations
bob number 910264802843302543727715012778515024668672985500518212480436126224326541525112880873528145314566435381118149458984913711881309782988969961649614081111546
wbJewa+i26OHQNtWGG9+SQ==
pTZuhWOkhSQ7iXBjNmuHRBqUTCWZQqWdXkmX9dtF0WeleuPfLGUcNzCu6KTi2N9/
bit-flip str:

Generated after 442 iterations
bob number 636260678472818242123736830981846047843023684973809856185880407799102862692695801013365011115927995667882107127503776363614358811653031945119466185001697
fvP3tBlqEIs1brhLXgbL+w==
9B6EZZOQGaJ1fSPmzfz9YwS4R2y2q/InDz1B2vrFHHbHLJzEBhOyfzyIo39Xe+kn
bit-flip str:

[...]

Posible SEEDs: 
150375249166091944136940550518837195688
150375249166091944136940550518837195689
```

Luego modificamos el archivo `task.py` para descifrar el flag y asignamos el seed obtenido.

```python
[...]

alice_seed = long_to_bytes(150375249166091944136940550518837195689, 16)

alice = DiffieHellman(alice_seed)
alice.set_other(910264802843302543727715012778515024668672985500518212480436126224326541525112880873528145314566435381118149458984913711881309782988969961649614081111546)

iv = base64.b64decode('wbJewa+i26OHQNtWGG9+SQ==')
flag = base64.b64decode('pTZuhWOkhSQ7iXBjNmuHRBqUTCWZQqWdXkmX9dtF0WeleuPfLGUcNzCu6KTi2N9/')

cipher = AES.new(long_to_bytes(alice.shared, 16)[:16], AES.MODE_CBC, IV=iv)
print(cipher.decrypt(flag))
```

**Salida:**
```text
Generated after 443 iterations
b'DrgnS{T1min9_4ttack_f0r_k3y_generation}\n        '
```

> **FLAG:** `DrgnS{T1min9_4ttack_f0r_k3y_generation}`


Gracias a R.E. de [@ID-10-T](https://twitter.com/id10t_ctf) por mostrarme el camino.