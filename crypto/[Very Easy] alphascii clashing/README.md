![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='5'>alphascii clashing</font>

​	25<sup>th</sup> September 2024 / Document No. D24.102.229

​	Prepared By: `rasti`

​	Challenge Author: `rasti`

​	Difficulty: <font color=lightgreen>Very Easy</font>

​	Classification: Official







# Synopsis

- `alphascii clashing` is a very easy crypto challenge. The name of the challenge hints the players that they probably have to find an MD5 collision. However, there is a small twist; the input strings must be alphanumeric. With minimal research, one should be able to find two 72-byte alphanumeric strings that differ by a single byte and produce an MD5 collision.

# Description

- The Frontier Board's grip on the stars relies on a digital relic thought to be flawless. But in the depths of the void, anomalies can ripple through even the most secure systems. Do you have what it takes to expose the cracks in their so-called perfection?



## Skills Required

- Basic Python source code analysis.
- Know how to research with the right keywords based on the hints provided.



## Skills Learned

- Learn about MD5 collisions produced by alphanumeric inputs.



# Enumeration

In this challenge, we are provided with a single file:

- `server.py` : This is the python script that runs when we connect to the challenge instance.

## Analyzing the source code

Let us first analyze the source code which is not lengthy.

First, a dictionary-based database is initialized with two registered users.

```python
'''
Data format:
{
    username: [md5(username).hexdigest(), password],
    .
    .
    .
}
'''
users = {
    'HTBUser132' : [md5(b'HTBUser132').hexdigest(), 'secure123!'],
    'JohnMarcus' : [md5(b'JohnMarcus').hexdigest(), '0123456789']
}
```

The comment tells us how the data is stored in this minimal database. Then, there is the `get_option()` function which shows the main menu and provides us with three options to choose from; login, register and exit.

```python
def get_option():
    return input('''
    Welcome to my login application scaredy cat ! I am using MD5 to save the passwords in the database.
                          I am more than certain that this is secure.                       
                                   You can't prove me wrong!          
    
    [1] Login
    [2] Register
    [3] Exit

    Option (json format) :: ''')
```

The core body of the main method is shown below:

```python
def main():
    while True:
        option = json.loads(get_option())

        if 'option' not in option:
            print('[👾] please, enter a valid option!')
            continue

        option = option['option']
        if option == 'login':
            # ...
        
        elif option == 'register':
            # ...

        elif option == 'exit':
            print('byeee.')
            break
```

We will analyze the logic of `login` and `register` separately. Let us start with the `register` option.

```python
elif option == 'register':
    creds = json.loads(input('enter credentials (json format) :: '))

    usr, pwd = creds['username'], creds['password']
    if usr.isalnum() and pwd.isalnum():
        usr_hash = md5(usr.encode()).hexdigest()
        if usr not in users.keys():
            users[usr] = [md5(usr.encode()).hexdigest(), pwd]
        else:
            print('[👾] this user already exists!')
    else:
        print('[👾] your credentials must contain only ascii letters and digits.')
```

The user is asked to provide their credentials (username and password) in json format.

The line `if usr.isalnum() and pwd.isalnum():` tells us that the username and password must be alphanumeric. We will see that this is crucial for solving the challenge as it provides extra research keywords to the players.

Last but not least, if the provided username does not already exist in the database, the user is saved in the database along with the username hash and password. See the comment above the database initialization to recall the data format.

The `login` option is presented below:

```python
if option == 'login':
    creds = json.loads(input('enter credentials (json format) :: '))

    usr, pwd = creds['username'], creds['password']
    usr_hash = md5(usr.encode()).hexdigest()
    for db_user, v in users.items():
        if [usr_hash, pwd] == v:
            if usr == db_user:
                print(f'[🍫] welcome, {usr} 🤖!')
            else:
                print(f"[🍫] what?! this was unexpected. shutting down the system :: {FLAG} 👽")
                exit()
            break
    else:
        print('[👾] invalid username and/or password!')
```

Again, the user is asked to provide their credentials (username and password) in json format.

Then, the username is MD5-hashed and the database records are iterated one by one. First, there is a check whether the hash of the provided username and the provided password match any existing record. If yes, then:

- If the plaintext username matches the username stored in the database, the user is successfully logged in.
- If not, it looks like we fell into an unexpected behavior that shuts down the application and outputs the flag.

This is the entire logic of the application. As we are interested in getting the flag, let us reconsider what would cause the system shutdown and therefore the flag leakage.

We have to provide a username and a password such that:

- The hash of the provided username and the provided password exist in some record of the database, say the $i$-th one.
- The provided username does not match to the username of the $i$​-th record.

The choice of password is not strict as the only requirement is to exist in the database. This means that we can summarize the goal of the challenge to the following sentence:

*We have to provide a username, say `usr`, such that `md5('usr')` exists in the database in the $i$-th record, but the username stored in the $i$-th record is not `usr`.*

# Solution

## Finding the vulnerability

Since the username stored in the $i$-th record must not be `usr`, but yet its hash has to exist in the database, it means that we have to register at least two users in the database to solve the challenge.

These users should have different usernames, same username hashes but their passwords must be the *same* because of the check `if [usr_hash, pwd] == v`.

In other words, let the following record in the database.

```python
'usr1' : [md5(b'usr1').hexdigest(), 'password']
```

The task is to craft the following record:

```python
'usr2' : [md5(b'usr2').hexdigest(), 'password']
```

such that `md5('usr1') = md5('usr2')`.

At first glance, this sounds a bit tricky but let us recall the name of the challenge and the hash function being utilized; that is `collision` and `MD5`. It is well known that MD5 is vulnerable to collisions. A collision can be described as:

*Find two different inputs $x \neq y$ such that $H(x) = H(y)$​.*

The task of the challenge is similar to the definition of the collision so that should be our way to go.

## Finding alphanumeric MD5 collisions

[This](https://en.wikipedia.org/wiki/MD5#Collision_vulnerabilities) wikipedia article showcases a popular MD5 collision for two different inputs. However, these inputs are raw bytes and not all of them can be represented by ASCII. In our challenge, we have the limitation that the username and password must be *alphanumeric*.

With minimal research using the proper keywords, such as `md5 alphanumeric collisions`, we end up to quite a few results ([[1]](https://x.com/realhashbreaker/status/1770161965006008570) or [[2]](https://www.johndcook.com/blog/2024/03/20/md5-hash-collision/)) that look promising. The twitter post claims that there is an 72-byte MD5 alphanumeric collision. Let us test verify whether this holds (of course it does):

```python
>>> from hashlib import md5
>>> inp1 = b'TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak'
>>> inp2 = b'TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak'
>>> inp1 != inp2 and md5(inp1).hexdigest() == md5(inp2).hexdigest()
True
```

In fact, one can find many more such collisions using the open-source [tool](https://github.com/cr-marcstevens/hashclash) of the author.

# Exploitation

Right now, we should have a good grasp of how to solve the challenge. The steps are:

- Register a user with username the first alphanumeric input that produces the MD5 collision and any password of your choice.
- Register a user with username the second alphanumeric input that produces the MD5 collision and the same password as the first user.
- Login as the second user.

The reason for logging in as the second user has to do with the way items are stored in dictionaries. After the two registrations, the database should look like:

```python
{
    'HTBUser132' : [md5(b'HTBUser132').hexdigest(), 'secure123!'],
    'JohnMarcus' : [md5(b'JohnMarcus').hexdigest(), '0123456789'],
    'TEXTCOLL...A...Knak' : [md5(b'TEXTCOLL...A...Knak').hexdigest(), 'password'],
    'TEXTCOLL...E...Knak' : [md5(b'TEXTCOLL...E...Knak').hexdigest(), 'password'],
}
```

with `md5(b'TEXTCOLL...A...Knak').hexdigest() = md5(b'TEXTCOLL...E...Knak').hexdigest()`.

The hashes and the passwords of the two users match so the condition `if [usr_hash, pwd] == v` is satisfied for the first user that occurs in the database and that is User 1. User 1 and User 2 have different usernames so we should be able to shut down the system and access the flag.

Let us write a function that implements the steps described above.

```python
import json

usr_1 = 'TEXTCOLL...A...AuaKnak'
usr_2 = 'TEXTCOLL...E...AuaKnak'

def get_flag():
    io.sendlineafter(b' :: ', json.dumps({'option': 'register'}).encode())
    io.sendlineafter(b' :: ', json.dumps({'username': usr_1, 'password': 'password'}).encode())
    io.sendlineafter(b' :: ', json.dumps({'option': 'register'}).encode())
    io.sendlineafter(b' :: ', json.dumps({'username': usr_2, 'password': 'password'}).encode())
    io.sendlineafter(b' :: ', json.dumps({'option': 'login'}).encode())
    io.sendlineafter(b' :: ', json.dumps({'username': usr_2, 'password': 'password'}).encode())
    return io.recvline().decode().strip().split(' :: ')[-1]
```

## Getting the flag

A final summary of all that was said above:

1. Notice that the challenge name and the hash function being used are hints for the solution.
2. Based on the authentication algorithm, translate the path for shutting down the system into finding an alphanumeric MD5 collision.
3. Finding the actual collision requires minimal research using the right keywords.
4. Register two users with same passwords and usernames being the two inputs that produce the collision and login as the second one to get the flag.

This recap can be represented by code with the `pwn()` function:

```python
from pwn import *

io = None

def pwn():
    flag = get_flag()
    print(flag)

if __name__ == '__main__':
    if args.REMOTE:
        host_port = sys.argv[1].split(':')
        HOST = host_port[0]
        PORT = host_port[1]
        io = remote(HOST, PORT, level='error')
    else:
        import os
        os.chdir('../challenge')
        io = process(['python3', 'server.py'], level='error')

    pwn()
```
