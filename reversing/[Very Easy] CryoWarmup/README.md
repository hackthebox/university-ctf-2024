<img src="../../assets/banner.png" style="zoom: 80%;" align=center />

<img src="../../assets/htb.png" style="zoom: 80%;" align='left' /><font size="6">CryoWarmup</font>

  10<sup>th</sup> 12 24 / Document No. D24.102.244

  Prepared By: clubby

  Challenge Author: clubby

  Difficulty: <font color=green>Very Easy</font>

  Classification: Official






# Synopsis

CryoWarmup is a Very Easy reversing challenge. Players will answer quiz questions on reverse engineering fundamentals.

## Skills Learned
    - Basics of assembly and decompilers

# Solution

## 1. What libc function is used to check if the password is correct?

`strcmp` is called within `validate_password`

## 2. What is the size of the password buffer, based on the argument to `scanf`?

`%49s` is used as the `scanf` format string, so the length is 49 bytes

## 3. What is the name of the function that modifies the user's input?

`generate_key` takes a pointer to the user input and performs XOR/addition operations on it

## 4. What would be the result of applying the operation from this function to a string containing one character, 'B'? Provide your answer as a hex number, e.g. `0x4f`.

Using Python, `hex((ord('B') ^ 0x2a) + 5)` gives us `0x6d`

## 5. What is printed if the password is correct?

The program prints 'Access granted!'

## 6. How long is the password, based on the value that the user's input is compared against (not including the final null byte)?

The value compared against is 8 bytes long.

## 7. What is the password?

We can use Python to invert the transformation:

```py
>>> secret = [71, 32, 83, 83, 30, 73, 95, 98]
>>> decoded = bytes([(s - 5) ^ 0x2a for s in secret])
>>> decoded
b'h1dd3npw'
```

The password is `h1dd3npw`.
