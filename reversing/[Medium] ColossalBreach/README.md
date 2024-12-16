<img src="../../assets/banner.png" style="zoom: 80%;" align=center />

<img src="../../assets/htb.png" style="zoom: 80%;" align='left' /><font size="6">ColossalBreach</font>

  28<sup>th</sup> 11 24 / Document No. D24.102.215

  Prepared By: 0xEr3n

  Challenge Author: 0xEr3n

  Difficulty: <font color=orange>Medium</font>

  Classification: Official






# Synopsis

ColossalBreach is a Medium reversing challenge. Players will analyze a malicious Linux kernel module provided in the form of a .ko file.
They will first understand how the keylogger works, then decode the keystrokes recorded by it.

## Skills Required
    - Use of a decompiler
    - Basic scripting
## Skills Learned
    - Linux Kernel Module analysis
    - Linux Kernel APIs

# Solution

## Question 1: Who is the module's author?

If we run `modinfo` on the `.ko` file, we're informed the author is `0xEr3n.`

## Question 2: What is the name of the function used to register keyboard events?

Opening the module in a `.ko`, we can see `register_keyboard_notifier` called in `init_module`.

## Question 3: What is the name of the function that convers keycodes to strings?

There is a function simply named `keycode_to_string`.

## Question 4: What file does the module create to store logs? Provide the full path

In `init_module`, we can see

```c
      uint64_t rax_1 = debugfs_create_dir(0xc90, 0)  {"spyyy"}
      subdir = rax_1
      
      if (rax_1 u<= -0x1000) {
          if (rax_1 == 0)
              return __x86_return_thunk() __tailcall
          
          if (debugfs_create_file(0xc96, 0x100, rax_1, 0, 0x3c0) == 0) {  {"keys"}
              debugfs_remove(subdir)
              return __x86_return_thunk() __tailcall
          }
```

The first function creates a directory in debugfs (`/sys/keynel/debug`) named `spyyy`. We then use `debugfs_create_file` to create a file named `keys` - so the answer is `/sys/keynel/debug/spyyy/keys`.

## Question 5: What message does the module print when imported?

At the end of `init_module`, there's a `printk("w00tw00t")`.

## Question 6: What is the XOR key used to obfuscate the keys? (e.g. 0x01, 0x32)

Within `spy_cb` (used as the callback for keyboard events), there is a loop XORing bytes against `0x19`.

## Question 7: What is the password entered for 'adam'?

We can XOR the logs file with `0x19` to uncover the entered keys. Near the bottom, we see `adam` entered, followed by `supers3cur3passw0rd`.
