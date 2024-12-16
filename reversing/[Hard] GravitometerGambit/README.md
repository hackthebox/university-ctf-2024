<img src="../../assets/banner.png" style="zoom: 80%;" align=center />

<img src="../../assets/htb.png" style="zoom: 80%;" align='left' /><font size="6">GravitometerGambit</font>

  5<sup>th</sup> 12 24 / Document No. D24.102.241

  Prepared By: clubby789

  Challenge Author: rafah

  Difficulty: <font color=red>Hard</font>

  Classification: Official






# Synopsis

GravitometerGambit is a Hard reversing challenge. Players will first uncover a 'password' (which is actually machine code) by using guided bruteforcing of SHA256 hashes.
Once they pass the initial stage, they must extract and solve a sudoku-like game using Z3.

## Skills Required
    - TODO
## Skills Learned
    - TODO

# Solution

By running `file` on the binary, we notice we are not dealing with an amd64 binary. So, we open IDA and start having a look.

We notice some of the symbols were left over and the binary is statically linked.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char *v3; // r7
  int v4; // r6
  int v5; // r3
  int v6; // r2
  _BYTE *v7; // r1
  int v8; // r0
  int v9; // r1
  int (*v11)(); // r5
  int v12; // r0
  _BYTE v13[116]; // [sp+10h] [bp-D0h] BYREF
  _DWORD v14[16]; // [sp+84h] [bp-5Ch] BYREF
  int v15; // [sp+C4h] [bp-1Ch]

  v15 = dword_5711F0;
  if ( mmap(0x800000, 4096, 3, 50, -1, 0) == -1 )
  {
    v8 = perror("mmap");
    goto LABEL_20;
  }
  j_memcpy(0x800000, 5242880, 4096);
  v3 = byte_57339C;
  mmap(5242880, 4096, 7, 50, -1, 0);
  v4 = 1;
  puts("https://class.ece.iastate.edu/cpre288/resources/docs/Thumb-2SupplementReferenceManual.pdf");
  puts(
    "Dear traveller, you found an old manual floating around! In order to escape from the Rocky Belt of Thumbs, you need "
    "to control the Gravitometer (me) and write the secret code. Make sure you give me the correct serial number or you w"
    "ill have to restart! There are no function calls to outside the code area (BL instruction). There is BLX (47 xx), wi"
    "th the args that were passed in and propagate inside. Are you worthy of exploding me and setting me free?");
  while ( 1 )
  {
    if ( _isoc99_scanf("%2hhX", v3) != 1 )
    {
LABEL_8:
      puts("Invalid input!");
      exit(1);
    }
    if ( (unsigned int)(v4 - 1) > 0xF )
      break;
    if ( (unsigned __int8)*v3 > 0xFu )
      goto LABEL_8;
LABEL_4:
    ++v3;
    ++v4;
  }
  if ( v4 != 256 )
    goto LABEL_4;
  v5 = 0x800000;
  do
  {
    while ( 1 )
    {
      v6 = v5 & 1;
      v7 = (_BYTE *)v5;
      if ( v5 > 8389339 )
        v6 = 1;
      ++v5;
      if ( v6 )
        break;
      *v7 = byte_57339C[(unsigned __int8)*v7];
    }
    *v7 = byte_57339C[*v7 & 0xF] | (16 * byte_57339C[(unsigned __int8)*v7 >> 4]);
  }
  while ( v5 != 8392704 );
  j_memcpy(5242880, 0x800000, 4096);
  if ( munmap(0x800000, 4096) == -1 )
  {
    v8 = perror("munmap");
  }
  else if ( sub_519580(&byte_500614) == 57
         && byte_573447 == 45
         && *((unsigned __int8 *)sub_500268 + 1) == 233
         && byte_500614 == 45
         && byte_5733A3 == 7 )
  {
    v11 = (int (*)())dword_500000;
    while ( 1 )
    {
      memset(v13, 0, 112);
      memset(v14, 0, sizeof(v14));
      v12 = sha256_init(v13);
      sha256_update(v12, v11, 16);
      sha256_final(v13, v14);
      if ( memcmp((char *)&unk_548318 + 32 * (((int)v11 - 5242880) >> 4), v14, 32) )
        break;
      v11 = (int (*)())((char *)v11 + 16);
      if ( v11 == sub_5006E0 )
      {
        puts("Go ahead!");
        sub_500268(srandom, rand, printf, _isoc99_scanf, (char *)&malloc + 1, free, exit);
      }
    }
    v8 = puts("Wrong stuff, mate! What would you like to drink?");
  }
  else
  {
    v8 = puts("A glass of cosmic vodka or a wacky beer? I would start from the strings if I were you. ;)");
  }
LABEL_20:
  if ( dword_5711F0 != v15 )
    sub_51EA20(v8, v9, dword_5711F0 ^ v15, 0);
  return 1;
}
```

The main function seems to do something fishy. It reads a "serial number" from the user, then it does some operations on the alleged serial number and compares it with some values? If the comparison is successful, it calls `sub_500268` with some functions as arguments. Otherwise, it prints a message and exits? We will get back to this in a sec.

One thing that spots out is the mmap sheningans. And we do indeed find that there is a segment `.game` at 0x500000. The 0x800000 is there as an arbitrary address to be able to patch that segment in runtime in case the binary for some reason does not have the segment as RWX.

```c
  do
  {
    while ( 1 )
    {
      v6 = v5 & 1;
      v7 = (_BYTE *)v5;
      if ( v5 > 0x8002DB )
        v6 = 1;
      ++v5;
      if ( v6 )
        break;
      *v7 = byte_57339C[(unsigned __int8)*v7];
    }
    *v7 = byte_57339C[*v7 & 0xF] | (16 * byte_57339C[(unsigned __int8)*v7 >> 4]);
  }
  while ( v5 != 0x801000 );
```

Just right over here lie the patches. It seems as though we are placing v3 at `byte_57339C` in the scanf and reading specification of bytes given by the user and then they are applied with an SBOX technique. The SBOX is either full or operates on 4bits.
During the scanf, this check indicates that the first 16 bytes form a permutation within those bytes.
```c
    if ( (unsigned __int8)*v3 > 0xFu )
      goto LABEL_8;

```


There is also a link `https://class.ece.iastate.edu/cpre288/resources/docs/Thumb-2SupplementReferenceManual.pdf`. So we probably have already concluded that this challenge might have a guess the ASM part by now. We have the SHA256 to keep our sanity. Further more a "I would start from the strings if I were you. ;)" warning and we know there are no BL instructions to outside the code area, we are informed there is "BLX" with the args that are passed. As we can see: `sub_500268(srandom, rand, printf, _isoc99_scanf, (char *)&malloc + 1, free, exit);`, the call to the `.game` code does indeed pass things.

This way, we wrote the scripts in the `solve` folder.
- The `brute.py` will brute every single window of bytes that is sha'd (they are done in intervals of 16 bytes).We just used this script while we were guessing things.
- The `patch.py` documents our progress in solving this part of the challenge, but putting the stuff we fuzzed from the strings, the things we got from `brute.py` for free as we were unveiling things and instructions that had to be guessed, because it otherwise would not make any progress (maybe it would under 4 bytes brute, but I have no patience and prefer something fast, interactive and repetitive until the moments you have to actually think).


From the checks in main, we also get some of other bytes for free.
```py
# there are too many in the end, so it's a really good heuristic to assume that they are 0 (I would not troll poor players)
key[6] = 0

# We are told in a check this is the push of the routine.
key[0xB] = 0xE
key[0x2] = 9
key[0xf] = 6

# from the check as well, now we are told to look at the strings
key[8] = 2
key[5] = 0xd
key[7] = 7

# The string section in `.game` after the code starts being unveilled
# givj -> give
key[0xa] = 0x5

# yau -> you
key[1] = 0xf

# wicc -> will
key[3] = 0xc

# newline
key[4] = 0xa

# ive -> Give
key[0xc] = 0x4

# Invmlid -> Invalid
key[0xd] = 1

# tne -> the
key[0xe] = 8

# anywer -> answer
key[0x9] = 3

# Well, those were easy words to patch up, but there is also a 0-F string for free, it seems.
# { // 0123456789ABCDEF string as well
key[0] = 0xb
```

So, after unveiling these ones, we had a lot of instructions covered already, but the code obviously did not make much sense. So we started running brute.py tons of times.
We got like 13 bytes for free from the spin, spin, spin.

Right at the beginning there is a `47 xx` instruction as we said in the main function that there would be at `0x500040`. We can brute regs to see if this is a BLX by forcing them in `patch.py` and then seeing if `brute.py` yields more results, as there is a number of bytes to be found smaller than 3 in that chunk (oh, yeah, the do.sh will print an objdump showing the bytes that were patched by encapsulating them between stars, so that we know how many are to be broken).

OK, after realizing it was `BLX R6`... By reading the manual and knowing how to encode the instruction or just by going on armconverter.com to use a simple web tool (;))... The bytes are raining like crazy, `brute.py` does not stop giving new things.

The last attempts actually required me to guess instructions (well, I know it was me who made the challenge but I generated a random SBOX and I don't really know the Assembly of what I have written, so I made a chall for myself and I still took like 2 hours to get the SBOX...). Here's a sneak peak of me schizoing and losing my sanity:
```py
# OK we are left with 33, 42 and 43.
# Let's print what is left so that we can get to the point.
# for i in key:
#     print(f"{i:#02x}, ")

# 0    1     2      3     4   5      6      7   8      9     a     b     c     d     e     f
0xb,  0xf,  0x9,  0xc,  0xa,  0xd,  0x0,  0x7,  0x2,  0x3,  0x5,  0xe,  0x4,  0x1,  0x8,  0x6, # 0
0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x4c, 0x60, 0x41, 0x43, 0x21, 0x1b, 0x1c, 0x1d, 0xdd, 0x1f, # 1
0x19, 0x21, 0x22, 0x23, 0x24, 0xb3, 0x26, 0x27, 0x67, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, # 2
0x33, 0x31, 0x84, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x4a, 0x3a, 0x3b, 0xe9, 0x3d, 0x3e, 0x3f, # 3
0xa9, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x54, 0x49, 0xc1, 0x4b, 0x4c, 0x5a, 0xed, 0x4f, # 4
0x9b, 0x51, 0x52, 0x53, 0x48, 0x20, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x38, # 5
0x40, 0x34, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x81, 0x69, 0xc0, 0xec, 0x6c, 0x6d, 0x66, 0x83, # 6
0x92, 0xe3, 0x72, 0x73, 0x74, 0x75, 0xa7, 0x77, 0x91, 0x79, 0x16, 0x7b, 0xf4, 0x7d, 0xdc, 0xa4, # 7
0x39, 0xf8, 0x82, 0x78, 0xb4, 0x85, 0xfb, 0xf3, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, # 8
0x90, 0x91, 0x18, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0xd9, 0x9e, 0x9f, # 9
0x12, 0xa1, 0xa2, 0xbc, 0x14, 0xa5, 0xa6, 0xa7, 0x3d, 0xa9, 0xaa, 0x2d, 0xff, 0xda, 0xd8, 0x5b, # a
0xe4, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xa1, 0xb8, 0xb9, 0xca, 0xbd, 0xbc, 0xe1, 0xbe, 0xbf, # b
0xc0, 0x13, 0xc2, 0x94, 0xc4, 0x4f, 0xc6, 0xb0, 0x62, 0xc9, 0xac, 0xc3, 0xcc, 0xcd, 0x80, 0x11, # c
0xd0, 0xd1, 0xd2, 0x61, 0xd4, 0xa0, 0xe8, 0xd7, 0x82, 0xfa, 0x58, 0xdb, 0xdf, 0xf0, 0x1a, 0xdf, # d
0xe0, 0xf1, 0xe2, 0xe3, 0xee, 0x49, 0x63, 0xe7, 0x10, 0x50, 0xea, 0xeb, 0xe7, 0xed, 0x93, 0xf2, # e
0xa8, 0x30, 0xf2, 0x68, 0xf4, 0xf5, 0xe1, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, # f

# There is still only one 0x9c, so maybe we can try to do 500212:       429c          cmp     r4, r3
# key[0xb4] = 0x9c
# nope

# Trying to guess the ldr, it should have the form ldrb    r2, [r1, r?] due to the 0x500... load
# key[0x9f] = 0xa2
key[0x9f] = 0x8a

# Got it
#Bruting: 33 15
key[0xb4] = 0x9d
key[0xe2] = 0xf9
key[0x8d] = 0x70

# I opened in IDA to check what was going around (since we most stuff matched already) and the code at 2D2 was not being reached. So, 5002a0 branches there.
key[0x63] = 0x17

#Bruting: 42 15
key[0x52] = 0xa2
key[0x41] = 0xf5
key[0x8c] = 0x59

# Well, at 5002b2 there is a bl, we just have to brute where it branches to.
# 500164 has no refs, maybe?
# key[0x95] = 0x55
# key[0x95] = 0x7d
# key[0x95] = 0x55

# 5002be ldr r4, [r4], ofc, due to the structure, we can already re it in ida anyway
key[0x95] = 0x24

#Bruting: 43 15
key[0xa6] = 0x57
key[0xfd] = 0x55
key[0xaa] = 0x37
```

And we terminate with something given to us for free. How amazing. Now we can start analysing the puzzle with our binary that has cleaned `.game` section.

```c
int __fastcall sub_500268(
        void (__fastcall *srand)(int),
        int (*rand)(void),
        void (__fastcall *printf)(char *),
        int (*scanf)(const char *, ...),
        void *malloc,
        int (__fastcall *free)(_DWORD *),
        void (__fastcall *exit)(int))
{
  int v9; // r7
  int v10; // r10
  int cur_value; // r0
  int *ll; // r5
  int result; // r0
  _DWORD *i; // r4
  _DWORD *v15; // r0

  v9 = 16;
  v10 = 0;
  srand(1337);
  do
  {
    while ( v10 != 0xFFFF )
    {
      cur_value = rand() & 0xF;
      if ( ((1 << cur_value) & v10) == 0 )
      {
        v10 |= 1 << cur_value;
        operates_on_list_thingies(cur_value, malloc);
      }
    }
    --v9;
  }
  while ( v9 );
  ll = board_thingies_identities;
  result = winning_function_check(printf, scanf, exit);
  do
  {
    for ( i = (_DWORD *)ll[2 * v9]; i; result = free(v15) )
    {
      v15 = i;
      i = (_DWORD *)*i;
    }
    ++v9;
  }
  while ( v9 != 16 );
  return result;
}
```

So, after reing and propagating the symbols that we get from the args (so that we understand the libc calls).
We see that we srand stuff based on 0x1337, we check if the nth bit using the randed number as n is set on v10 and if it is not we have sorted a new number until they are all full. And this way it is generating numbers between 0 and 15 in a first-come-first-served policy.

```c
int operates_on_list_thingies(int number_for_tag, void *malloc)
{
  int v2; // r9
  int v4; // r11
  int bruuuh; // r3
  int v6; // r7
  int v7; // r8
  ListThingy *v8; // r10
  int v9; // r4
  _BYTE *v10; // r5
  int v11; // t1

  v2 = dword_500064;
  v4 = number_for_tag + 1;
  bruuuh = addressor_for_v5;
  v6 = dword_500064 + 241;
  v7 = dword_500064 + 256;
  ++addressor_for_v5;
  v8 = (ListThingy *)&thingies[2 * bruuuh];
  do
  {
    v9 = v2 - 16;
    v10 = (_BYTE *)v6;
    do
    {
      v11 = *(unsigned __int8 *)++v9;
      if ( v11 == v4 )
      {
        v8->p = v10;
        number_for_tag = ((int (__fastcall *)(int))malloc)(8);
        v8->next = (struct ListThingy *)number_for_tag;
        v8 = (ListThingy *)number_for_tag;
      }
      ++v10;
    }
    while ( v9 != v2 );
    v2 = v9 + 16;
    v6 += 16;
  }
  while ( v9 + 16 != v7 );
  v8->next = 0;
  return number_for_tag;
}
```

We see that this pretty much grouping on the containers that we have in the binary memory groups identified by the numbers generated by srand in that exact order.

```
.game:005002E0 board_thingies_identities DCD thingies  ; DATA XREF: sub_500268+42↑r
.game:005002E4                 DCD 0x1010101, 0x2020202, 0x3030303, 0xD0D0D0D, 0x1010101
.game:005002F8                 DCD 0x2020202, 0x3030303, 0xD0D0D0D, 0x1010101, 0x2020202
.game:0050030C                 DCD 0x3030303, 0xD0D0D0D, 0x2010101, 0x6020202, 0x3030303
.game:00500320                 DCD 0xD0D0D0D, 0x4040401, 0x6050504, 0x8080707, 0xE0E0E0E
.game:00500334                 DCD 0x4040404, 0x6050404, 0x8080707, 0xE0E0E0E, 0x4040404
.game:00500348                 DCD 0x6050404, 0x8080707, 0xE0E0E0E, 0x9090909, 0x6050509
.game:0050035C                 DCD 0x8080707, 0xE0E0E0E, 0x9090909, 0x6050505, 0x8080707
.game:00500370                 DCD 0xF0F0F0F, 0x5090909, 0x6050505, 0x8080707, 0xF0F0F0F
.game:00500384                 DCD 0x5090909, 0x6060505, 0x8080707, 0xF0F0F0F, 0x6060609
.game:00500398                 DCD 0x6060606, 0x8080707, 0xF0F0F0F, 0xA0A0A0A, 0xB0B0B0B
.game:005003AC                 DCD 0xC0C0C0C, 0x10101010, 0xA0A0A0A, 0xB0B0B0B, 0xC0C0C0C
.game:005003C0                 DCD 0x10101010, 0xA0A0A0A, 0xB0B0B0B, 0xC0C0C0C, 0x10101010
.game:005003D4                 DCD 0xA0A0A0A, 0xB0B0B0B, 0xC0C0C0C, 0x10101010, 0xFFFFFF07
.game:005003E8                 DCD 0xFFFFFF03, 0x1FFFFFF, 0x804FF05
.game:005003F4 board_per_se    DCD 0xFFFF0B08, 0xFF0AFFFF, 0xFFFFFFFF, 0xFF09FFFF, 0x60DFFFF
.game:005003F4                                         ; DATA XREF: lines+6↑o
.game:005003F4                                         ; .game:off_5000B0↑o
.game:00500408                 DCD 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFF0F, 0xFF0CFF08
.game:0050041C                 DCD 0x6FF0AFF, 0x7FFFFFF, 0xFFFF02FF, 0xB0600FF, 0xFF0809FF
.game:00500430                 DCD 0xFF0AFFFF, 0xFFFFFFFF, 0xFF02FFFF, 0xFF050001, 0xFF0CFFFF
.game:00500444                 DCD 0xBFFFFFF, 0x2FF0DFF, 0xFFFF07FF, 0xFF06FFFF, 0xFFFFFFFF
.game:00500458                 DCD 0xF09FF07, 0xFFFFFF04, 0xFFFF03, 0xFF080400, 0xDFFFFFF
.game:0050046C                 DCD 0xFF07FFFF, 0xFF0BFF02, 0x7FFFFFF, 0xFFFF05FF, 0xFF0BFF03
.game:00500480                 DCD 0xEFF01FF, 0xFFFFFF03, 0xFFFFFF0F, 0x9FFFFFF, 0x4FFFFFF
.game:00500494                 DCD 0xFFFF0502, 0xC0107FF, 0x4FF0EFF, 0xFFFFFF00, 0xFFFFFF0B
.game:005004A8                 DCD 0x1FFFFFF, 0xFFFFFF08, 0xFFFF06FF, 0x2FFFFFF, 0x9FFFF04
.game:005004BC                 DCD 0xFFFFFF00, 0xFF05FFFF, 0xFF09FF0C, 0xFFFF03FF, 0xDFFFF0E
.game:005004D0                 DCD 0xFF00FFFF, 0xFFFF00FF, 0xFFFF0EFF, 0xBFF0CFF, 0x1FF0F07
```

We come to the conclusion this is a sudoku like game. There is a thing that groups the clusters in arbitrary forms instead of blocks and uses the numbers as identifiers.

```c
int __fastcall winning_function_check(
        void (__fastcall *printf)(char *),
        int (*scanf)(const char *, ...),
        void (__fastcall *exit)(int))
{
  char *v4; // r9
  char *v7; // r10
  char *v8; // r4
  int *cluster_list_thingies_ptr; // r12
  int v10; // r2
  int *v11; // r7
  int *v12; // r3
  int *v13; // r0
  bool v14; // zf
  _BYTE *v15; // r1
  char v16; // r0
  bool v17; // zf
  char *v18; // r3
  int v19; // t1

  v4 = off_500260[0];
  v7 = off_500260[0] + 168;
  v8 = off_500260[0];
  printf(aGiveMeTheAnswe);
  do
  {
    while ( scanf("%1hhX", v8) != 1 || (unsigned int)*v8 > 0xF )
    {
      ((void (*)(void))printf)();
      ++v8;
      exit(1);
      if ( v8 == v7 )
        goto LABEL_6;
    }
    ++v8;
  }
  while ( v8 != v7 );
LABEL_6:
  cluster_list_thingies_ptr = off_500264;
  v10 = 0;
  v11 = off_500264 - 1;
  do
  {
    v12 = (int *)*cluster_list_thingies_ptr;
    v13 = cluster_list_thingies_ptr;
    v14 = *cluster_list_thingies_ptr == 0;
    if ( *cluster_list_thingies_ptr )
      v14 = v10 == 168;
    if ( !v14 )
    {
      do
      {
        v15 = (_BYTE *)v13[1];
        if ( (char)*v15 == -1 )
        {
          v16 = *((_BYTE *)v11 + v10++ + 132);
          *v15 = v16;
        }
        v13 = v12;
        v17 = v10 == 168;
        if ( v10 != 168 )
          v17 = *v12 == 0;
        v12 = (int *)*v12;
      }
      while ( !v17 );
    }
    cluster_list_thingies_ptr += 2;
  }
  while ( v4 != (char *)cluster_list_thingies_ptr );
  v18 = (char *)off_50025C;
  do
  {
    v19 = *++v18;
    *v18 = a0123456789abcd_1[v19];
  }
  while ( v4 + 167 != v18 );
  ((void (__fastcall *)(char *, char *))printf)(aDoingIt, a0123456789abcd_1);
  if ( lines() && columns() && clusters() )
    return ((int (*)(const char *, ...))printf)("---\nYou win!\nHTB{%s}\n---\n", off_500260[0]);
  else
    return ((int (__fastcall *)(char *))printf)(aIncorrect);
}
```

After polishing the win function we notice they pretty much just go thtrough the clusters according to srand order and check our input against them. So, let's write something in Python to give to Z3... Well, it is slow as heck, but it works.

```py
from z3 import *
from collections import defaultdict
from ctypes import CDLL
from copy import deepcopy

# Z3 takes time to solve the Sudoku like puzzle but it gets there.

lc = CDLL("/usr/lib/libc.so.6")
lc.srand(1337)

# Board identification.
identification_cols = [
    [1, 1, 1, 1, 1, 4, 4, 9, 9, 9, 9, 9, 10, 10, 10, 10],
    [1, 1, 1, 1, 4, 4, 4, 9, 9, 9, 9, 6, 10, 10, 10, 10],
    [1, 1, 1, 1, 4, 4, 4, 9, 9, 9, 9, 6, 10, 10, 10, 10],
    [1, 1, 1, 2, 4, 4, 4, 9, 9, 5, 5, 6, 10, 10, 10, 10],
    [2, 2, 2, 2, 4, 4, 4, 9, 5, 5, 5, 6, 11, 11, 11, 11],
    [2, 2, 2, 2, 5, 4, 4, 5, 5, 5, 5, 6, 11, 11, 11, 11],
    [2, 2, 2, 2, 5, 5, 5, 5, 5, 5, 6, 6, 11, 11, 11, 11],
    [2, 2, 2, 6, 6, 6, 6, 6, 6, 6, 6, 6, 11, 11, 11, 11],
    [3, 3, 3, 3, 7, 7, 7, 7, 7, 7, 7, 7, 12, 12, 12, 12],
    [3, 3, 3, 3, 7, 7, 7, 7, 7, 7, 7, 7, 12, 12, 12, 12],
    [3, 3, 3, 3, 8, 8, 8, 8, 8, 8, 8, 8, 12, 12, 12, 12],
    [3, 3, 3, 3, 8, 8, 8, 8, 8, 8, 8, 8, 12, 12, 12, 12],
    [13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15, 16, 16, 16, 16],
    [13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15, 16, 16, 16, 16],
    [13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15, 16, 16, 16, 16],
    [13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15, 16, 16, 16, 16],
]

# Make sure that there are only 16 of each numeration
verif = defaultdict(lambda: 0)
for l in identification_cols:
    for n in l:
        verif[n] = verif[n] + 1

# Assert board positioning
assert(all([x in verif for x in range(1, 10)]))
assert(all([verif[x] == 16 for x in range(1, 10)]))

# Generate board.
cols = []
for i in range(16):
    cols.append([Int(f'c_{i}_l_{j}') for j in range(16)])


curs = [
    (0, 0, 7), 
    (0, 1, 8), 
    (0, 3, 15), 
    (1, 1, 11), 
    (2, 2, 13), 
    (3, 2, 6), 
    (4, 0, 3), 
    (4, 3, 8), 
    (6, 1, 10), 
    (6, 3, 12), 
    (9, 3, 10), 
    (11, 0, 1), 
    (11, 3, 6),
    (1, 4, 2), 
    (3, 6, 11), 
    (5, 6, 13), 
    (3, 9, 7),
    (4, 10, 15), 
    (5, 4, 0), 
    (5, 9, 5), 
    (6, 4, 6), 
    (6, 5, 2), 
    (6, 7, 9), 
    (1, 11, 5), 
    (5, 11, 7), 
    (6, 11, 1), 
    (7, 4, 11), 
    (7, 6, 2), 
    (7, 7, 15), 
    (7, 8, 13), 
    (7, 11, 12), 
    (8, 5, 1), 
    (8, 7, 4), 
    (8, 9, 3), 
    (9, 4, 9), 
    (9, 5, 0), 
    (9, 6, 7), 
    (9, 11, 14), 
    (10, 4, 8), 
    (10, 5, 5), 
    (10, 8, 7), 
    (10, 9, 11), 
    (11, 10, 9), 
    (11, 11, 4), 
    (0, 8, 0), 
    (0, 10, 3), 
    (0, 11, 2), 
    (1, 8, 4), 
    (2, 8, 8), 
    (4, 7, 7), 
    (0, 12, 11), 
    (0, 14, 12), 
    (1, 15, 0), 
    (2, 14, 9), 
    (3, 13, 2), 
    (4, 13, 4), 
    (5, 14, 3), 
    (5, 15, 14), 
    (7, 12, 1), 
    (7, 13, 9), 
    (8, 12, 8), 
    (8, 13, 0), 
    (8, 14, 14), 
    (9, 15, 12), 
    (11, 14, 13), 
    (11, 15, 11), 
    (12, 0, 5), 
    (14, 0, 4), 
    (14, 1, 9), 
    (15, 0, 8), 
    (15, 3, 7), 
    (12, 7, 3),
    (14, 4, 10),
    (14, 5, 12), 
    (14, 6, 6), 
    (15, 7, 0), 
    (12, 8, 2), 
    (12, 11, 0), 
    (13, 9, 1), 
    (14, 8, 11), 
    (15, 9, 14), 
    (15, 10, 4), 
    (12, 15, 7), 
    (13, 12, 6), 
    (13, 15, 15), 
    (14, 13, 5), 
    (14, 14, 0), 
    (15, 15, 1)
]

s = Solver()

cols2 = deepcopy(cols)
# Add known board state.
for n in curs:
    s.add(cols[n[0]][n[1]] == n[2])
    cols2[n[0]][n[1]] = n[2]

# Make sure them all are between 0 and 15 and they are different.
for i in range(16):
    for j in range(16):
        s.add(And(cols[i][j] >= 0, cols[i][j] <= 15))
    # Distinct columns.
    s.add(Distinct(cols[i]))

# Distinct lines.
for i in range(16):
    s.add(Distinct([cols[j][i] for j in range(16)]))

# Group clusters.
cluster = defaultdict(lambda: [])
for i in range(16):
    for j in range(16):
        cluster[identification_cols[i][j]].append(cols[i][j])

# Distinct in cluster.
for k in cluster:
    s.add(Distinct(cluster[k]))


# Check if solution exists
solution = [
    [7, 8, 10, 15, 4, 6, 14, 13, 0, 9, 3, 2, 11, 1, 12, 5],
    [14, 11, 9, 3, 2, 7, 8, 12, 4, 15, 1, 5, 10, 13, 6, 0],
    [2, 1, 13, 5, 12, 4, 0, 14, 8, 6, 11, 10, 7, 15, 9, 3],
    [0, 12, 6, 1, 3, 15, 11, 5, 10, 7, 13, 9, 14, 2, 8, 4],
    [3, 14, 11, 8, 1, 9, 5, 7, 12, 10, 15, 6, 0, 4, 2, 13],
    [15, 4, 2, 9, 0, 10, 13, 11, 1, 5, 8, 7, 12, 6, 3, 14],
    [13, 10, 5, 12, 6, 2, 3, 9, 14, 4, 0, 1, 15, 11, 7, 8],
    [6, 7, 0, 4, 11, 3, 2, 15, 13, 8, 14, 12, 1, 9, 5, 10],
    [9, 15, 7, 2, 13, 1, 10, 4, 5, 3, 12, 11, 8, 0, 14, 6],
    [11, 13, 4, 10, 9, 0, 7, 8, 15, 2, 6, 14, 5, 3, 1, 12],
    [12, 3, 14, 0, 8, 5, 1, 6, 7, 11, 2, 13, 4, 10, 15, 9],
    [1, 5, 8, 6, 15, 14, 12, 10, 3, 0, 9, 4, 2, 7, 13, 11],
    [5, 6, 1, 11, 14, 13, 15, 3, 2, 12, 10, 0, 9, 8, 4, 7],
    [10, 0, 12, 13, 7, 8, 4, 2, 9, 1, 5, 3, 6, 14, 11, 15],
    [4, 9, 15, 14, 10, 12, 6, 1, 11, 13, 7, 8, 3, 5, 0, 2],
    [8, 2, 3, 7, 5, 11, 9, 0, 6, 14, 4, 15, 13, 12, 10, 1],
]

lc.srand(1337)

stuffs = []

print("Checking")
if s.check() == sat:
    print("Done")
    
    m = s.model()
    solution = [[m.evaluate(cols[i][j]).as_long() for j in range(16)] for i in range(16)]

    for s in solution:
        print(s)
    flag = "HTB{"
    while len(stuffs) != 16:
        cur = (lc.rand() % 16) + 1
        if cur not in stuffs:
            stuffs.append(cur)
            for j in range(len(solution)):
                for i in range(len(solution)):
                    if identification_cols[i][j] == cur and type(cols2[i][j]) != int:
                        flag += ("%1X" % (solution[i][j]))
    flag += "}"
    print(flag)
else:
    print("No solution found")
```

There we go!
