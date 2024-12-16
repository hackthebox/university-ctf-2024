#!/usr/bin/env python3

from pwn import *
from hashlib import sha256

elf = ELF(args.BINARY)
key = list(range(256))

# First, I broke the strings, then I started bruteforcing instructions, but
# at some point we had to guess the Assembly to be able to continue efficiently.

# there are too many in the end
key[6] = 0

# We are told in a check this is the push of the routine.
key[0xB] = 0xE
key[0x2] = 9
key[0xf] = 6

# from the check as well, now we are told to look at the strings
key[8] = 2
key[5] = 0xd
key[7] = 7

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

# { // 0123456789ABCDEF string as well
key[0] = 0xb

#Bruting: 1 15
key[0xad] = 0xda
key[0xe1] = 0xf1
#Bruting: 18 15
key[0xc1] = 0x13
#Bruting: 41 15
key[0x7] = 0x7
key[0xf0] = 0xa8
key[0xa0] = 0x12
#Bruting: 104 15
key[0x77] = 0x77

#Bruting: 4 15
key[0xba] = 0xca
key[0xd8] = 0x82
key[0x16] = 0x4c
#Bruting: 25 15
key[0x16] = 0x4c
key[0xae] = 0xd8
key[0x48] = 0x54


# blx r6
key[0xc7] = 0xb0

# we now get lots of shit for free

#Bruting: 3 15
key[0xa8] = 0x3d
key[0xa4] = 0x14
key[0xaf] = 0x5b
#Bruting: 14 15
key[0xde] = 0x1a
key[0xb7] = 0xa1
key[0x4e] = 0xed
#Bruting: 27 15
key[0xc3] = 0x94
key[0xe4] = 0xee
key[0xdc] = 0xdf

#Bruting: 30 15
key[0x32] = 0x84
key[0x20] = 0x19
key[0x92] = 0x18
#Bruting: 31 15
key[0x92] = 0x18
key[0xf6] = 0xe1
key[0x71] = 0xe3

#Bruting: 8 15
key[0xc8] = 0x62
key[0x25] = 0xb3
key[0xac] = 0xff
#Bruting: 9 15
key[0x7] = 0x7
#Bruting: 13 15
key[0xc8] = 0x62
key[0x25] = 0xb3
key[0xac] = 0xff
#Bruting: 20 15
key[0xc8] = 0x62
key[0x6b] = 0xec
key[0xf1] = 0x30


#Bruting: 10 15
key[0xe8] = 0x10
key[0xca] = 0xac
key[0xec] = 0xe7
#Bruting: 16 15
key[0xc5] = 0x4f
key[0xc5] = 0x4f
key[0x7a] = 0x16
key[0xce] = 0x80
#Bruting: 19 15
key[0xd3] = 0x61
key[0x19] = 0x43
key[0xee] = 0x93
#Bruting: 21 15
key[0x86] = 0xfb
key[0xca] = 0xac

#Bruting: 5 15
key[0x4a] = 0xc1
key[0x3c] = 0xe9
key[0xbb] = 0xbd
#Bruting: 6 15
key[0x81] = 0xf8
key[0x87] = 0xf3
key[0xe9] = 0x50
#Bruting: 7 15
key[0x7f] = 0xa4
key[0xcf] = 0x11
#Bruting: 9 15
key[0x7] = 0x7
#Bruting: 11 15
key[0x7c] = 0xf4
key[0xe9] = 0x50
#Bruting: 12 15
key[0x7f] = 0xa4
key[0x78] = 0x91
#Bruting: 15 15
key[0xb0] = 0xe4
key[0xe9] = 0x50
#Bruting: 23 15
key[0x60] = 0x40
key[0x60] = 0x40
key[0x6a] = 0xc0
key[0xe9] = 0x50
key[0xe9] = 0x50
#Bruting: 28 15
key[0x7f] = 0xa4
key[0x7e] = 0xdc
key[0x17] = 0x60
#Bruting: 29 15
key[0x18] = 0x41
key[0xa3] = 0xbc
key[0x78] = 0x91
#Bruting: 39 15
key[0x80] = 0x39
key[0x6f] = 0x83
key[0x50] = 0x9b
#Bruting: 40 15
key[0x1e] = 0xdd
key[0x1e] = 0xdd
key[0x61] = 0x34
key[0xd5] = 0xa0

#Bruting: 0 15
key[0xab] = 0x2d
#Bruting: 9 15
key[0x7] = 0x7
#Bruting: 24 15
key[0xda] = 0x58
#Bruting: 26 15
key[0x1a] = 0x21
key[0x5f] = 0x38
key[0xef] = 0xf2
#Bruting: 32 15
key[0x84] = 0xb4
key[0x76] = 0xa7
#Bruting: 34 15
key[0x55] = 0x20
key[0x83] = 0x78
#Bruting: 35 15
key[0x6e] = 0x66
key[0x54] = 0x48
key[0x30] = 0x33
#Bruting: 36 15
key[0xdd] = 0xf0
key[0x30] = 0x33
#Bruting: 37 15
key[0xdd] = 0xf0
key[0x28] = 0x67
#Bruting: 41 15
key[0x7] = 0x7
#Bruting: 44 15
key[0xd9] = 0xfa

#Bruting: 17 15
key[0x9d] = 0xd9
key[0xe6] = 0x63
key[0x4d] = 0x5a
#Bruting: 22 15
key[0xd6] = 0xe8
key[0x68] = 0x81
#Bruting: 38 15
key[0xf3] = 0x68
key[0xd6] = 0xe8

#Bruting: 2 15
key[0x39] = 0x4a
key[0xcb] = 0xc3
key[0x40] = 0xa9

#Bruting: 45 15
key[0xe5] = 0x49
key[0x70] = 0x92
key[0xbd] = 0xe1


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

# I opened in IDA to check what was going around and the code at 2D2 was not being reached. So, 5002a0 branches there.
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

heh = "".join([("%02X" % x) for x in key])


print(f"KEY:\n{heh}")


for i in range(0x1000):
    if (i) & 1 == 1 or i > 0x2DC:
        elf.write(
            i + 0x500000,
            p8(
                (key[(u8(elf.read(i + 0x500000, 1)) >> 4) & 0xF] << 4)
                | (key[u8(elf.read(i + 0x500000, 1)) & 0xF])
            ),
        )
    else:
        elf.write(i + 0x500000, p8(key[u8(elf.read(i + 0x500000, 1))]))

dat = elf.read(0x500000, 0x6E0)

shas = [
"dcbb4b1a52503aff0e7c6bc56006b6fc3335cffd3b9a520e108ee091078961f1",
"6fe1161785058daaf2f1336c28122cd48db25ee006f030f53f53dc7c9b94ce88",
"e4d0e2c53288109025a863f1d45fe6b20e3ed5cc67b0c666cabb128a9b7a4b75",
"6926ed31e92b1eb26de73d6ef5f282a0e518098f46a738dbde7a0935dfc3a564",
"118c15079d3d646a095796a4cee640ce9a5a0a309970cca1e1b6f84125df9671",
"14d545528ffedcf842a965d5aec33be81fd6b55638fd3a40757d44c82dff7c1a",
"b167a9a6994cfd696a6cb57c40bcee2edab438c5abc103561b11aaa63bda5eeb",
"8e3ad5c7085a2ef5c3e89368092e9643c949a71e2e4f931bd7473f04b6f21613",
"b61430536f41fc6eab3947fe1b0ba46b4fafb6cf55e9432d5aea94254cdf95e7",
"7247e95d41505c1856202d5b04fd2622ad967bc4739654a5865aaded27cbf2c7",
"ac96dfa94d122f7a9ff273b3ae568bea9b614190b47cbde6eff524f85336b915",
"f08e6dc358ff95954252616b17b903bf8a103898e775dd6a57b40d8c7c9ffbe9",
"cf26e99f37a266e9331639d47266f45d4e1ab740d32a683fb570e66ef3ab3b50",
"16feb4507865a39f203ed57ff719aa8e4e8320c465f5683d362925de2d818f83",
"70628fcb74541b777546996c083385dd0ca63ea3e9526ff9ecfaa660eb86ec8a",
"94b452e33c07fb22db2ed0a2a79aee63a6184caa6f20b767cdc70cd6bbe31b6e",
"b67e1209fa7440f14bd6305bc9e6587356f409cc69371408c1070217e5a49a2a",
"1ac1add57365e350dfa59d558c24398d62e6a272211d9fa281de366f6f9c9e62",
"06e56df05f58dac5e46ba2d77209d199fe3a4224e79ad568009acf87538781e5",
"dbcb2ac077fbdff7b370e3421c41fb49e829095db8fd3923be621a5b9bb9e5a2",
"ad15b9d6b856479c7ce7b2eee6f697d94daa79b8c53d5d2925a7ed93edc40023",
"98a2fb2d167b7aa8dad5830f1653310acf142faffd3fd5029921d85731a3edaf",
"644c4e992eccf236985412952611f6dd357fdd9ea442476b9ad71fc15a110a6d",
"08b494ba6e8d51fe5c544e828322b6a89f330d28e238d95816666492737a34ac",
"0a82f49859806b6af2588061a86f7c4c748c6fd010e072fa5859327d23f0aaaa",
"25ce0a8346b99f72e9f70f68cb108e5f196148920b355ffe2ab758a5e35414c6",
"8866ad67dfa96582b420d7205a98a45d5b5437b05a1ea67e3b0be04368aba8b1",
"0a3c5c07b6b20bac6e07f9ff9f40fe98586f849f33e8369c594c42cd87341c4d",
"9009649eaa2dd9bfc988ce06921f80863ec5c5ff443657dbb40e7ccdba531334",
"178ec0eb6789c6f887fed8e98975715cabcb190f03f219704f60ff6da82ac61f",
"7d3647d9f7af465ae303fed13c8576aca48eb9e22639395fc880ab4cc10d5b68",
"1bff4d8354f8226efb2099838a752f18021c946d0c1abd83fc174c4bf495ba32",
"9b5b527041394066d83a1306a46f36c96ec5ef1d9deea4e6ee4d7f82c43f10b2",
"47a6f44a6b3b27d3c60e9bd9425a957f7bd1c50f19eb8624a92372c7d42b3356",
"0111a2fc0b7017511c96de797211b61f9b300ae69a6a60e67ea4587b610f375d",
"ac0de86371d668278a2050711d8b63e862dd2f9b6ad8e8242e30e00edf52f3fd",
"578eba06bde3a51e2bba6ff88e06031de90ab3449507a07e565017f679e5ff66",
"47e9d61365c79079b97440483e23809f0e71ff943f151b81a2b28bc866ccfd88",
"c367680b444851a1a1c5bbb439a98e34bc7105b7679e6cb9e2e4477ef4097f2f",
"89f5b92946b46e1d3ee47507351e449612d5410af1503d5cfa5304c0e585d28e",
"d9812b612d2802914d67fbedddb248216c37d7212a2639e875e48aeb51d560b4",
"55e708e53884001ee85a2ec6db13f52c324f2987f5d5e8d1ad65035c549b6092",
"6755abac60cb0ee5c8028255f6a1b9617501c9ec4dc9d79293e7c98514f56537",
"ae1d785149e98f3d9740d569252aea89a9a59ef6ac9d2e4e229bdb330d6865c1",
"ea550be89e601bbefc135fe4fb61acf6e1ddec5c76b6862b3b6ee0226db7ce34",
"a00527cc0c7f68d13d845b0e79f1f2b778594a7c3f80b2cdc0676b28d11f425d",
"c2f77bc3d63336dae7028684a371e93c1ab2b8020aea9371fe4e281b89bd98ec",
"3bbf587b24923a738469b1ca26683bd615f2567c89b1b52b90e25cc530e59599",
"3bbf587b24923a738469b1ca26683bd615f2567c89b1b52b90e25cc530e59599",
"aaf69e28b5161ba0171517dec4bb832c4e2ed69d0984855b29a3be1430d92a1c",
"9836f9dea091b46e6a3ae337d1b4257729af4ba905d106307cc1904809da2236",
"7381e4612e2532b276fe4569ae6d371851a2ae410ae2b39f001d3e6ab7d80419",
"7381e4612e2532b276fe4569ae6d371851a2ae410ae2b39f001d3e6ab7d80419",
"2547dd9f890833ddb0716773dcc3bde61a8d830737e9a17f539d588e2d996371",
"1dd5fb494f3a5133ff13b6896606154bf71a8cd0ac49b5f169a754f112aa95ca",
"aa93942d7f24803066523c645bee07b7d55b5828db5d2b96954465aabda7eb42",
"a520da7514f1212adbefa41f8958fd7bc7cf56e8da61999725990075eb5dbb14",
"2e7a9281cc7ff16b94d6c57281d83fb379538162a53591b509cfdb7512d04c6e",
"7095e83c5e5496048ca78f290abf320e848998e7c6a80cac9ae7d5d5022d512f",
"7fb8002c2b405dc58559abf8ca6f31d76646dd9ea235cf40a12b37abeb31a141",
"7fb8002c2b405dc58559abf8ca6f31d76646dd9ea235cf40a12b37abeb31a141",
"7fb8002c2b405dc58559abf8ca6f31d76646dd9ea235cf40a12b37abeb31a141",
"cbd378a22d3f3dd3765182df7593238cc253e8a07b88f2922978abf4bdce2aa8",
"9fde42e6f1fcb0e3bc598492da0fe1d3be27d3d94b7a63fc6b28b88b7a10041f",
"6e2edd2d6bf63896a2dd77b3375914c78df218c3463a7173ec991295d2387bdf",
"b8939cfd49fe7be232cb3bedd3ae244abe9f0bd02c67743eae4c4d6cda666217",
"db13b7fa503df5c9b3047ace69db445c75d5cb474efd5a9416290203109087d8",
"9e0f2d36383501248a4961a387effe4e8f452e06b4328d90fd09884daf28c734",
"b540b8e29a22cb256db6bafef26b60afa648dc310bcf54c78a092d564e65dd57",
"f0438345afca99a41411fea0af91de87a8a165a5ad7b8211e3b158caff93573f",
"1581039d65c51702eaf4582033883ca642df43faf6ead79730ea45c15e0cb7c5",
"626ce3930fe97e8788b613d45e809db5565df09760e51baa5b6119afce2bdeaf",
"2856f26c1573ea8b42e08b67febb79c2ca4c116c51105a0136005fd98d2c8d98",
"48d961ee484b42af28ff6afb7fccce0b9be61b6a984337ea2b4f59b5579fd63f",
"abe02ffacf0ea116539cbc4f73d066eb890d0c1ef11bcad49bf10f539982afec",
"9f76d7722e0344b9eb559f578c1719273a7750009e98c102120c897653b51030",
"f545f16ae94a837d98b48e3ae06115f5beb9cbdd549d378f60512b4b12f9da66",
"e432c21733b53496c6fc261eb590b3fbbd5fea9e8a6b05801937a7bf546e52ce",
"d0a5647a130db9dcb057f068c7b12e9856ad4d9685ba996dccb45f4d3132497a",
"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
"d33c37078dcbb56f4edb1f38778cda6ce150ee2c0bfc9bd5b7331041ee34f045",
"fcd9b1d95862d6ccb5cab60f27b42b527aca18ad8408a2ec0414cf58f9f5d4a7",
"69b5ca59375d44475ca65160c0c11e755c5087133168487d110acb69fcfffc82",
"b3031f87d0ff0bd8cd89d6ff6d6fcadc0d0d0f0b44a54f6c2a823ec4ac15753a",
"6351669b5d01de5c91fa9c1e4950aeb117cbe319823fe3b3dfd38da585758e8a",
"715067e41900a6fb245c94dd4573e004af1e3af486f7656bcb3ff5bd264f3817",
"c706b2c1e0cd4c70ae26836b66b4e03348cfa3ed2fcb54653f4ccbda0383d582",
"0b4f9fb9789a49ae98160ce2ff570d548e23b71c8b93e5894a3ed96217fe0f1c",
"d6f895a9c621ce3cd207bf08fda5b33920c20c8f77273f2583dc75da00dc6f20",
"eb2c97a93be11809f206860fd416c3a728d93be5b269c3c3bfa7f5d4135d8ef1",
"59e2c04bd20722efc55f0c0872d449299b5f03a319d1719937f70bf6392f3e65",
"082eaddf1c03bf9fbca44a100d9acddc64833993c724cf2e6b8bfb1dfec8a6bb",
"374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
]

# We have to pass checkpoints.
for i in range(0, len(dat), 16):
    if sha256(dat[i : i + 16]).digest().hex() != shas[i // 16]:
        print(f"Checkpoint #{i // 16} not passed")

elf.save("./chal_patched")
