# 1. Firmware Parsing

추출된 gen3의 파티션을 확인하면 UBI 헤더가 존재한다.

![image.png](Img/image.png?raw=true)

ubi 추출에는 [UBI Forensic Toolkit](https://github.com/matthias-deu/ubift?tab=readme-ov-file)툴을 사용해 rootfs를 추출했다.

```c
python3 ./ubift.py ubift_recover --output ./g3_router ./g3_router.bin
```

[추출 결과](Script/extract_result)

# 2. 펌웨어 정보

스타링크의 오픈소스 정보는 [스타링크 깃허브](https://github.com/SpaceExplorationTechnologies)에서 확인 가능하다.

Kernel Version : Linux/arm64 5.4.203

Compiler: aarch64-openwrt-linux-musl-gcc

# 3. 관리자 페이지

## 3.1. 관리자 페이지 접속

rootfs 안에 cgi폴더와 luci 폴더가 존재하지만 동작하지 않으며, 관리자 페이지는 wifi_control 바이너리로 동작한다.

처음 router를 동작시킨 후 관리자 페이지로 접속하면(192.168.1.1)  관리자 페이지가 존재하고, SSID와 password가 설정되어 있지 않으면 /setup 페이지로 라우팅 된다. 

![image.png](Img/image2.png?raw=true)

```c
POST /setup HTTP/1.1
Host: 192.168.1.1
Content-Length: 31
Cache-Control: max-age=0
Accept-Language: ko-KR,ko;q=0.9
Origin: http://192.168.1.1
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.1.1/setup
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

ssid=starlink&password=starlink
```

해당 setup 페이지에서 SSID와 password를 설정할 수 있고, 관리자 페이지의 유일한 입력 벡터이다.

![image.png](Img/image3.png?raw=true)

SSID와 password를 설정 이후 관리자 페이지는 조작이 불가능하다.

## 3.2. wifi_control 바이너리

wifi_control 바이너리는 go 언어로 이루어져 있다. 

/setup 페이지를 제외한 나머지 페이지는 /landing-v2, /speedtest, /static, /config, /hotspot-detect.html, /bypass가 존재한다.

- /static : net_http_StripPrefix를 통해 /static 경로 뒤에 오는 문자를 경로로 처리한다.

```c
p_http_fileHandler->root.data = v62;
  v48.tab = (void *)net_http_StripPrefix((int)"/static", 7, (int)"p", (int)p_http_fileHandler);
  v34.len = 8;
```

따라서 /static 경로 데이터를 확인할 수 있다.

- landing-v2
    - DNS 서버나 라우터 상태를 확인하며, 문제 발생 시 500 에러를 반환한다. 정상적인 경우 기본 관리자 페이지를 보여준다.
- speedtest : GET 요청과 POST 요청으로 나뉘어 동작한다.
    - GET 요청
        - 서버에서 클라이언트로 데이터를 대량 송출하는 요청을 보낸다.
    - POST 요청
        - 클라이언트에서 서버로 데이터를 전송받는 테스트를 수행한다.
- config : GET 요청과 POST 요청으로 나뉘어 동작한다.
    - GET 요청
    - `main_HttpServerApp_getConfigPortalData()`를 호출하여 템플릿에 필요한 데이터를 가져오고, `config_portal.html` 를 더링한다.
    - POST 요청
        - `request.ParseForm()` (여기서는 `net_http__ptr_Request_ParseForm`)을 통해 폼 데이터를 파싱한다.
- hotspot-detect.html
    - 호스트와 포트를 파싱하고, 클라이언트의 IP 주소를 기반으로 네트워크 정보를 조회한다.
- bypass
    - bypass 모드를 설정하고 관리자 페이지를 로드한다.
        ![image.png](Img/image4.png?raw=true)
        

 

static과 bypass를 제외한 다른 페이지의 경로는 코드상 명시된 페이지를 보여주지 않는다.

# 4. Pin2pwn

wifi_control 바이너리에서 모든 관리자 페이지 처리를 하기 때문에 해당 바이너리가 올라가지 않은 상태로 라우터가 켜지지 않으면 cgi 페이지나 luci를 이용한 관리자 페이지가 올라오거나 다른 포트가 열릴 것이라는 가설을 세웠다.

[pin2pwn: How to Root an Embedded Linux Box with a Sewing Needle](https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEF%20CON%2024%20-%20Brad-Dixon-Pin2Pwn-How-to-Root-An-Embedded-Linux-Box-With-A-Sewing-Needle-UPDATED.pdf)를 참고해 pin2pwn을 진행하였다.

[Nand flash의 data sheet](https://www.alldatasheet.com/datasheet-pdf/pdf/932059/WINBOND/W25N01GVZEIG.html)를 참고했다.

![image.png](Img/image5.png?raw=true)

NAND FLASH 메모리의 CS핀과 DO핀을 부팅 시에 연결시켜서 MEMORY READ를 방해한다.

정상적으로 부팅시 root@starlinkrouter:/# 쉘이 뜨게 된다.

```bash
[   24.552572] br-hiddenlan: port 6(apclix0) entered blocking state
[   24.558596] br-hiddenlan: port 6(apclix0) entered forwarding state
[   24.669912] br-hiddenlan: port 6(apclix0) entered disabled state
[   26.528515] HTB: quantum of class 10020 is big. Consider r2q change.
[   26.546301] HTB: quantum of class 10020 is big. Consider r2q change.

BusyBox v1.33.2 (2024-05-07 20:47:15 UTC) built-in shell (ash)

root@starlinkrouter:/# 
```

MEMORY READ를 방해하는 타이밍은 squashfs 파일을 읽는 도중에 시도했다.

결과적으로 wifi_control이 올라가지 않은 상태의 쉘을 올릴 수 있었다.

```bash
[    9.819129] SQUASHFS error: xz decompression failed, data probably corrupt
[    9.826025] SQUASHFS error: squashfs_read_data failed to read block 0x122ecbd
[   10.085398] Per-port-per-queue mode is going to be enabled !
[   10.091105] PPPQ use qid 0~5 (scheduler 0).

BusyBox v1.33.2 (2024-05-07 20:47:15 UTC) built-in shell (ash)

root@(none):/# [   95.955979] SQUASHFS error: xz decompression failed, data probably corrupt
```

LAN 연결을 통해 포트를 검사했을 때 아무 포트도 열려있지 않았고 관리자 페이지 또한 올라오지 않는다.

kernel이 RAM으로 로드될 때 방해할 경우 메모리값이 dump 되기도 한다.

```bash
In:    serial@11002000
Out:   serial@11002000
Err:   serial@11002000
Net:   SpaceX: Skipping power up of MT7531 port 6!
Warning: ethernet@15100000 (eth0) using random MAC address - f2:e9:74:83:57:c9
eth0: ethernet@15100000
Got bootcount: 355!, loading OpenWrt 1, mtd device ubi1

----------------------PIN!!-----------------------------------

ubi0: attaching mtd8
ubi0 error: check_corruption: PEB 306 contains corrupted VID header, and the data does not contain all 
ubi0 error: check_corruption: this may be a non-UBI PEB or a severe VID header corruption which requires manual inspection
Volume identifier header dump:
	magic     
	version   
	vol_type  
	copy_flag 
	compat    
	vol_id    
	lnum      
	data_size 
	used_ebs  
	data_pad  
	sqnum     
	hdr_crc   
Volume identifier header hexdump:
00000000: 55 42 49 21 01 01 00 00 00 00 00 01 00 00 00 5d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  UBI!...........]................
00000020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 eb 00 00 00 00 00 00 00 00 00 00 00 00 d6 92 fc 6d  ...............................m
hexdump of PEB 306 offset 4096, length 126976
00000000: 65 79 fb 14 3f 6c b4 37 b3 c7 94 74 13 6d e2 d5 1c d6 60 df bc 01 04 d1 ec 8d ef 13 28 46 f8 8b  ey..?l.7...t.m....`.........(F..
00000020: d1 d0 9b 67 a9 48 4f 5d 57 33 2f 32 63 c8 e5 65 91 2b 3b 2c c1 cc f3 bd d8 fe 75 e8 a0 73 e5 56  ...g.HO]W3/2c..e.+;,......u..s.V
00000040: e3 e9 2c 50 b0 ef 41 72 ab 26 7f 19 75 d0 44 5f 18 6a 1c 79 cc 1f 27 30 0a 70 24 83 5e 6b 9a 22  ..,P..Ar.&..u.D_.j.y..'0.p$.^k."
```

민감한 데이터가 포함되어 있을 가능성을 인지하였으나, 현재까지 구체적인 분석은 후속 연구로 진행될 예정이다.
