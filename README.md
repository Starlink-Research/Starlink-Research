### **KITRI BoB 13기 취약점 분석 Track : 프로젝트 ‘스타링크 취약점 분석’**

> 연구 기간: 2024년 9월 ~ 2024년 12월(약 4개월)
> 

본 프로젝트는 KITRI BoB(Best of the Best) 13기에서 진행한 프로젝트로, 4개월간의 스타링크 취약성 연구를 진행한 자료입니다. 

저희 팀이 분석한 결과를 공유함으로써, 앞으로 진행될 후속 연구 및 저궤도 위성 산업의 보안 증진에 기여하고자 합니다.

---

## 저자

> KITRI BoB 13기 취약점분석 트랙 우주해적단 팀
> 
- Mentor : 박천성, 송종혁
- PL(Project Leader) : 김현식
- Mentee : 👑이병영, 김상철, 김서율, 김민지, 김태연, 장형범

# 카테고리  

---
### 분석 방법론
  1. [Standard(V4 & Gen3)](https://github.com/Starlink-Research/Starlink-Research/tree/master/Hardware/Standard(V4%26Gen3))
     - [V4 & Gen3 TearDown](https://github.com/Starlink-Research/Starlink-Research/tree/master/Hardware/Standard(V4%26Gen3)#1-teardown--firmware-extracting)
     - [V4 & Gen3 UART & Firmware Extracting](https://github.com/Starlink-Research/Starlink-Research/tree/master/Hardware/Standard(V4%26Gen3)#12-v4gen3-uart--firmware-extracting)
     - [Gen3 NanFlash Repair](https://github.com/Starlink-Research/Starlink-Research/tree/master/Hardware/Standard(V4%26Gen3)#21-gen3-nanflash-repair)
  2. [Standard Circular(V1)](https://github.com/Starlink-Research/Starlink-Research/tree/master/Hardware/Standard%20Circular(V1))
     - [V1 TearDown & UART 확인](https://github.com/Starlink-Research/Starlink-Research/tree/master/Hardware/Standard%20Circular(V1)#1-teardown--extracting-firmware)
     - [V1 Firmware Extracting & Rewriting](https://github.com/Starlink-Research/Starlink-Research/tree/master/Hardware/Standard%20Circular(V1)#12-firmware-extracing--rewriting)
     - [V1 Glitching 연구](https://github.com/Starlink-Research/Starlink-Research/tree/master/Hardware/Standard%20Circular(V1)#2-glitching-%EC%97%B0%EA%B5%AC)

  2. [gRPC](https://github.com/Starlink-Research/Starlink-Research/blob/master/gRPC/README.md)
     - [개요](https://github.com/Starlink-Research/Starlink-Research/blob/master/gRPC/README.md#1-%EA%B0%9C%EC%9A%94)
     - [gRPC Tools](https://github.com/Starlink-Research/Starlink-Research/blob/master/gRPC/README.md#2-grpc-tools)
     - [Proto추출 및 Fieldcode](https://github.com/Starlink-Research/Starlink-Research/blob/master/gRPC/README.md#3-proto%EC%B6%94%EC%B6%9C-%EB%B0%8F-fieldcode)
     - [gRPC 요청 및 응답, 해석](https://github.com/Starlink-Research/Starlink-Research/blob/master/gRPC/README.md#4-grpc-%EC%9A%94%EC%B2%AD-%EB%B0%8F-%EC%9D%91%EB%8B%B5-%ED%95%B4%EC%84%9D)
     - [Fuzzing & Bruteforce](https://github.com/Starlink-Research/Starlink-Research/blob/master/gRPC/README.md#5-fuzzing--bruteforce)
     
  3. [Mobile App](https://github.com/Starlink-Research/Starlink-Research/tree/master/Mobile%20App)
     - [개요](https://github.com/Starlink-Research/Starlink-Research/tree/master/Mobile%20App#1-%EA%B0%9C%EC%9A%94)
     - [정적 분석](https://github.com/Starlink-Research/Starlink-Research/blob/master/Mobile%20App/README.md#2-%EC%A0%95%EC%A0%81-%EB%B6%84%EC%84%9D)
     - [동적 분석](https://github.com/Starlink-Research/Starlink-Research/blob/master/Mobile%20App/README.md#3-%EB%8F%99%EC%A0%81-%EB%B6%84%EC%84%9D)
  4. [V4 DISHY](https://github.com/Starlink-Research/Starlink-Research/blob/master/V4%20DISHY/README.md)
     - [Firmware Overview](https://github.com/Starlink-Research/Starlink-Research/tree/master/V4%20DISHY#1-firmware-overview)
     - [Firmware Parsing](https://github.com/Starlink-Research/Starlink-Research/tree/master/V4%20DISHY#2-firmware-extracting)
     - [에뮬레이팅 & 디버깅](https://github.com/Starlink-Research/Starlink-Research/tree/master/V4%20DISHY#3-%EC%97%90%EB%AE%AC%EB%A0%88%EC%9D%B4%ED%8C%85--%EB%94%94%EB%B2%84%EA%B9%85)
     - [외부로 연결된 포트](https://github.com/Starlink-Research/Starlink-Research/tree/master/V4%20DISHY#4-%EC%99%B8%EB%B6%80%EB%A1%9C-%EC%97%B0%EA%B2%B0%EB%90%9C-%ED%8F%AC%ED%8A%B8)
     - [내부로 연결된 포트](https://github.com/Starlink-Research/Starlink-Research/tree/master/V4%20DISHY#5-%EB%82%B4%EB%B6%80%EB%A1%9C-%EC%97%B0%EA%B2%B0%EB%90%9C-%ED%8F%AC%ED%8A%B8)
  5. [GEN3 ROUTER](https://github.com/Starlink-Research/Starlink-Research/blob/master/G3%20ROUTER/README.md)
     - [Firmware Parsing](https://github.com/Starlink-Research/Starlink-Research/blob/master/G3%20ROUTER/README.md#1-firmware-extracting)
     - [펌웨어 정보](https://github.com/Starlink-Research/Starlink-Research/blob/master/G3%20ROUTER/README.md#2-%ED%8E%8C%EC%9B%A8%EC%96%B4-%EC%A0%95%EB%B3%B4)
     - [관리자 페이지](https://github.com/Starlink-Research/Starlink-Research/blob/master/G3%20ROUTER/README.md#3-%EA%B4%80%EB%A6%AC%EC%9E%90-%ED%8E%98%EC%9D%B4%EC%A7%80)
     - [Pin2pwn](https://github.com/Starlink-Research/Starlink-Research/blob/master/G3%20ROUTER/README.md#4-pin2pwn)
     
