import requests


def send_reboot_request(url):
    # 헤더 및 데이터 설정
    headers = {
        "Content-Type": "application/grpc-web+proto",
        "Connection": "close",
        "x-grpc-web": "1",
        "Accept": "*/*",
        "Accept-Language": "ko-KR,ko;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "User-Agent": "Starlink/2000009159 CFNetwork/135.0.3.4 Darwin/21.6.0",
    }

    # 16진수 데이터로 변환
    binary_data = bytes.fromhex("0000000003ca3e00")  # reboot command

    # POST 요청 보내기
    response = requests.post(url, headers=headers, data=binary_data)

    # 응답 출력
    print(f"Status Code: {response.status_code}")
    print("Response Body:", response.text)


# URL 설정
router_url = "http://192.168.1.1:9001/SpaceX.API.Device.Device/Handle"
dishy_url = "http://192.168.100.1:9201/SpaceX.API.Device.Device/Handle"

# 라우터 및 디쉬 재부팅 요청
send_reboot_request(router_url)