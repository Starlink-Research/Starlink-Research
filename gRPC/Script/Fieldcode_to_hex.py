def encode_varint(n):
    """ 정수 n을 VarInt 방식으로 인코딩하는 함수 """
    result = []
    while True:
        byte = n & 0x7F  # 하위 7비트 추출
        n >>= 7  # n을 7비트 오른쪽으로 이동
        if n != 0:
            result.append(byte | 0x80)  # MSB를 1로 설정하여 다음 바이트가 있음을 표시
        else:
            result.append(byte)  # 마지막 바이트이므로 MSB는 0
            break
    return result
  

def makedata(fieldcode):
    """ 주어진 필드코드에 대한 데이터값을 생성하는 함수 """
    n = fieldcode * 8 + 2
    varint_bytes = encode_varint(n)
    length_byte = len(varint_bytes) + 1  # VarInt 바이트 수 + 1
    data_value = [0x00, 0x00, 0x00, 0x00, length_byte] + varint_bytes + [0x00]
    # 바이트 배열을 16진수 문자열로 변환
    data_value_hex = "".join("{:02X}".format(b) for b in data_value)
    return data_value_hex
    
# 사용 예시:
print(makedata(13))