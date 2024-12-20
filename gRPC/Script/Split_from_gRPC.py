def process_grpc_message(hex_string):
    # 입력 문자열에서 모든 공백을 제거
    hex_string = hex_string.replace(" ", "")

    # 16진수 문자열을 바이트 배열로 변환
    byte_array = bytes.fromhex(hex_string)

    index = 0
    length = len(byte_array)

    # gRPC 헤더 처리
    if length < 5:
        print("메시지가 너무 짧아 헤더를 읽을 수 없습니다.")
        return

    compressed_flag = byte_array[0]
    compressed_flag_hex = byte_array[0:1].hex()
    message_length_bytes = byte_array[1:5]
    message_length = int.from_bytes(message_length_bytes, byteorder="big")
    message_length_hex = message_length_bytes.hex()

    print(
        f"압축 플래그: {compressed_flag} [{compressed_flag_hex}], 메시지 길이: {message_length} [{message_length_hex}]"
    )

    index = 5  # 헤더 이후부터 메시지 본문 시작

    # 메시지 본문의 끝 인덱스 계산
    message_end = index + message_length

    # 메시지 길이 확인
    if message_end > length:
        print("메시지 길이가 실제 데이터보다 깁니다.")
        return

    # 메시지 본문 처리
    while index < message_end:
        # 필드 키 읽기
        field_key, key_size, field_key_bytes = decode_varint_with_bytes(
            byte_array, index
        )
        field_key_hex = " ".join(f"{b:02x}" for b in field_key_bytes)
        index += key_size

        # 와이어 타입과 필드 번호 추출
        wire_type = field_key & 0x07
        field_number = field_key >> 3

        print(f"필드 번호: {field_number} [{field_key_hex}], 와이어 타입: {wire_type}")

        # 데이터 처리
        if wire_type == 0:  # Varint
            value, value_size, value_bytes = decode_varint_with_bytes(byte_array, index)
            value_hex = " ".join(f"{b:02x}" for b in value_bytes)
            index += value_size
            print(f"값: {value} [{value_hex}]")
        elif wire_type == 2:  # Length-delimited
            length_value, length_size, length_bytes = decode_varint_with_bytes(
                byte_array, index
            )
            length_hex = " ".join(f"{b:02x}" for b in length_bytes)
            index += length_size
            data = byte_array[index : index + length_value]
            data_hex = " ".join(f"{b:02x}" for b in data)
            index += length_value
            print(f"길이: {length_value} [{length_hex}], 데이터: [{data_hex}]")
        elif wire_type == 5:  # 32-bit
            data = byte_array[index : index + 4]
            data_hex = " ".join(f"{b:02x}" for b in data)
            index += 4
            print(f"32비트 데이터: [{data_hex}]")
        elif wire_type == 1:  # 64-bit
            data = byte_array[index : index + 8]
            data_hex = " ".join(f"{b:02x}" for b in data)
            index += 8
            print(f"64비트 데이터: [{data_hex}]")
        else:
            print(f"알 수 없는 와이어 타입입니다: {wire_type}")
            break


def decode_varint_with_bytes(data, index):
    result = 0
    shift = 0
    size = 0
    bytes_list = []
    while True:
        if index >= len(data):
            raise IndexError("인덱스가 데이터 길이를 초과했습니다.")
        byte = data[index]
        bytes_list.append(byte)
        index += 1
        size += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
    return result, size, bytes_list


# 예시 입력
hex_input = "{{gRPC 메시지}}"
process_grpc_message(hex_input)
