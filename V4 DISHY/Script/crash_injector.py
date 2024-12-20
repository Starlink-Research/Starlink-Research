# crash_injector.py

import sys
import socket
from lib.service import Service
from lib.slate import Slate
from lib.tunnel import UdpInjectorTunnel
import hexdump

def main():
    if len(sys.argv) != 3:
        print("Usage: python crash_injector.py <service_name> <crash_file_path>", file=sys.stderr)
        sys.exit(1)

    service_name = sys.argv[1]
    crash_file_path = sys.argv[2]

    # 서비스 디렉토리 및 프로세스 정보 파싱
    try:
        services = Service.parse("./config/service_directory.json", "./config/process_info.json")
        slates = list(map(Slate.from_service, services))
    except Exception as e:
        print(f"Error parsing service or process info: {e}", file=sys.stderr)
        sys.exit(1)

    # 대상 서비스 찾기
    slate = next((s for s in slates if s.service.name == service_name), None)
    if not slate:
        print(f"Service '{service_name}' not found.", file=sys.stderr)
        sys.exit(1)

    # 크래시 메시지 읽기
    try:
        with open(crash_file_path, "rb") as f:
            message_bytes = f.read()
    except Exception as e:
        print(f"Error reading crash file: {e}", file=sys.stderr)
        sys.exit(1)

    # UdpInjectorTunnel을 통해 메시지 전송
    try:
        with UdpInjectorTunnel(slate.service.port) as tunnel:
            print("Sending crash message:")
            hexdump.hexdump(message_bytes)

            # 메시지 전송
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(message_bytes, (tunnel.host, tunnel.external_port))

            print("Crash message sent.")
    except Exception as e:
        print(f"Failed to send message: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
