# This script was created with reference to the Starlink-FI project: 
# https://github.com/KULeuven-COSIC/Starlink-FI
# Copyright belongs to the original authors. Please check their license for terms of use.

import serial
import time
import signal

class PicoPulseGen:
    def __init__(self, port='/dev/ttyACM0'):
        """
        클래스 초기화: Raspberry Pi Pico와 직렬 통신을 설정합니다.
        
        :param port: 직렬 포트 경로 (기본값: '/dev/ttyACM0')
        """
        self._pulse_offset = 0  # 펄스 오프셋 초기화
        self._pulse_width = 0   # 펄스 폭 초기화
        self._trig_edges = 0    # 트리거 에지 수 초기화
        
        # Pico와 직렬 통신을 설정합니다.
        self.pico = serial.Serial(port, 115200)
        time.sleep(0.1)
        self.pico.write(b'S')  # 상태 요청 명령 전송

        # 응답 확인: 'PulseGenerator' 문자열이 포함되어야 정상 연결
        test = self.pico.readline()
        if b'PulseGenerator' not in test:
            raise ConnectionError('Could not connect to the PulseGenerator :(')
        
        # SIGALRM 신호 설정 (타임아웃 시 arm_abort 메서드 실행)
        signal.signal(signal.SIGALRM, self.arm_abort)
        

    @property
    def pulse_offset(self):
        """현재 펄스 오프셋 값을 반환합니다."""
        return self._pulse_offset

    
    @pulse_offset.setter
    def pulse_offset(self, offset):
        """
        펄스 오프셋 값을 설정합니다.
        :param offset: 설정할 오프셋 값 (0 ~ 0xFFFFFFFF 사이의 정수)
        """
        if type(offset) != int or offset < 0 or offset > 0xFFFFFFFF:
            raise ValueError('Offset has to be an int between 0 and 0xFFFFFFFF')
        
        self._pulse_offset = offset
        
        self.pico.flushInput()  # 입력 버퍼를 비웁니다.
        self.pico.write(b'O')  # 오프셋 설정 명령 전송
        self.pico.write((self._pulse_offset).to_bytes(4, 'little'))  # 오프셋 값을 바이트로 전송
        ret = self.pico.readline()
        assert int(ret.strip()) == self._pulse_offset, ret  # 응답 확인

        
    @property
    def pulse_width(self):
        """현재 펄스 폭 값을 반환합니다."""
        return self._pulse_width

    
    @pulse_width.setter
    def pulse_width(self, width):
        """
        펄스 폭 값을 설정합니다.
        :param width: 설정할 펄스 폭 값 (0 ~ 0xFFFFFFFF 사이의 정수)
        """
        if type(width) != int or width < 0 or width > 0xFFFFFFFF:
            raise ValueError('Width has to be an int between 0 and 0xFFFFFFFF')
        
        self._pulse_width = width

        self.pico.flushInput()
        self.pico.write(b'W')  # 펄스 폭 설정 명령 전송
        self.pico.write((self._pulse_width).to_bytes(4, 'little'))
        ret = self.pico.readline()
        assert int(ret.strip()) == self._pulse_width, ret


    @property
    def trig_edges(self):
        """현재 트리거 에지 값을 반환합니다."""
        return self._trig_edges

    
    @trig_edges.setter
    def trig_edges(self, edges):
        """
        트리거 에지 값을 설정합니다.
        :param edges: 설정할 에지 수 (0 ~ 0xFFFFFFFF 사이의 정수)
        """
        if type(edges) != int or edges < 0 or edges > 0xFFFFFFFF:
            raise ValueError('Width has to be an int between 0 and 0xFFFFFFFF')
        
        self._trig_edges = edges
        
        self.pico.write(b'E')  # 트리거 에지 설정 명령 전송
        self.pico.write((self._trig_edges).to_bytes(4, 'little'))
        ret = self.pico.readline()
        assert int(ret.strip()) == self._trig_edges, ret
            
        
    def arm(self):
        """
        펄스 생성기(Trigger)를 활성화합니다.
        """
        self.pico.write(b'A')  # 활성화 명령 전송
        ret = self.pico.readline()
        assert b'A' in ret  # 응답 확인


    def wait_trig(self, timeout=5):
        """
        트리거 신호를 대기합니다.
        :param timeout: 최대 대기 시간 (초 단위)
        """
        self.pico.write(b'B')  # 트리거 대기 명령 전송
        signal.alarm(timeout)  # 타임아웃 설정
        ret = self.pico.readline()
        signal.alarm(0)  # 타이머 종료
        assert b'T' in ret  # 응답 확인


    def arm_abort(self, signum, frame):
        """
        트리거 대기가 시간 초과되면 실행됩니다.
        """
        print('  -- No trigger observed, disarming!')
        self.pico.write(b'D')  # 비활성화 명령 전송


    def status(self):
        """
        장치의 현재 상태를 요청하고 출력합니다.
        """
        self.pico.write(b'S')  # 상태 요청 명령 전송
        ret = self.pico.readline()
        print(ret.decode('utf-8'))  # 상태 출력
        

    def set_gpio(self, state):
        """
        GPIO 핀의 상태를 설정합니다.
        :param state: 0 (LOW) 또는 1 (HIGH)
        """
        if type(state) != int or state < 0:
            raise ValueError('State has to be zero (GPIO 0) or a positive value larger than zero (GPIO 1)')

        self.pico.write(b'G')  # GPIO 설정 명령 전송
        self.pico.write(bytes([7]))  # GPIO 핀 번호 (현재 하나만 사용 중)
        if state:
            self.pico.write(bytes([1]))  # HIGH로 설정
        else:
            self.pico.write(bytes([0]))  # LOW로 설정

        ret = self.pico.readline()
        assert b'G' in ret  # 응답 확인


    def read_gpios(self):
        """
        GPIO 핀의 현재 상태를 읽습니다.
        :return: GPIO 상태 값
        """
        self.pico.write(b'R')  # GPIO 읽기 명령 전송
        ret = self.pico.readline()
        ret = int(ret.strip())
        return ret

    
    def close(self):
        """
        직렬 포트를 닫습니다.
        """
        self.pico.close()


    def __del__(self):
        """
        객체가 소멸될 때 직렬 포트를 닫습니다.
        """
        self.pico.close()
