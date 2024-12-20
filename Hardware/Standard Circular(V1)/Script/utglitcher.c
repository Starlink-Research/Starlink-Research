# This script was created with reference to the Starlink-FI project: 
# https://github.com/KULeuven-COSIC/Starlink-FI
# Copyright belongs to the original authors. Please check their license for terms of use.


#include <stdio.h>
#include "pico/stdlib.h"
#include "hardware/uart.h"
#include "hardware/gpio.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "hardware/vreg.h"
#include "pulsegen.pio.h"

#define PIN_NRST   7       // NRST 핀
#define PIN_TRIG   6       // 트리거 핀
#define PIN_PULSE  0       // 펄스 출력 핀
#define PIN_CAPS   1       // 캡처 핀

#define PIN_LED1   16      // LED1 핀
#define PIN_LED2   17      // LED2 핀

int main()
{
    /* 
     * 250 MHz로 시스템 클럭 설정
     */
    set_sys_clock_khz(250000, true);
    
    stdio_init_all(); // 표준 I/O 초기화

    // GPIO 초기화
    gpio_init(PIN_NRST);
    gpio_init(PIN_TRIG);
    gpio_init(PIN_PULSE);
    gpio_init(PIN_CAPS);
    gpio_init(PIN_LED1);
    gpio_init(PIN_LED2);

    gpio_set_dir(PIN_NRST, GPIO_OUT);  // NRST 핀 출력 설정
    gpio_set_dir(PIN_TRIG, GPIO_IN);   // 트리거 핀 입력 설정
    gpio_set_dir(PIN_PULSE, GPIO_OUT); // 펄스 핀 출력 설정
    gpio_set_dir(PIN_CAPS, GPIO_OUT);  // 캡처 핀 출력 설정
    gpio_set_dir(PIN_LED1, GPIO_OUT);  // LED1 핀 출력 설정
    gpio_set_dir(PIN_LED2, GPIO_OUT);  // LED2 핀 출력 설정

    gpio_set_pulls(PIN_CAPS, true, false); // CAPS 핀 풀업 설정
    gpio_set_drive_strength(PIN_PULSE, GPIO_DRIVE_STRENGTH_12MA); // 펄스 핀 구동 강도 설정
    gpio_set_drive_strength(PIN_CAPS, GPIO_DRIVE_STRENGTH_12MA);  // CAPS 핀 구동 강도 설정
    gpio_set_slew_rate(PIN_PULSE, GPIO_SLEW_RATE_FAST); // 펄스 핀 고속 전환 설정

    // PIO 초기화
    PIO pio = pio0; // PIO0 사용
    uint32_t sm = pio_claim_unused_sm(pio, true); // 사용하지 않는 상태 머신 할당
    uint32_t pio_offset = pio_add_program(pio, &pulsegen_program); // PIO 프로그램 로드
    pulsegen_program_init(pio, sm, pio_offset, PIN_TRIG, PIN_PULSE, PIN_CAPS); // PIO 프로그램 초기화

    // USB 시리얼 연결 대기
    while (!stdio_usb_connected()) {
      sleep_ms(500);
    }

    gpio_put(PIN_LED1, true); // LED1 켜기
    gpio_put(PIN_NRST, false); // NRST 핀 초기화

    char cmd; // 명령 입력
    uint32_t pulse_offset = 0; // 펄스 오프셋
    uint32_t pulse_width = 0;  // 펄스 폭
    uint32_t trig_edges = 1;   // 트리거 엣지 수
    uint32_t gpio_states = 0;  // GPIO 상태

    uint8_t gpio_pin = 0;  // 제어할 GPIO 핀
    uint8_t gpio_state = 0; // 제어할 GPIO 상태

    while (true) {
        cmd = getchar(); // 명령 입력 받기
        
        switch (cmd)
        {
            // 글리치 SM 활성화
            case 'A':
                gpio_put(PIN_LED2, true); // LED2 켜기
                pio_sm_put_blocking(pio, sm, trig_edges); // 트리거 엣지 수 설정
                pio_sm_put_blocking(pio, sm, pulse_offset); // 펄스 오프셋 설정
                pio_sm_put_blocking(pio, sm, pulse_width);  // 펄스 폭 설정

                gpio_put(PIN_NRST, true); // NRST 핀 활성화
                sleep_ms(46); // 안정화 대기 시간

                pio_sm_set_enabled(pio, sm, true); // 상태 머신 활성화
                printf("A\n");
                break;

            // 트리거 대기
            case 'B':
                while(!pio_interrupt_get(pio0, 0)) {
                    cmd = getchar_timeout_us(1);
                    if (cmd == 'D') break; // 비활성화 명령
                };

                pio_sm_set_enabled(pio, sm, false); // 상태 머신 비활성화
                pio_interrupt_clear(pio, 0); // 인터럽트 클리어
                pio_sm_clear_fifos(pio, sm); // FIFO 초기화
                pio_sm_drain_tx_fifo(pio, sm);
                pio_sm_restart(pio, sm); // 상태 머신 재시작
                pio_sm_set_enabled(pio, sm, false);
                
                pio_sm_exec_wait_blocking(pio, sm, pio_encode_set(pio_x, pio_offset)); // PIO 명령 실행
                pio_sm_exec_wait_blocking(pio, sm, pio_encode_mov(pio_pc, pio_x)); // PC 설정
                printf("T\n");
                gpio_put(PIN_LED2, false); // LED2 끄기
                break;
            
            // 트리거 엣지 수 설정
            case 'E':
                fread(&trig_edges, 1, 4, stdin);
                printf("%d\n", trig_edges);
                break;

            // 펄스 오프셋 설정
            case 'O':
                fread(&pulse_offset, 1, 4, stdin);
                printf("%d\n", pulse_offset);
                break;
            
            // 펄스 폭 설정
            case 'W':
                fread(&pulse_width, 1, 4, stdin);
                printf("%d\n", pulse_width);
                break;

            // 현재 펄스 설정 출력
            case 'S':
                printf("PulseGenerator offset: %d, width: %d, edges: %d\n", pulse_offset, pulse_width, trig_edges);
                break;

            // GPIO 핀 제어
            case 'G':
                fread(&gpio_pin, 1, 1, stdin);
                fread(&gpio_state, 1, 1, stdin);

                if (gpio_pin == PIN_NRST) {
                    if (gpio_state == 0) {
                        gpio_put(PIN_NRST, false);
                    } else {
                        gpio_put(PIN_NRST, true);
                    }    
                }
                printf("G\n");
                break;

            // GPIO 상태 읽기
            case 'R':
                gpio_states = gpio_get_all();
                printf("%d\n", gpio_states);
                break;

            default:
                break;
        }
    }

    return 0;
}
