# This script was created with reference to the Starlink-FI project: 
# https://github.com/KULeuven-COSIC/Starlink-FI
# Copyright belongs to the original authors. Please check their license for terms of use.

import numpy as np
import time
import serial
from tqdm import tnrange, tqdm
import random
from pulsegen import PicoPulseGen
import logging

GLITCH_ISDEV = 1
USE_SERIAL = 0

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

if USE_SERIAL:
	try:
		ser = serial.Serial('/dev/ttyUSB0', 115200)

	except Exception as e:
		print('Could not open /dev/ttyUSB0', e)
		exit()

try:
	glitcher = PicoPulseGen('/dev/ttyACM0')
	logger.info('Connected to modchip')
	glitcher.trig_edges = 1
	glitcher.pulse_offset = 0
	glitcher.pulse_width = 0
	glitcher.set_gpio(0)

except Exception as e:
	print('Could not connect to modchip', e)
	exit()

input("Press enter to start.")

def generator():
	while True:
		yield

idx = 0
success = False
E_Range = [1, 1]

A, B =  1250, 2000 # 5us ~ 8us
C, D =  750, 1000 # 3us ~ 4us

for _ in tqdm(generator()):
	print("")
	if idx % 10 == 0:
		glitch_width = random.randint(A, B)
		glitch_offset = random.randint(C, D)

		glitcher.trig_edges = random.randint(E_Range[0],E_Range[1])
		glitcher.pulse_offset = glitch_offset
		glitcher.pulse_width = glitch_width
	if USE_SERIAL:
		ser.reset_input_buffer()
	
	glitcher.arm()			# Arm the modchip, it will try to power up the UT and will wait for the number of set trigger pulses to occur before inserting a glitch
	if GLITCH_ISDEV:
		adjust_time = round(random.randint(0000, 3000)/1000,3) + 7
		time.sleep(round(adjust_time,3))
		print(f" -- Glitching DATA /{round(glitch_offset/250,3)}/{round(glitch_width/250,3)}/{round(adjust_time,3)}")
	else:
		adjust_time = round(random.randint(0000, 1000)/1000,3)
		time.sleep(round(adjust_time,3))
		print(f" -- Glitching DATA /{round(glitch_offset/250,3)}/{round(glitch_width/250,3)}/{round(adjust_time,3)}")
	glitcher.wait_trig(timeout=1)	# Waits for the modchip to signal it has triggered. The modchip will be disarmed if no glitch has occurred within 5 seconds.
	time.sleep(0.55) # 0.55->3 Have to wait for the second stage to start to see serial output
	if USE_SERIAL:
		time.sleep(2) 
		data = ser.read(ser.in_waiting)	
		if GLITCH_ISDEV:
			command = "ls\n"
			ser.write(command.encode('utf-8'))
			time.sleep(0.5)
			data = ser.read_all()
			print(f" -- Sent:[{command.strip()}] Recv:[{data}]")
		else:
			print(f" -- DATA:[{data}]")

		if len(data)>10: # a check to determine if the glitch was successful. My BL2 has been modified to print LENNERT.
			success = True
			break		
	glitcher.set_gpio(0) # Disables the core voltage regulator. The modchip firmware will re-enable the regulator automatically on the next glitch attempt.
	time.sleep(1)
	idx += 1

if success:
	print('Glitch successul!')
	logger.debug('%d, %d, %d' %(idx, glitch_width, glitch_offset))
	logger.debug(data.decode('utf-8', 'ignore'))

if USE_SERIAL:
	ser.close()
glitcher.close()
