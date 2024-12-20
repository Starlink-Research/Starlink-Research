#init.sh
#!/bin/sh
set -x 

ip link set eth0 up || echo "Failed to bring up eth0" > /dev/console

echo "Assigning IP address..." > /dev/console
ip addr add 192.168.100.1/24 dev eth0 || echo "Failed to assign IP address" > /dev/console

echo "Adding default route..." > /dev/console
route add -net 0.0.0.0 netmask 0.0.0.0 gw 192.168.100.2 dev eth0 || echo "Failed to add default route" > /dev/console

cp -r /sx/local/runtime/dat/ /tmp
cd /tmp/dat/common/
mv control_to_emc_web_socket_server_v4_1beam.include control_to_emc_web_socket_server
cd /tmp
/sx/local/runtime/bin/emc_web_socket_server &


cd /sx/local/runtime
./bin/telemetry_funnel &
