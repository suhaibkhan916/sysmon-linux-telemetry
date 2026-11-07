#!/bin/bash
# Runs inside the sensor container. Starts rsyslog and Sysmon with one config,
# plays the workload, and copies the Sysmon lines to /out/<config>.log.
set -u
config="$1"
mount -t debugfs none /sys/kernel/debug
mount -t tracefs none /sys/kernel/tracing
rsyslogd
sleep 1
sysmon -accepteula -i "/configs/$config.xml" > /dev/null 2>&1
/opt/sysmon/sysmon -i /opt/sysmon/config.xml -service > /tmp/sysmon-service.log 2>&1 &
for _ in $(seq 1 30); do
  grep -q "<EventID>4</EventID>" /var/log/syslog && break
  sleep 1
done
grep -q "<EventID>4</EventID>" /var/log/syslog || { cat /tmp/sysmon-service.log; exit 1; }

bash /lab/scenario/benign.sh 16 &
benign=$!
sleep 8
bash /lab/scenario/attack.sh &
attack=$!
wait "$attack" "$benign"
sleep 3
# Build the file inside the container and copy it out last. A redirect straight to
# /out is itself a FileCreate event, and on Docker Desktop its path holds the host path.
grep "sysmon: <Event>" /var/log/syslog > "/tmp/$config.log"
echo "$config: $(wc -l < "/tmp/$config.log") events"
cp "/tmp/$config.log" /out/
