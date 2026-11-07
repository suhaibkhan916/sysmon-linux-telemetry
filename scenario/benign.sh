#!/bin/bash
# Synthetic normal activity: a service health check, log rotation and admin checks.
# Some of it looks a bit like an attack on purpose, to test for false positives.
mkdir -p /var/log/app
for i in $(seq 1 "${1:-16}"); do
  curl -s -m 2 -o /dev/null http://listener:8000/healthz
  ps aux > /dev/null
  date >> /var/log/app/heartbeat.log
  grep -c root /etc/passwd > /dev/null
  ls /etc/cron.d > /dev/null 2>&1
  python3 -c "print('app metrics tick')" >> /var/log/app/metrics.log
  echo "job $i" > "/tmp/app-job-$i.tmp"
  rm -f "/tmp/app-job-$i.tmp"
  sleep 2
done
# Admin chores that overlap with the attack techniques.
curl -s -m 2 -o /tmp/app-update.tar http://listener:8000/app-update.tar
echo "c2V0dGluZz0x" | base64 -d > /var/log/app/settings.conf
chage -l root > /dev/null
rm -f /tmp/app-update.tar
