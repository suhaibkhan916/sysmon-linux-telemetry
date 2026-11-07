# Design notes

## Why a container and what it requires

auditd could not be controlled from a container on Docker Desktop because audit control is tied to the initial namespaces. eBPF has no such limit, so Sysmon for Linux works with `--privileged --pid=host`, debugfs and tracefs mounted, and a kernel with BTF (`/sys/kernel/btf/vmlinux`). The WSL2 kernel 6.6 has all of these.

The sensor is a separate process tree from systemd's point of view, so it starts Sysmon with the command in the unit file rather than through `systemctl`. rsyslog runs in the container to receive events. Its `imklog` module is disabled, otherwise the host kernel log would be copied into syslog.

## Network isolation

The sensor and listener share an `--internal` Docker network, so the attack script cannot reach anything outside the lab. The listener serves harmless files on port 8000 and discards anything sent to port 4444. The "reverse shell" stage opens the connection and sends one line. It reads nothing back.

## Ground truth

Labels must not come from the detections being measured, or the numbers are circular. The attack tree is the ground truth: every event whose PID descends from the attack script is signal.

The root comes from a marker process (`printenv LAB_ATTACK_ROOT_MARKER`) whose `ParentProcessId` is the attack script. It must be visible in every config, so no config filters `printenv`. A PID recorded from inside the container cannot be used, because Docker Desktop's namespace is nested and the numbers differ from what Sysmon reports.

Marker events count as signal and add one event per capture. This is a small distortion, accepted for labels that do not depend on config.

## PID against ProcessGuid

ProcessGuid is the normal way to link Sysmon events, and in Windows it is reliable. On Linux, ProcessCreate fires on exec, so a forked shell that has not exec'd yet has no GUID. File events in that gap carry an all-zero GUID. PIDs do not have this gap because exec keeps the PID. The cost is exposure to PID reuse, which cannot happen at this scale.

`guid_lineage_events` is kept to measure the difference. It would be the wrong choice to delete it and only claim the problem exists.

## Tuning approach

1. Run with everything on and list noise by `event id + image` (`top_noise`).
2. Drop event types nothing reads. ProcessTerminate was 42.9% of volume and no rule uses it.
3. For the rest, exclude by exact command line, not by image. `ps aux` is safe to drop. `/usr/bin/bash` is not, because it hides everything run through bash.
4. For file events, use include rules on sensitive paths. New files are too common to list exclusions for.
5. Re-run the detections on the new capture. A tuning change with no detection check is not finished.

Include rules set `name` to an ATT&CK id, so `RuleName` arrives in the event already tagged.

## Rule design

Each rule declares the event id it reads, so the coverage table shows which event type a missed detection depends on.

`decoded_into_shell` is the only rule that needs two events. A pipeline's members are children of one parent, so `base64 -d` with a sibling shell within 0.5 seconds means a pipeline. Decoding alone is common and does not fire. A benign `base64 -d` is in the workload to test this.

## Metric choice

Signal percentage alone rewards deleting events, as the overtuned capture shows. The tool always reports it with rules kept, and exits 1 when a capture misses any rule, so a tuning change in CI can fail on lost coverage.

## Data in the repo

Captures are committed so tests run without Docker. They are about 610 KB in total. They were checked for host paths and personal strings, and a test keeps checking.
