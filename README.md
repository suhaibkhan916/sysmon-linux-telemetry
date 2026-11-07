# sysmon-linux-telemetry

Sysmon for Linux running in a container, three configs compared on the same scripted workload, and a small Python tool that measures what each config costs in volume and what it costs in missed detections.

**Data:** the activity is **synthetic**: a scripted benign workload and a scripted attack, in a disposable container, talking only to a second lab container on an internal Docker network. The events in `data/captures/` are real Sysmon output from that run. Passwords and keys are not real, and the attack payloads only print text.

## The problem

Turn on all Sysmon events and you get volume nobody reads. Filter by whatever tops the noise list and you go blind without noticing, because a missing event raises no error. So tuning needs a measurement on both sides: how much noise went, and which detections still work.

This lab labels every event as signal or noise from the attack's process tree, runs eight detections mapped to ATT&CK, and compares three configs:

| Config | Idea |
|---|---|
| `config-noisy.xml` | log everything Sysmon for Linux can log |
| `config-tuned.xml` | narrow exclusions by exact command line, include-only file events on paths that matter, ATT&CK ids in `RuleName` |
| `config-overtuned.xml` | a bad config on purpose: exclude the top images (`bash`, `curl`, `rm`...) and switch off network and file events |

## Results

| Capture | Events | Bytes | Events/min | Signal | Noise | Signal % | Rules on attack | True alerts | False alerts |
|---|---|---|---|---|---|---|---|---|---|
| noisy | 487 | 539,911 | 808 | 80 | 407 | 16.4 | 8/8 | 9 | 1 |
| tuned | 37 | 51,106 | 62 | 21 | 16 | 56.8 | 8/8 | 9 | 1 |
| overtuned | 14 | 20,291 | 25 | 5 | 9 | 35.7 | 1/8 | 1 | 0 |

The tuned config cut events by 92.4% and bytes by 90.5% and kept all eight detections. The overtuned config cut only a little more (14 events against 37) and lost seven of eight. It still looks reasonable if you only look at signal percentage, which is why that number alone is not enough.

| Rule | ATT&CK | Needs event | noisy | tuned | overtuned |
|---|---|---|---|---|---|
| download_to_temp | T1105 | 1 ProcessCreate | yes | yes | MISSED |
| outbound_from_shell | T1059.004 | 3 NetworkConnect | yes | yes | MISSED |
| shadow_read | T1003.008 | 1 ProcessCreate | yes | yes | MISSED |
| account_created | T1136.001 | 1 ProcessCreate | yes | yes | yes |
| cron_persistence | T1053.003 | 11 FileCreate | yes | yes | MISSED |
| ssh_key_persistence | T1098.004 | 11 FileCreate | yes | yes | MISSED |
| hidden_temp_deleted | T1070.004 | 23 FileDelete | yes | yes | MISSED |
| decoded_into_shell | T1140 | 1 ProcessCreate | yes | yes | MISSED |

`account_created` survived the bad config by luck: `useradd` was not on the noise list.

Event mix in the noisy capture: 209 ProcessTerminate (42.9%), 161 ProcessCreate, 44 FileCreate, 39 NetworkConnect, 32 FileDelete, 1 ServiceStateChange, 1 ConfigChange.

The one false alert is real and left in: the benign workload runs `curl -o /tmp/app-update.tar`, which looks the same as the attacker's download to `download_to_temp`. A Sysmon config cannot fix that, because the telemetry is correct. The rule needs an allow list, or a rule on hidden file names.

Checks in this build: 60 pytest tests pass on Python 3.14 locally and on Python 3.10 in a `python:3.10-slim` container. `ruff check` and `ruff format --check` are clean. Seven hand-made mutations of the rules, labels and CLI (for example removing the `Initiated` check) were each caught by a test. CI has not run yet because the repo has not been pushed.

## How to run

Analysis only (Python 3.10 or later, no third-party packages at run time):

```bash
python -m sysmontel data/captures/config-noisy.log data/captures/config-tuned.log data/captures/config-overtuned.log --out reports
pip install -r requirements-dev.txt && python -m pytest -q
```

Exit codes: `0` nothing missed, `1` a capture missed a detection (the command above gives 1, because of the overtuned capture), `2` input problem.

New captures (Docker needed, about 45 seconds per config after the image build). Run from the repo root in Git Bash or a Linux shell:

```bash
bash scripts/capture.sh config-noisy config-tuned config-overtuned
```

This builds the image, starts a listener container on an internal network and runs the sensor container. The sensor runs `--privileged --pid=host`, which it needs to load eBPF programs, so run this on a lab machine or Docker Desktop VM. New captures differ by a few events from run to run. The tests pin the numbers of the committed files, so they will fail on new captures until updated.

## What broke and how it was fixed

- **Sysmon's install needs systemd.** `sysmon -accepteula -i` printed `systemctl: not found` four times. The unit file it writes (`/etc/systemd/system/sysmon.service`) shows the real command, `/opt/sysmon/sysmon -i /opt/sysmon/config.xml -service`, so `run_capture.sh` starts that directly. My first guess, `sysmon -service` with no config, started with no error and produced no events.
- **eBPF would not attach.** `libbpf: failed to determine tracepoint 'sched/sched_process_exit' perf event ID: -ENOENT`, then `Telemetry failed to start`. Tracepoint ids live in tracefs, which a container does not mount. Fixed by mounting debugfs and tracefs at the start of `run_capture.sh`.
- **A host path leaked into the data.** The first capture redirected straight to `/out/config-noisy.log`. That write was itself a FileCreate event, and on Docker Desktop its `TargetFilename` held the full Windows user path. A scrub grep found it before any commit. The capture is now built inside the container and copied out last, and a test fails if a host path or personal string appears in a capture.
- **Every event was labelled noise.** The first labelling used `$!` from the capture script as the attack root. It gave 8531 where Sysmon reported 8977 for the same process, so signal was 0 and every detection showed as missed, while the alerts themselves looked right. Even with `--pid=host`, Docker Desktop's PID namespace is nested and Sysmon reports kernel root namespace PIDs. Fixed with a marker: `attack.sh` runs `printenv LAB_ATTACK_ROOT_MARKER`, and that event's `ParentProcessId` gives the root in Sysmon's numbering. This also means the truth file was removed.
- **ProcessGuid lineage drops an event.** `cat /etc/shadow > /tmp/.s` opens the file after fork and before exec, so the FileCreate says `Image=/usr/bin/bash` with an all-zero `ProcessGuid`. It is the file holding the stolen hashes. Walking GUIDs finds 79 of the 80 signal events and misses this one. Labels use PID lineage. A test pins the difference.
- **`decoded_into_shell` matched the wrong process.** With a 2-second window it paired `base64 -d` with an unrelated `bash -c` from the previous attack stage, so it fired for the wrong reason. Members of one pipeline start within milliseconds, so the window is now 0.5 seconds and the alert names the `sh` it really matched.

## Limitations

- One scripted attack and about 36 seconds per capture, so rates are not a forecast for a real host. The workload is small enough that the tuned config's 92% is a result for this workload only.
- The tuned config was written after looking at this exact workload, so its exclusions fit it perfectly. Real tuning needs a hold-out period to check against.
- Tuned exclusions drop the attacker's own `sleep` and its `curl` connection to port 8000. The `curl` command line still appears in ProcessCreate, so the detection holds. A health check using the same port and tool remains a place to hide.
- The tuned config has no exclusion for `<unknown process>`, on purpose, even though it made up 50 noisy events. It marks a process started before Sysmon, which is what an implant already running would look like.
- PID lineage breaks if a PID is reused during a capture, and shows less when a config hides a parent (under the overtuned config, `id` under an excluded `sh` counts as noise).
- `--pid=host` means the sensor also sees the Docker VM (for example `fstrim`) and the listener container. Those events count as noise. Inside a real host this would be similar.
- Sysmon for Linux has fewer event types than Windows. There is no DNS query event, registry or image load, and its ProcessCreate fires on exec, not fork.
- Detections are substring and path checks in Python. Renaming `curl` or using `python3` to download would beat `download_to_temp`. Day 5 of this series moves to Sigma.
- CI only runs the analysis and tests on committed captures. It does not run Sysmon. Captures were made on Docker Desktop with WSL2 kernel 6.6.87.2; other kernels were not tried.

## Layout

```
docker/Dockerfile         sensor image: Ubuntu 22.04, Sysmon for Linux 1.6.0, rsyslog
configs/                  noisy, tuned and overtuned Sysmon configs
scenario/                 benign.sh, attack.sh, run_capture.sh, harmless payloads
scripts/capture.sh        builds the image, runs listener and sensor containers
data/captures/            real Sysmon events from the synthetic workload
sysmontel/parser.py       syslog lines to events, counts lines it cannot parse
sysmontel/lineage.py      attack root from the marker, PID and GUID lineage
sysmontel/detections.py   eight ATT&CK-mapped rules
sysmontel/metrics.py      volume, signal share, rules kept and lost
sysmontel/report.py       Markdown and JSON output
tests/                    pytest
docs/DESIGN_NOTES.md      design decisions
```

## Licence

MIT, see LICENSE.
