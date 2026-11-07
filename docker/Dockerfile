# Sysmon for Linux sensor image. Tools come from Ubuntu and Microsoft's package repo.
FROM ubuntu:22.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg rsyslog procps \
      netcat-openbsd python3 passwd \
 && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft.gpg \
 && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/ubuntu/22.04/prod jammy main" > /etc/apt/sources.list.d/microsoft.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends sysmonforlinux \
 && rm -rf /var/lib/apt/lists/*
# The default imklog module would copy the host kernel log into syslog.
RUN sed -i 's/^module(load="imklog".*/#&/' /etc/rsyslog.conf
