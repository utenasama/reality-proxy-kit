FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive container=docker
RUN apt-get update && apt-get install -y systemd systemd-sysv dbus openssh-server python3 sudo curl ca-certificates iproute2 openssl && rm -rf /var/lib/apt/lists/* && systemctl enable ssh && rm -f /etc/machine-id /var/lib/dbus/machine-id && touch /etc/machine-id
STOPSIGNAL SIGRTMIN+3
COPY entrypoint.sh /usr/local/bin/rpk-lab-init
CMD ["/bin/sh", "/usr/local/bin/rpk-lab-init"]
