FROM ubuntu:16.04 AS chroot

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        gcc-multilib \
        libc6-dev:i386 \
        libc6:i386 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ADD ./chall /app/run
ADD ./flag.txt /app
RUN chmod +x /app/run
RUN chmod 644 /app/flag.txt

FROM pwn.red/jail
COPY --from=chroot / /srv
ENV JAIL_MEM=30M JAIL_TIME=60

EXPOSE 5000
