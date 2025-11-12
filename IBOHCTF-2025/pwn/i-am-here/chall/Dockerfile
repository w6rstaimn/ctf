FROM ubuntu:18.04 AS chroot

ADD ./chall /app/run
ADD ./flag.txt /app
RUN chmod +x /app/run

FROM pwn.red/jail
COPY --from=chroot / /srv
ENV JAIL_MEM=30M JAIL_TIME=60

EXPOSE 5000