FROM ubuntu:18.04
MAINTAINER reginleif


RUN apt-get update -y
RUN apt-get install xinetd  -y
RUN apt-get install git gdb -y

RUN useradd -U -m dwarrowdelf

ADD --chown=root:root flag /home/dwarrowdelf/
ADD --chown=root:root xinetd /etc/xinetd.d/dwarrowdelf

EXPOSE 13371/tcp


RUN chmod 774 /tmp
RUN chmod -R 774 /var/tmp
RUN chmod -R 774 /dev
RUN chmod -R 774 /run
RUN chmod 1733 /tmp /var/tmp /dev/shm

ADD --chown=root:root bin/libcapstone.so.4 /usr/lib/libcapstone.so.4
RUN chmod 755 /usr/lib/libcapstone.so.4
RUN ln -s /usr/lib/libcapstone.so.4 /usr/lib/libcapstone.so

RUN chown -R root:root /home/dwarrowdelf
ADD --chown=root:root bin/dwarrowdelf /home/dwarrowdelf/dwarrowdelf
RUN chmod -r /home/dwarrowdelf/dwarrowdelf

CMD ["/usr/sbin/xinetd","-dontfork"]
