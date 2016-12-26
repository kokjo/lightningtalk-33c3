FROM 32bit/debian

EXPOSE 1337

RUN apt-get -qy update
RUN apt-get -qy install socat

COPY pwnable .
COPY flag .

RUN useradd pwnable

USER pwnable

CMD socat tcp-listen:1337,fork,reuseaddr system:/pwnable
