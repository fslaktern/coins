FROM debian:bookworm-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nasm binutils make musl-tools dpkg-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Makefile coins.asm ./
RUN make clean && make

RUN echo "deb-src [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian bookworm main" > /etc/apt/sources.list.d/src.list \
 && apt-get update \
 && cd /tmp \
 && apt-get source socat \
 && cd socat-* \
 && ./configure --disable-openssl --disable-readline CC=musl-gcc \
 && make -s LDFLAGS=-static \
 && cp socat /src/socat-static

FROM scratch
COPY --from=build /src/coins /coins
COPY --from=build /src/socat-static /usr/bin/socat
EXPOSE 4919
CMD ["socat", "TCP-LISTEN:4919,reuseaddr,fork", "EXEC:/coins,stderr"]
