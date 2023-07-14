FROM ubuntu:latest

LABEL about="This file is just container..."
LABEL version="1.0.1"
LABEL author="@selsocono"

ENV GO=1.20.6
ENV OPENSSL=openssl-3.0.9
ENV YARA_VERSION=v4.3.2
ENV HILLU=4.3.2

ENV GOLANGARCH=amd64
ENV BUILD_THREADS=8
ENV ARCH_x32=i686
ENV ARCH=x86_64
ENV GOOS=windows
ENV GOARCH=amd64
ENV MINGWARCH_x32=mingw
ENV MINGWARCH=mingw64
ENV WORKDIR=/home
ENV GODIR=/usr/local
ENV DEPSDIR=$WORKDIR/${ARCH}-w64-mingw32/deps
ENV DEPSDIR_x32=$WORKDIR/${ARCH_x32}-w64-mingw32/deps
ENV BUILDDIR=$WORKDIR/build
ENV CGO_ENABLED=1
ENV GOCACHE=$WORKDIR/build-cache/go
ENV GOMODCACHE=$WORKDIR/build-cache/mod

WORKDIR $WORKDIR

RUN mkdir -p $BUILDDIR && mkdir -p $DEPSDIR && mkdir -p $DEPSDIR_x32 && mkdir -p $GODIR &&  \
    mkdir -p /root/go/src/github.com/hillu/go-yara  &&  mkdir -p $GODIR/go/src/golang.org/ && mkdir -p $WORKDIR

#DEPENDENCES
RUN apt-get clean && apt-get update && apt-get install -y wget build-essential pkg-config git gcc-multilib  \
    gcc-mingw-w64 autoconf automake libtool libjansson-dev libmagic-dev libssl-dev flex

#OPENSSL x32
RUN git clone --depth=1 --branch=$OPENSSL https://github.com/openssl/openssl.git $WORKDIR/${ARCH_x32}-w64-mingw32/openssl
RUN cp -r $WORKDIR/${ARCH_x32}-w64-mingw32/openssl $WORKDIR/${ARCH}-w64-mingw32/openssl
WORKDIR $WORKDIR/${ARCH_x32}-w64-mingw32/openssl
RUN ./Configure --prefix=$DEPSDIR_x32 --cross-compile-prefix=${ARCH_x32}-w64-mingw32- shared $MINGWARCH_x32 &&  \
    make -j$BUILD_THREADS && make install_dev

#YARA x32
WORKDIR $WORKDIR
RUN git clone --depth=1 --branch=$YARA_VERSION https://github.com/VirusTotal/yara.git $WORKDIR/${ARCH_x32}-w64-mingw32/yara
RUN cp -r $WORKDIR/${ARCH_x32}-w64-mingw32/yara $WORKDIR/${ARCH}-w64-mingw32/yara
WORKDIR $WORKDIR/${ARCH_x32}-w64-mingw32/yara
ENV PKG_CONFIG_LIBDIR=$DEPSDIR_x32/lib/pkgconfig
RUN ./bootstrap.sh
RUN ./configure CPPFLAGS="$(pkg-config --static --cflags openssl)" LDFLAGS="$(pkg-config --static --libs openssl)"  \
    --prefix=$DEPSDIR_x32 --host=${ARCH_x32}-w64-mingw32 --disable-shared --with-crypto &&  \
    make -j$BUILD_THREADS && make install

#OPENSSL x64
WORKDIR $WORKDIR/${ARCH}-w64-mingw32/openssl
RUN ./Configure --prefix=$DEPSDIR --cross-compile-prefix=${ARCH}-w64-mingw32- shared $MINGWARCH &&  \
    make -j$BUILD_THREADS && make install_dev

#YARA x64
WORKDIR $WORKDIR/${ARCH}-w64-mingw32/yara
ENV PKG_CONFIG_LIBDIR=$DEPSDIR/lib64/pkgconfig
RUN ./bootstrap.sh
RUN ./configure CPPFLAGS="$(pkg-config --static --cflags openssl)" LDFLAGS="$(pkg-config --static --libs openssl)"  \
    --prefix=$DEPSDIR --host=${ARCH}-w64-mingw32 --disable-shared --with-crypto &&  \
    make -j$BUILD_THREADS && make install

#GOLANG
WORKDIR $WORKDIR
RUN wget https://golang.org/dl/go$GO.linux-$GOLANGARCH.tar.gz
RUN tar -xvf go$GO.linux-$GOLANGARCH.tar.gz -C $GODIR

ENV GO111MODULE=off

#HILLU
WORKDIR $WORKDIR
RUN wget https://github.com/hillu/go-yara/archive/v$HILLU.tar.gz
RUN tar -xvf $WORKDIR/v$HILLU.tar.gz -C $WORKDIR/
WORKDIR $WORKDIR/go-yara-$HILLU
RUN cp -r ./ /root/go/src/github.com/hillu/go-yara

ENV PKG_CONFIG_LIBDIR=$DEPSDIR/lib64/pkgconfig
ENV PKG_CONFIG_PATH=$DEPSDIR/lib/pkgconfig
ENV CC=$ARCH-w64-mingw32-gcc
ENV LD=$ARCH-w64-mingw32-ld
ENV GOROOT=$GODIR/go
ENV GOPATH=/root/go
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$GODIR/go/bin"

WORKDIR $WORKDIR