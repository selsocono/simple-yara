#!/bin/bash

#Latest
docker build -t container-latest -f ./build/configs/latest/Dockerfile .
docker run --rm --volume "./:/home/simple-yara/" -i container-latest <<EOF
cd /home/simple-yara
go build -ldflags '-s -w -extldflags "-static"' -trimpath -o /home/simple-yara/simple-yara-win64.exe -tags yara_static -buildmode=exe

export GOARCH=386
export PKG_CONFIG_PATH=/home/i686-w64-mingw32/deps/lib/pkgconfig
export CC=i686-w64-mingw32-gcc
export LD=i686-w64-mingw32-lds
go build -ldflags '-s -w -extldflags "-static"' -trimpath -o /home/simple-yara/simple-yara-win32.exe -tags yara_static -buildmode=exe
EOF

#Legacy
docker build -t container-legacy -f ./build/configs/legacy/Dockerfile .
docker run --rm --volume "./:/home/simple-yara/" -i container-legacy <<EOF
cd /home/simple-yara
go build -ldflags '-s -w -extldflags "-static"' -o /home/simple-yara/simple-yara-win32-legacy.exe -tags yara_static -buildmode=exe

export GOARCH=amd64
export PKG_CONFIG_PATH=/home/x86_64-w64-mingw32/deps/lib/pkgconfig
export CC=x86_64-w64-mingw32-gcc
export LD=x86_64-w64-mingw32-ld
go build -ldflags '-s -w -extldflags "-static"' -o /home/simple-yara/simple-yara-win64-legacy.exe -tags yara_static -buildmode=exe
EOF