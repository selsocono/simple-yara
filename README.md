# simple-yara

[![GitHub license](https://img.shields.io/github/license/selsocono/simple-yara)](https://github.com/selsocono/simple-yara/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/selsocono/simple-yara)](https://github.com/selsocono/simple-yara/stargazers)


simple-yara is an open source project that allows you to statically build a simple golang yara scanner for all architectures and all versions of the Windows OS.
simple-yara is designed to help developers quickly and easily assemble their projects written in golang with the built-in yara engine.

## Help

```
D:\simple-yara\simple-yara-win64.exe --help
Usage of D:\simple-yara\simple-yara-win64.exe:
  -dir string
        path to scan file or directory. example: C:\Windows\System32\
  -rules string
        path to file with rules. example: C:\test1.yar
```
## Usage
```
D:\simple-yara\simple-yara-win64.exe --dir=C:\Windows\System32\ --rules=D:\simple-yara\test1.yar
```

## Latest version
<code>[GO](https://go.dev/dl/)
</code> 1.21.0 (latest)

<code>[YARA](https://github.com/VirusTotal/yara/releases)
</code> 4.3.2 (latest)

<code>[go-yara](https://github.com/hillu/go-yara/tags)
</code> 4.3.2 (latest)

<code>[OPENSSL](https://www.openssl.org/source/)
</code> 3.1.2 (latest)

## Legacy version (for Windows XP)
<code>[GO](https://go.dev/dl/)
</code> 1.11.4

<code>[YARA](https://github.com/VirusTotal/yara/releases)
</code> 4.2.0

<code>[go-yara](https://github.com/hillu/go-yara/tags)
</code> 4.0.4

<code>[OPENSSL](https://www.openssl.org/source/)
</code> 1.1.1-stable

### Supported operating systems:
`Windows XP`
`Windows Vista`
`Windows 7`
`Windows 8`
`Windows 8.1`
`Windows 10`
`Windows 11`
`Windows Server 2003`
`Windows Server 2008`
`Windows Server 2008 R2`
`Windows Server 2012`
`Windows Server 2012 R2`
`Windows Server 2016`
`Windows Server 2019`
`Windows Server 2022`

## Build instruction

### Install Docker

<code>[Install Docker Engine on Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
</code>

### Run commands:

```
git clone https://github.com/selsocono/simple-yara.git
cd ./simple-yara
clear && time ./build.sh
```