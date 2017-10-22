!This code requires an independent audit check!

libsodium-go
============
A binding library made in Go for the popular portable cryptography library [Sodium](https://download.libsodium.org/doc/).


Purpose
-------
The goal of this binding library is to make use of Sodium in a more Go friendly matter.  And of course making it easier to make secure software.

Team (as of now...)
----------------
<ul>
<li>Stephen Chavez (@redragonx)</li>
<li>Graham Smith (@neuegram)</li>
</ul>

Contributors
------------
Silkeh

How to build
------------
For linux, this should be easy since there's pkg-config support. Please make sure libsodium is installed on your system first.

Pre-setup:
1. Please install Libsodium here https://download.libsodium.org/doc/installation/index.html
2. `sudo ldconfig`
3. `sudo apt-get install pkg-config`

Install libsodium-go:
1. `go get -d github.com/GoKillers/libsodium-go`
2. `cd $GOPATH/src/github.com/GoKillers/libsodium-go`
3. `./build.sh`

For Windows, this requires a little more work.

1. Download and install pkg-config for [win32](http://ftp.gnome.org/pub/gnome/binaries/win32/dependencies/) or [win64](http://ftp.gnome.org/pub/gnome/binaries/win64/dependencies/)
2. Add a system or user variable PKG_CONFIG_PATH pointing to a folder containing pkg-config files, including libsodium
3. `go get -d github.com/GoKillers/libsodium-go`
4. `cd %GOPATH%/src/github.com/GoKillers/libsodium-go`
5. `build.bat`

License
---------
Copyright 2015 - GoKillers
