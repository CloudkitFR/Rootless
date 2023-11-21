#!/bin/sh

TMP=$(pwd)/box

# Download debian 12 (bookworm) base image.
wget https://github.com/debuerreotype/docker-debian-artifacts/raw/dist-amd64/bookworm/rootfs.tar.xz
rm -rf box
mkdir box
tar -xvf rootfs.tar.xz -C box
rm rootfs.tar.xz

# Source
# https://www.fr.linuxfromscratch.org/view/lfs-6.1-fr/chapter06/devices.html
mknod -m 622 $TMP/dev/console c 5 1
mknod -m 666 $TMP/dev/null c 1 3
mknod -m 666 $TMP/dev/zero c 1 5
mknod -m 666 $TMP/dev/ptmx c 5 2
mknod -m 666 $TMP/dev/tty c 5 0
mknod -m 444 $TMP/dev/random c 1 8
mknod -m 444 $TMP/dev/urandom c 1 9
chown -R root:root $TMP/dev

# Populate dev
mkdir $TMP/dev/pts
mkdir $TMP/dev/shm
