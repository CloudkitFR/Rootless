#!/bin/sh

TMP=$(pwd)/box

# Setup SSH

chown -R aker:aker box/aker
chmod -R 1700 box/aker

# Source
# https://www.fr.linuxfromscratch.org/view/lfs-6.1-fr/chapter06/devices.html

mknod -m 622 $TMP/dev/console c 5 1
mknod -m 666 $TMP/dev/null c 1 3
mknod -m 666 $TMP/dev/zero c 1 5
mknod -m 666 $TMP/dev/ptmx c 5 2
mknod -m 666 $TMP/dev/tty c 5 0
mknod -m 444 $TMP/dev/random c 1 8
mknod -m 444 $TMP/dev/urandom c 1 9
chown -R aker:aker $TMP/dev


# Populate dev

# ln -s /proc/self/fd /dev/fd
# ln -s /proc/self/fd/0 /dev/stdin
# ln -s /proc/self/fd/1 /dev/stdout
# ln -s /proc/self/fd/2 /dev/stderr
# ln -s /proc/kcore /dev/core
# mkdir /dev/pts
# mkdir /dev/shm

# Set apt, dpkg, tmp permissions

chown -R aker:aker box/var/lib/apt/lists
chmod -R 700 box/var/lib/apt/lists
chown -R aker:aker box/var/lib/dpkg
chmod -R 700 box/var/lib/dpkg
chown -R aker:aker box/var/cache/apt
chmod -R 700 box/var/cache/apt
chown -R aker:aker box/tmp
chmod -R 700 box/tmp
