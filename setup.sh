#!/bin/sh

TMP=$(pwd)/box
mknod -m 666 $TMP/dev/null c 1 3; chown root:root $TMP/dev/null
mknod -m 666 $TMP/dev/zero c 1 5; chown root:root $TMP/dev/zero
mknod -m 666 $TMP/dev/random c 1 8; chown root:root $TMP/dev/random
mknod -m 666 $TMP/dev/urandom c 1 9; chown root:root $TMP/dev/urandom

chown -R aker:aker .ssh
chmod 700 .ssh
chmod 600 .ssh/authorized_keys

chown -R aker:aker box/aker
chmod -R 1700 box/aker

chown -R aker:aker box/var/lib/dpkg
chmod -R 700 box/var/lib/dpkg
chown -R aker:aker box/var/cache/apt
chmod -R 700 box/var/cache/apt
chown -R aker:aker box/tmp
chmod -R 700 box/tmp

chown -R aker:aker box/var/lib/apt/lists
chmod -R 700 box/var/lib/apt/lists
