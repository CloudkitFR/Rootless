# Rootless

---

## Create User

```sh
$ adduser -d /home/aker -s /home/aker/shell aker
$ usermod -p "*" aker
```

## Setup Device Files

```sh
$ export TMP=/home/box
$ mknod -m 666 $TMP/dev/null c 1 3; chown root:root $TMP/dev/null
$ mknod -m 666 $TMP/dev/zero c 1 5; chown root:root $TMP/dev/zero
$ mknod -m 666 $TMP/dev/random c 1 8; chown root:root $TMP/dev/random
$ mknod -m 666 $TMP/dev/urandom c 1 9; chown root:root $TMP/dev/urandom
```

##  Edit SSH Config

```
PermitUserEnvironment AKER_USER
```

---

## Vulnerabilities

1. Users can create a symlink to access underlying host filesystem via `ln -s ../`.  
   **Fix:** `umount2(rootfs, MNT_DETACH);` [(Explanation)](https://unix.stackexchange.com/questions/571823/strange-behaviour-of-pivot-root-in-mount-namespace)
