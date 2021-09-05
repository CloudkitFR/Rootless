# Rootless

---

## Create User

```sh
$ adduser -d /home/aker -s /home/aker/shell aker  
$ usermod -p "*" aker
```

## Setup Device Files

```sh
$ mkdir /box/dev  
$ mknod -m 666 /box/dev/null c 1 3  
$ mknod -m 666 /box/dev/zero c 1 5  
$ chown root:root /box/dev/null /box/dev/zero  
```

##  Edit SSH config

```
PermitUserEnvironment AKER_USER
```

---

## Vulnerabilities

1. Users can create a symlink to access underlying host filesystem via `ln -s ../`.  
   Fix : `umount2(rootfs, MNT_DETACH);` [(Explanation)](https://unix.stackexchange.com/questions/571823/strange-behaviour-of-pivot-root-in-mount-namespace)
