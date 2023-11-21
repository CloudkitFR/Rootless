# Rootless

---

We need to spawn the process into a new TTY.

---

## Vulnerabilities

1. Users can create a symlink to access underlying host filesystem via `ln -s ../`.  
   **Fix:** `umount2(rootfs, MNT_DETACH);` [(Explanation)](https://unix.stackexchange.com/questions/571823/strange-behaviour-of-pivot-root-in-mount-namespace)
