
## Summary
This is a lib tool for mapping text segment to hugepage, in order to reduce tlb miss.

Tested in linux x86-64 centos7/debian/ubuntu

## check config
```sh
# first, make sure you have configured some hugepages.
$ cat /proc/sys/vm/nr_hugepages

# if got 0, using the following cmd to add hugepages
$ echo 192 > /proc/sys/vm/nr_hugepages

# then check free hugepage num, usually we need at least 1 or 2 HugePages_Free
$ cat /proc/meminfo | grep -i huge
AnonHugePages:    176128 kB
HugePages_Total:       9
HugePages_Free:        7
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:       2048 kB
```

## build & execute
```sh
./build.sh

./huge_demo
```
after execute demo, you can check the demo's memory map with the follwing cmd:
```sh
$ cat /proc/`pgrep huge_demo`/maps
```
