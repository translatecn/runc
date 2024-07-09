## 封印文件描述符


使用memfd_create(2)创建的文件描述符，默认具有F_SEAL_SEAL标记，不能再更改封印标记，
此时，客户端进程可使用ftruncate(2)扩大或者缩小共享内存大小。为了能够封印，需要在memfd_create中使用MFD_ALLOW_SEALING标记。

`fd = memfd_create(name, MFD_ALLOW_SEALING);`
顺带一提，memfd_create中的name只是用于debug（在proc中），即便多次创建相同name的共享内存，
每次都是得到不同的共享内存。当然，实践中最好把客户端标识作为name。

`fcntl(fd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW);`
fcntl(2)中的F_ADD_SEALS操作可以为文件描述符添加封印标记，其中
F_SEAL_SHRINK不允许缩小共享内存，
F_SEAL_GROW不允许扩大共享内存；
F_SEAL_SEAL不允许再执行F_ADD_SEALS操作，这样客户端就不能限制服务端写入。
F_SEAL_WRITE操作，限制写入，因此可以构造只读的共享内存，
这也是为什么在讨论的场景中要加入F_SEAL_SEAL的原因，否则客户端可以限制服务端写入。这时如果尝试用ftruncate改变大小，则会报错。

memfd_create 是在kernel3.17才被引进来
fexecve是glibc的一个函数，是在版本2.3.2之后才有的

# CVE
- CVE-2019-5736




# (clone和fork的区别)
（1）clone和fork的调用方式很不相同，clone调用需要传入一个函数，该函数在子进程中执行。
（2）clone和fork最大不同在于clone不再复制父进程的栈空间，而是自己创建一个新的。 （void *child_stack,）也就是第二个参数，需要分配栈指针的空间大小，所以它不再是继承或者复制，而是全新的创造。




prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) 使进程不可转储
prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) 使进程可转储


```

- NEWNET    = "NEWNET"
- NEWPID    = "NEWPID"
- NEWNS     = "NEWNS"
- NEWUTS    = "NEWUTS"
- NEWIPC    = "NEWIPC"
- NEWUSER   = "NEWUSER"
- NEWCGROUP = "NEWCGROUP"

$ unahre --user -r --uts /bin/bash

[root@vm ~]# unshare -h

用法：
unshare [选项] [<程序> [<参数>...]]

以某些未与父(进程)共享的名字空间运行某个程序。

选项：
-m, --mount[=<文件>]      取消共享 mounts 名字空间
-u, --uts[=<文件>]        取消共享 UTS 名字空间(主机名等)
-i, --ipc[=<文件>]        取消共享 System V IPC 名字空间
-n, --net[=<file>]        取消共享网络名字空间
-p, --pid[=<文件>]        取消共享 pid 名字空间
-U, --user[=<文件>]       取消共享用户名字空间
-C, --cgroup[=<文件>]     取消共享 cgroup 名字空间
-f, --fork                在启动<程序>前 fork
--kill-child[=<signame>]  when dying, kill the forked child (implies --fork); defaults to SIGKILL
--mount-proc[=<目录>] 先挂载 proc 文件系统(连带打开 --mount)
-r, --map-root-user       将当前用户映射为 root (连带打开 --user)
--propagation slave|shared|private|unchanged
修改 mount 名字空间中的 mount 传播
-s, --setgroups allow|deny  控制用户名字空间中的 setgroups 系统调用

-h, --help                display this help
-V, --version             display version
```

```
cat /proc/$$/status |egrep 'Cap(Inh|Prm|Eff)'
```






