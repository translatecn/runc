# cve
- https://zhuanlan.zhihu.com/p/401057262
- https://cloud.tencent.com/developer/article/2161414


- https://blog.csdn.net/qq_43375973/article/details/117387384

- busctl --user --no-pager status|grep OwnerUID
- 什么是 RootlessCgroupManager  、 If the value is 0, we have rootful systemd inside userns, so we do not need the rootless cgroup manager.


- 无根容器 rootless
- https://developer.aliyun.com/article/780825
- https://blog.csdn.net/flynetcn/article/details/138550515

- newuidmap
- newgidmap
- criu  // https://blog.csdn.net/qq_43375973/article/details/117387384
- systemd.NewUnifiedManager
- systemd.NewLegacyManager
- fs.NewManager
- fs2.NewManager
- Cgroup2Unified   // 是 cgroup v2 的一个特性，它强调的是不同资源控制器的统一管理，使得资源的分配和限制更加高效和灵活。
- Cgroup2Hybrid    // 关注于如何在支持新的 cgroup v2 特性的同时，继续支持旧的 cgroup v1 接口




- /proc/self/ns/user
- /proc/self/ns/cgroup

```
org.systemd.property.Type=simple
org.systemd.property.TypeSec=simple
```



### mknod
```
- NewSockPair
- createExecFifo
- https://baike.baidu.com/item/mknod/3561210?fr=ge_ala
```


```
docker pull registry.ap-southeast-1.aliyuncs.com/acejilam/ls-2018:v1.1.12-arm
docker pull registry.ap-southeast-1.aliyuncs.com/acejilam/ls-2018:v1.1.12-amd

docker tag registry.ap-southeast-1.aliyuncs.com/acejilam/ls-2018:v1.1.12-amd registry.cn-hangzhou.aliyuncs.com/acejilam/runc_dev:v1.1.12-amd
docker tag registry.ap-southeast-1.aliyuncs.com/acejilam/ls-2018:v1.1.12-arm registry.cn-hangzhou.aliyuncs.com/acejilam/runc_dev:v1.1.12-arm

docker push registry.cn-hangzhou.aliyuncs.com/acejilam/runc_dev:v1.1.12-arm
docker push registry.cn-hangzhou.aliyuncs.com/acejilam/runc_dev:v1.1.12-amd

docker manifest rm registry.cn-hangzhou.aliyuncs.com/acejilam/runc_dev:v1.1.12

docker manifest create registry.cn-hangzhou.aliyuncs.com/acejilam/runc_dev:v1.1.12 --amend registry.cn-hangzhou.aliyuncs.com/acejilam/runc_dev:v1.1.12-arm --amend registry.cn-hangzhou.aliyuncs.com/acejilam/runc_dev:v1.1.12-amd

docker manifest push registry.cn-hangzhou.aliyuncs.com/acejilam/runc_dev:v1.1.12
docker manifest inspect registry.cn-hangzhou.aliyuncs.com/acejilam/runc_dev:v1.1.12

```



1、runc start -- pipe --> runc init
    ENV:
        GOMAXPROCS=4
        _LIBCONTAINER_INITPIPE=3
        _LIBCONTAINER_STATEDIR=/run/containerd/runc/k8s.io/000673ca95406e146f7a88a6f03dfeb7c7f15f89c80f957f3850ca29ff7c6301
        _LIBCONTAINER_LOGPIPE=4
        _LIBCONTAINER_LOGLEVEL=4
        _LIBCONTAINER_FIFOFD=5
        _LIBCONTAINER_INITTYPE=standard


    ExtraFiles:
        NewSockPair      init-c    3
        os.Pipe()        |1        4
        /run/containerd/runc/k8s.io/425f28daf8c6dd7935d6a748dce42e505e002d61e871b4c6919902bf7f6651ed/exec.fifo


    runc init 的 c模块会向 runc start 发送  0、stage2_pid、stage1_pid