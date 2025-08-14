##### new-beginning
- 四个过程
    - 事件订阅、dplane打包为context、传给master线程、master线程读取和使用消息
- 使用GDB学习interface的调用栈
    - `docker exec -it clab-frr01-router1 bash`
- 讲ARP的具体流程及测试

- 执行 `ip addr add 192.168.1.100/24 dev eth0`
   1. ip命令通过netlink -> 内核
   2. 内核配置地址成功
   3. 内核通过`netlink multicast` -> Zebra
   4. Zebra收到 `RTM_NEWADDR` 消息
   5. Zebra调用`connected_add_ipv4()` -> `connected_update()`

- 详细调用过程
    1. 事件订阅
        -> 从group移动到dplane_groups即可，表示要注册的事件 (`kernel_netlink.c`)
        -> `netlink_socket` 新建一个内核socket， 侦听这些事件
    2. 事件发生时，以ip addr add 为例
        1. `static void dplane_incoming_read(struct event *event)` 先获取事件的上下文数据 zi (`zebra_dplane.c`)
        2. 调用 `int kernel_dplane_read(struct zebra_dplane_info *info)`函数来从内核的数据平面读取信息，传入的是 `zi->info`，包含了读取配置和状态的数据。
        具体的读取操作将在 `kernel_dplane_read` 内部完成，该函数负责与数据平面接口交互，获取所需的原始数据
        3. 在`kernel_dplane_read`中，首先根据接口信息的`socket id`找到对应的`netlink socket`，然后
        `netlink_parse_info(netlink_parse_info, nl, info, 5,false)`读取消息进行具体的处理,`netlink_parse_info`内部通过`netlink_recv_msg`来获取消息，
        并将消息给回调函数`static int dplane_netlink_information_fetch(struct nlmsghdr *h, ns_id_t ns_id,int startup)`处理
        4. `dplane_netlink_information_fetch`根据netlink message header中的 type 确定是什么消息，这里调用`netlink_interface_addr_dplane`进行`RTM_NEWADDR`消息的处理，`ifa = NLMSG_DATA(h)`从中解析ip地址相关信息，然后`netlink_parse_rtattr`解析出消息的各个属性（在include/linux/if_addr.h），验证完毕后，打包数据到`ctx`中
    3. 将 `zebra_dplane_ctx` 通过函数 `dplane_provider_enqueue_to_zebra` 交给主线程处理，
       1. 先把`ctx`放在`temp_list`的队尾，然后 `(zdplane_info.dg_results_cb)(&temp_list);`来处理这个`queue`
    4. 消息读取
       1. 在dplane启动的时候，`zdplane_info.dg_results_cb` 赋值为了 `rib_dplane_results`，`rib_dplane_results`函数将`ctx`放在全局变量`rib_dplane_q`中，并使用
      `event_add_event(zrouter.master, rib_process_dplane_results, NULL, 0,&t_dplane);` 通知主线程来处理这个消息。
       2. `rib_process_dplane_results` 从`rib_dplane_q`取出所有`ctx`，根据 `dplane_ctx_get_op(ctx)` 的不同，此处调用 `zebra_if_dplane_result(ctx)`来处理接口信息的更改消息，此处调用`zebra_if_addr_update_ctx(ctx, ifp);`进行地址的增添。
       3. 在`zebra_if_addr_update_ctx`中，提取出ctx的各个标志位，然后调用`connected_add_ipv4(ifp, flags, &addr->u.prefix4, addr->prefixlen,dest ? &dest->u.prefix4 : NULL, label, metric);`添加ipv4的地址，将携带的地址信息比如AF_family、前缀、前缀长度等打包为新的ifc，然后调用`connected_update(ifp, ifc);`来更新信息并通告出去。

##### ARP/NDP

1. ARP 协议
    ARP（Address Resolution Protocol，地址解析协议）是一种工作在网络层与链路层之间的协议，主要用于将一个IP地址解析为对应的MAC地址。在以太网或无线局域网等局域网环境中，设备之间的通信依赖于 MAC 地址进行寻址，而上层协议如IP协议则使用IP地址进行定位。
2. ARP 的工作原理
    当一台主机需要向同一子网内的另一台主机发送数据时，它会首先检查自己的ARP缓存表，看是否已经保存了该目标IP地址对应的MAC地址。如果缓存中存在该记录，主机就可以直接使用该MAC地址发送数据。如果没有找到匹配的记录，主机就会发起一个ARP请求。
    ARP 请求是一种广播消息，它会被发送到局域网中的所有主机。该请求包含发送方的IP和MAC地址，以及目标的IP地址。网络中的所有主机在接收到ARP请求后，会检查请求中的目标IP是否与自身的IP地址相符。如果匹配，目标主机会发送一个ARP响应，该响应是单播的，仅发送给请求者。一旦请求方收到ARP响应，它会将IP和MAC的映射关系添加到自己的ARP缓存表中，以便后续通信使用。
3. ARP 报文的格式
    在以太网中，ARP报文是封装在以太网帧中的。以太网帧头部包含目标MAC地址、源MAC地址和一个类型字段（值为0x0806表示ARP）。ARP报文本身则包含了硬件类型（如以太网是1）、协议类型（IPv4是0x0800）、硬件地址长度、协议地址长度、操作码（表示请求或响应）、发送方和目标的MAC和IP地址。这些字段共同定义了一条完整的ARP请求或响应消息。
4. ARP 的缓存机制
    为了避免频繁地发起ARP请求，操作系统会维护一个ARP缓存表，用于记录已经解析过的IP-MAC对应关系。这些记录通常有一个生命周期（例如60秒或更长），在生命周期结束后会被删除。用户可以通过命令如`arp -a`或`ip neigh`来查看当前的ARP表项。

- 关于neigh的操作
    - `DPLANE_OP_NEIGH_INSTALL`:
	- `DPLANE_OP_NEIGH_UPDATE`:
	- `DPLANE_OP_NEIGH_DELETE`:
	- `DPLANE_OP_VTEP_ADD`:
	- `DPLANE_OP_VTEP_DELETE`:
        - 这些操作调用`kernel_neigh_update_ctx(ctx)`，把邻居表等变更从zebra同步到内核

	- `DPLANE_OP_NEIGH_IP_INSTALL`:
	- `DPLANE_OP_NEIGH_IP_DELETE`:
    - `DPLANE_OP_NEIGH_DISCOVER`:
        - 既可以将消息同步到内核，也可以**接受来自内核的netlink消息**
        - netlink_put_neigh_update_msg 回调 netlink_neigh_msg_encoder，然后调用netlink_neigh_update_ctx
        - netlink_neigh_update_ctx将邻居项（ARP或NDP）通过netlink协议写入内核，它根据dplane数据平面上下文，构造netlink消息并调用底层编码函数netlink_neigh_update_msg_encode，用于构造一条完整的netlink邻居更新消息（RTM_NEWNEIGH/RTM_DELNEIGH）并填充到data缓冲区中

	- `DPLANE_OP_NEIGH_TABLE_UPDATE`:
        - `zebra_configure_arp` -> `dplane_neigh_table_update`
        - 当zebra收到某个配置请求（ZAPI消息），包含接口索引和地址族信息时，它会找到对应的接口，并调用数据面函数`dplane_neigh_table_update`来更新该接口的邻居表（ARP/NDP）
    - debug
        -  `b: zebra_neigh_del`
        -  `b: zebra_neigh_new`
        -  `sudo ip neigh add 192.1.1.1 lladdr aa:aa:aa:aa:aa:aa dev eth0`
        -  `sudo ip neigh del 192.1.1.1 dev eth0`

##### 原本主线程处理逻辑
- 需要处理的RTM_NEIGH消息分为`RTM_NEWNEIGH`(28)、`RTM_DELNEIGH`(29)、`RTM_GETNEIGH`(30)
- 对于`RTM_NEWNEIGH`消息 `sudo ip neigh add 192.1.1.1 lladdr aa:aa:aa:aa:aa:aa dev eth3`
  - ![alt text](image.png)
  - 在`netlink_information_fetch`中，根据`h->nlmsg_type`
    - 如果是上述三类`RTM_NEIGH`消息，则调用`netlink_neigh_change`函数
    - `netlink_neigh_change` 函数用于处理来自内核的邻居表变更消息，它首先检查消息类型是否为 ##新增、删除或查询邻居## ，再验证消息长度是否合法。随后根据地址族判断是处理桥接设备的MAC FDB?表（通过AF_BRIDGE）还是IPv4/IPv6的邻居表（通过AF_INET或AF_INET6），并分别调用对应的处理函数；对不属于这些类型或地址族未知的消息则直接忽略或记录警告。
    - 此处进入`netlink_ipneigh_change`，读取并拷贝解析邻居消息中的IP地址和MAC地址等属性，本地邻居通过`zebra_neigh_add(ifp, &ip, &mac);`添加，在内部邻居表中查找：是否已经存在这个接口上的该IP的邻居条目，如果没有这个邻居条目，调用 `zebra_neigh_new`创建一个新的邻居项并插入内部表，如果有这个条目，若要更新则调用`zebra_neigh_pbr_rules_update`更新policy_based_routing规则
- 对于`RTM_DELNEIGH`消息，在`netlink_ipneigh_change`中执行`zebra_neigh_del(ifp, &ip)`删除条目
    - 先查找再删除，远端remote邻居？
    ![alt text](image-1.png)

todo:调试一下vlan的执行流程
`sudo ip link set dev eth0 mtu 1500`产生`RTM_NEWLINK`事件，调用`netlink_link_change`函数，产生的操作是`DPLANE_OP_INTF_INSTALL`

##### 实习任务
当前zebra从kernel读取信息会从两个socket，分别在main thread和dplane thread中读取。 由于读取的各种类型数据之间可能存在依赖关系，在两个thread中读取可能会存在时序问题： 比如当前接口信息是在dplane thread中读取，neigh信息是从main thread中读取。由于随机的处理时序，可能会导致neigh被读取时，接口信息还未被处理，导致neigh信息被错误丢弃。 该项目最终目标希望将所有从kernel读取消息的过程全部由zebra master thread移动到dplane thread。 
当前第一阶段优先解决neigh的订阅消息读取，移动到dplane thread中读取。需要保证neigh信息挪入dplane thread后的正确可用，数据的encode/decode ctx符合dplane组件的标准，解决异步线程的数据访问等问题。


##### 设计方案
- 两个消息对应`DPLANE_OP_NEIGH_IP_INSTALL`，`DPLANE_OP_NEIGH_IP_DELETE`两个opcode
- Is this a notification for the MAC FDB or IP neighbor table? 
    - 是否需要修改`ndm_family == AF_BRIDGE`的`netlink_macfdb_change`
        - ip neighbor（邻居表）是操作系统维护的一个IP-MAC 映射表,用于主机进行三层通信（IP层）时查找目标MAC地址，来源包括ARP请求（IPv4）或NDP（IPv6）、静态添加、RA/SLAAC等。
        - MAC FDB（Forwarding Database）是Linux bridge或VXLAN设备等维护的一个 MAC-接口/VLAN/VNI 映射表，用于二层交换场景下，决定MAC帧往哪个接口发送，来源包括动态学习（根据收到的帧）、静态配置、控制面下发（如**EVPN/** BGP等
    - 在`netlink_ipneigh_change`函数中生成ctx，传给master线程
- 执行流程
    1.	在dplane线程读取netlink消息后，构造zebra_dplane_ctx并填入neigh_info；
    2.	设置 `zd_ifindex`、`zd_vrf_id` 和 `zd_ifname`；
    3.	调用 `dplane_ctx_enqueue(ctx)` 把消息送回主线程；
    4.	在主线程里调用 `zebra_neigh_add` / `zebra_neigh_del` 并做 `VxLAN` 桥接处理等。
- 修改方案
    - dplane将ctx填充好之后，接着会执行`zebra_neigh_add`
    - `zebra_neigh_add`及之后函数的参数是ctx应该保存的
        - `struct interface *ifp`, `struct ipaddr *ip`, `struct ethaddr *mac`
        - 这三个参数必须在ctx中有，并且`zebra_neigh_add`中使用到的ifp的信息也需要在`netlink_ipneigh_change`保存到ctx
    - 需要传递的信息
        - 邻居 IP 地址、邻居 MAC 地址、邻居是否为RFC5549类型
        - 邻居状态 (`ndm->ndm_state`)、邻居标志 (`ndm->ndm_flags`)
        - ~~内核 `EXT_FLAGS`，如 `NTF_E_MH_PEER_SYNC`~~
        - 是否是新增/删除、`VNI`、接口索引`ifindex`、所属 VRF、接口名称
    - 不能直接传递ifp（指针），避免数据竞争、悬空指针，最终目的是为了保证线程安全
        - 传递ifp的关键字段：`ifindex`、`ifname`、`vrf_id`
        - 需要保存在`zebra_dplane_ctx`的顶层字段中，例如：`ctx->zd_ifindex`、`ctx->zd_ifname`等
            - 在`zebra_neigh_add`中，需要`ifp->name`、`ifp->ifindex`
    -  先参考PR代码，了解要改的大致哪些
        - https://github.com/FRRouting/frr/pull/13396/files (addr & link change)
        - https://github.com/FRRouting/frr/pull/16737/files (vlan change)
        -  /* We only care about state changes for now*/ , **but why?**
                if (!(h->nlmsg_type == RTM_NEWVLAN)) return 0;
    - **需要修改的文件**
        1. `rt_netlink.c`：主要修改`netlink_ipneigh_change`和`netlink_macfdb_change`
            ``` c
                if (ndm->ndm_state & NUD_VALID) {
                    if (zebra_evpn_mh_do_adv_reachable_neigh_only())
                        local_inactive =
                            !(ndm->ndm_state & NUD_LOCAL_ACTIVE);
                    else
                        /* If EVPN-MH is not enabled we treat STALE
                            * neighbors as locally-active and advertise
                            * them
                            */
                        local_inactive = false;
                    /* Add local neighbors to the l3 interface database */
                    if (is_ext)
                        // remove outer neighbor and reconstruct later
                        zebra_neigh_del(ifp, &ip);
                    else
                        // add local neighbor
                        zebra_neigh_add(ifp, &ip, &mac);
            
                    if (link_if)
                        zebra_vxlan_handle_kernel_neigh_update(
                            ifp, link_if, &ip, &mac, ndm->ndm_state,
                            is_ext, is_router, local_inactive,
                            dp_static);
                    return 0;
                }
                zebra_neigh_del(ifp, &ip);
                if (link_if)
                    zebra_vxlan_handle_kernel_neigh_del(ifp, link_if, &ip);
                return 0;
            ```
            - 对比 `netlink_link_change`、`netlink_interface_addr_dplane`
                - `struct interface`是主线程内部完整的接口对象，包含指针、状态等运行期信息
                - `struct dplane_intf_info`是其在`dplane context`中的“序列化形式”，用于线程间传递接口变更或状态信息，不可传递指针，适用于跨线程结构化通信

            - `ndm->ndm_state`、`ndm->ndm_ifindex`、`ip`、`mac`、`local_inactive`、`is_ext`、`is_router`、`dp_static`、`link_if`、`ifp->name`，`ifp->ifindex`
            - `op`、`ns_id`...
                - 大部分保存在 **`zebra_dplane_ctx.dplane_neigh_info`** 中
                - `ip`保存在`ipaddr`(类似于`prefix`)结构体中，ipaddr是POD，直接 `dplane_neigh_info.ip_addr = ip`
                - `dplane_neigh_info.link.mac = mac`
                - `dplane_neigh_info.flags = ndm->ndm_flags`
                - `dplane_neigh_info.state = ndm->ndm_state`

                - `zebra_dplane_ctx.zd_ifindex = ndm->ndm_ifindex`

                - ~~新定义`is_ext`、`local_inactive`、`dp_static`，也可以考虑使用`update_flags`的位运算来记录~~
                    - ~~`local_inactive`表示该邻居是否被认为是本地非活动的，不应被通告给远端 EVPN 节点
                    - `dp_static`用于标记该邻居在dataplane（数据平面）中是否应以静态项插入（通常不会被自动删除或动态更新）
                - 相应的，需要增加对应的`set`和`get`函数
                    - `dplane_ctx_set_ifindex(ctx, ifi->ifi_index)`等需要修改为`dplane_ctx_set_ifindex(ctx, ndm->ndm_ifindex)`
                    - `dplane_ctx_set_neigh_ip`、`dplane_ctx_set_neigh_mac`、`dplane_ctx_set_neigh_flags`、`dplane_ctx_set_neigh_state`...
                    - `dplane_ctx_get_neigh_ip`、`dplane_ctx_get_neigh_mac`、`dplane_ctx_get_neigh_flags`、`dplane_ctx_get_neigh_state`...
                    - 使用给`get`函数得到之前`set`的变量后，master线程增删逻辑保持不变

                - `ifp`可以直接通过`if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id), ndm->ndm_ifindex)`得到，不用存到ctx中（也可以另外存在ctx中），ctx必定会作为参数传递
                    - `zd_ns_info.ns_id`类型是`uint32_t`，由此可得到`ifp->name`，`ifp->ifindex`

                - `link_if`这段代码可以直接挪到dplane中
                    ``` c
                    if (IS_ZEBRA_IF_VLAN(ifp)) {
                        link_if = if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id),
                                            zif->link_ifindex);
                        if (!link_if)
                            return 0;
                    } else if (IS_ZEBRA_IF_BRIDGE(ifp))
                        link_if = ifp;
                    else {
                        link_if = NULL;
                        if (IS_ZEBRA_DEBUG_KERNEL)
                            zlog_debug(
                                "    Neighbor Entry received is not on a VLAN or a BRIDGE, ignoring");
                    }
                    ```
            - `zebra_neigh.c`：修改`zebra_neigh_del`和`zebra_neigh_add`等函数用于master线程
                - **使用 `struct zebra_dplane_ctx *ctx`替换`struct interface *ifp`、`struct ipaddr *ip`等所有参数**
                - `ifp`接口信息可以由`ns_id`和`ndm->ndm_ifindex`联合得到 
                - 增加`zebra_neigh_dplane_result`函数，以`ctx`为参数，根据`opcode`执行接下来的`zebra_neigh_del`还是`zebra_neigh_add`

            - `dplane_fpm_nl.c`：FPM是FRR中一个将数据平面信息输出给其他系统组件（如内核或控制平面客户端）的通信机制，如果启用了FPM，Zebra会调用`fpm_nl_enqueue() `将这些操作编码成netlink二进制消息，写入fnc->obuf缓冲区

            - `kernel_netlink.c`：将`RTM_NEWNEIGH`、`RTM_DELNEIGH`从main挪到dplane处理
                - 将RTM_NEIGH从groups移到dplane_groups 
            - `kernel_socket.c`：将`RTM_NEWNEIGH`、`RTM_DELNEIGH`从main挪到dplane处理
            - `zebra_dplane.c`：修改`dplane_neigh_info`结构体增加ctx的字段，以及get和set函数
            - `zebra_rib.c` & `zebra_script.c`：增加对neigh消息的处理
                - `zebra_neigh_dplane_result `
            - 
            - ...
        2. **macfdb处理**
            - `vid`保存在~~`vlan_info`的`zebra_vxlan_vlan_array`的`zebra_vxlan_vlan`的`vid`字段？还是新开字段~~**`dplane_mac_info`**的`vid`
                - `vni`、`vtep_ip`、`nhg_id`、`is_sticky`、`mac`、`vid`...
            - `local_inactive`、`dp_static`是`netlink_ipneigh_change`和`netlink_macfdb_change`都要用到的，可以放在顶层？
            - 现在`netlink_macfdb_change`中只处理了`RTM_NEWNEIGH`和`RTM_DELNEIGH`消息，还有`RTM_GETNEIGH`呢？
            - `netlink_neigh_change`函数不需要改

##### 相关知识
> if(op == DPLANE_OP_NEIGH_TABLE_UPDATE)  
    ret = netlink_neigh_table_update_ctx(ctx, buf, buflen);
其中 `netlink_neigh_msg_encoder` 用于更新内核信息，用于把路由、接口、邻居表等变更从zebra同步到内核
> `kernel_update_multi` 键函数，用于将多个 dataplane 上下文（dplane_ctx）转换为 Netlink 消息批量发送给内核，从而完成网络配置（如路由、邻居、接口等）在内核态的更新。
> VXLAN 提供了一个可以封装和传送数据的“虚拟通道”（隧道机制），但它不知道数据该送往哪里；EVPN 是一种基于 BGP 的控制平面协议，用于实现现代数据中心中多租户、支持 VXLAN 封装的二三层网络服务。它替代了泛洪学习，通过精确同步、冗余、控制来大幅提升网络弹性与可运维性，相当于EVPN 提供了“地址簿”，告诉网络设备：哪些 MAC/IP 存在哪些远端 VTEP 上，从而指导 VXLAN 正确地封装和转发数据。简言之，VXLAN 负责数据封装，EVPN 负责 MAC/IP 的学习和分发。
> `protodown r-bit` 是一个用于说明“接口为什么被控制平面主动禁用”的状态标志，在FRR中用于配合接口状态管理，尤其是与内核 Netlink 接口交互时，帮助区别物理down和协议down的不同情形。
>  Zebra尽力同步内核的邻居状态变化（如 RTM_NEWNEIGH），但无法做到100%绝对同步，因为系统级异步通信的本质以及内核的行为不可控性。Zebra是被动通过Netlink socket接收邻居变化，如果 Zebra没来得及处理消息，或者消息在Zebra启动前发生，可能会错过；并且如果Zebra处理比较慢、消息太多，可能造成缓冲区溢出；同时邻居的变化速度可能比Zebra的响应更快

- 熟悉一下组内业务

##### test
- `docker build -t frr:dev -f docker/ubuntu-ci/Dockerfile .`
    > docker test时函数有问题，链接阶段找不到strlcpy() 函数的定义（不是编译失败，是链接失败）
    /usr/bin/ld: tests/lib/test_grpc-test_grpc.o: in function `grpc_client_run_test()':
    test_grpc.cpp:(.text+0x16df): undefined reference to `strlcpy(char*, char const*, unsigned long)'
    /usr/bin/ld: tests/lib/test_grpc-test_grpc.o: in function `get_binpath(char const*, char*)':
    test_grpc.cpp:(.text+0x220a): undefined reference to `strlcpy(char*, char const*, unsigned long)'
    /usr/bin/ld: test_grpc.cpp:(.text+0x22c8): undefined reference to `strlcpy(char*, char const*, unsigned long)'
    collect2: error: ld returned 1 exit status
    make: *** [Makefile:9273: tests/lib/test_grpc] Error 1
- 怎么测试修改前后的代码？
    - `frr/tests/topotests/zebra_nhg_check.py`? x！
    - `cd test_to_be_run`
    - `sudo -E pytest ./test_to_be_run.py`
    - **ip neigh add/del**

##### 问题记录
- 0708
    - 是否需要处理`ndm_family == AF_BRIDGE`的`netlink_macfdb_change`？？？
        - 函数处理来自内核AF_BRIDGE子系统的Netlink消息（MAC FDB 的新增/更新/删除），并根据FRR的EVPN配置做相应处理，如添加或删除本地或远程MAC表项。
        - **仅当EVPN启用时才处理macfdb消息**，我们应该先只处理IP neighbor table，不用处理MAC FDB table？
        - 不影响原本的功能
    - 是否需要处理`netlink_handle_5549`
        - 为RFC5549支持创建的IPv4 link-local neighbor entry，如果内核将其删除（RTM_DELNEIGH）或变成失效（NUD_FAILED），就尝试重新安装
        - zebra主动通过Netlink给内核发送邻居项（Neighbor Entry）消息，由内核最终安装到邻居表中（FIB/NDP/ARP 表）
    - 编译出来的docker大1G？
        - 3G
        - `docker build -t frr-incremental .`增量更新
    - 修改思路和文件对吗
    - **文档更具体一些，碰到的问题疑惑可以写一下？先简单改一下？**

- 0709 
    - 为什么在`dplane`线程中打包为ctx，然后由master线程处理，而不是直接由dplane线程接受netlink消息并处理
        - 由master线程统一处理ctx，能保证线程安全和消息同步？
        - 流程：内核netlink通知 -> `dplane thread (netlink_read)` -> 构造`zebra_dplane_ctx` -> 放入队列`dplane_ctx_q` -> `master thread`调度处理ctx -> 更新内部结构（如interface/route/neigh）
        1. 线程职责划分：解耦数据面与控制面 
            - FRR 的设计中，数据平面（dplane）线程主要负责与内核交互（如接收netlink 消息），但不负责决策或状态管理。
            - `dplane thread`（或者叫`zebra_dplane_thread`）专注在 IO，如netlink消息读取；
            - `master thread`（或`event loop`）负责决策逻辑、路由计算、数据结构更新；
            - `zebra_dplane_ctx`作为一种“任务单”，封装内核事件，传给主线程决定如何处理。
        2. 避免数据竞争：共享数据需串行化访问
            - 网络接口列表（iflist）、邻居表（nht, neigh_table）、路由表（RIB）等是核心全局结构。
            - 如果多个线程直接访问并修改这些结构，需要加复杂的锁；
            - 但由主线程统一访问，可以省去锁机制，提升效率并减少bug
        3. 处理异步消息的统一调度机制
            netlink 消息并不总是同步到达，FRR 使用 ctx 作为缓冲和事件投递机制，可以：
            - 将netlink消息标准化为处理任务；
            - 在主线程主循环中按需处理，便于批量处理、合并操作或优化调度；
            - 保证处理顺序一致性
    - 是否需要处理`netlink_handle_5549`
        - 实际调用`kernel_neigh_update(0, ifp->ifindex, (void *)&ipv4_ll.s_addr, mac, 6, ns_id, AF_INET, true);`，但是这个函数只`return 0`，没有其他处理
        - `static const char ipv4_ll_buf[16] = "169.254.0.1"`?

- 0710 与Donald同步
    - 我所需要做的就是将接受从`netlink`发送的`neigh`消息，由主线程处理转为由dplane线程处理，在代码里面将`RTMGPR_NEIGH`从`groups`移动到`dplane_groups`，这样的话，就是改为由dplane线程接收来自内核的邻居消息。我们需要处理的邻居消息分别是`RTM_NEWNEIGH`(28)、`RTM_DELNEIGH`(29)、`RTM_GETNEIGH`(30)，对应到代码中的操作分别是`DPLANE_OP_NEIGH_IP_INSTALL`，`DPLANE_OP_NEIGH_IP_DELETE`，这些消息由`netlink_neigh_change`接收。dplane线程和master线程使用`zebra_dplane_ctx`进行同步，在dplane线程，需要将所有后面主线程用于决策所需要的信息封装在这里面，在neighbor消息处理场景下，要改的地方主要在`rt_netlink.c`文件里面（screen），主要修改`netlink_ipneigh_change`和`netlink_macfdb_change`两个地方，第一个是用于IP 协议族的消息，ip neighbor是操作系统维护的一个IP-MAC 映射表，用于主机进行三层通信（IP层）时查找目标MAC地址；第二个是bridge协议族下的场景，MAC FDB（Forwarding Database）是Linux bridge或VXLAN设备等维护的一个 MAC-接口/VLAN/VNI 映射表，用于二层交换场景下，决定MAC帧往哪个接口发送。我会先实现ip表的处理，具体而言，在处理ip-mac映射的时候，我们主要关注`netlink_ipneigh_change`这个函数(screen)，首先，与`ifp`的都需要移除，然后移动到新建的`zebra_neigh_dplane_result`函数。在这个函数中，前面这些用于提取netlink 消息的属性，以及根据这些属性确定一些标志位，比如`tb[NDA_LLADDR]`、`tb[NDA_DST]`、`ip`、`mac`~~、`local_inactive`、`is_ext`、`is_router`、`dp_static`~~等，这些信息主要保存在`zebra_dplane_ctx.dplane_neigh_info`中，比如`ip`通过 `dplane_neigh_info.ip_addr = ip`，`mac`地址通过`dplane_neigh_info.link.mac = mac`，其他的`tb[NDA_LLADDR]`、`tb[NDA_DST]`~~`local_inactive`、`is_ext`~~等可以在`dplane_neigh_info`中新建。为了保证线程安全，我们不直接传递ifp，避免数据竞争、悬空指针，这可以通过`if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id), ndm->ndm_ifindex)`来得到，`link_if`可以通过ifp得到，这些都放在master线程中去。为了将刚刚说过的信息保存在ctx，我们需要增加一些set和get函数，比如`dplane_ctx_set_neigh_ip`、`dplane_ctx_set_neigh_mac`、`dplane_ctx_set_neigh_flags`、`dplane_ctx_set_neigh_state`等等，我们将封装之后的ctx enqueue到全局的一个`rib_dplane_q`队列。然后我们需要在主线程中处理ctx，根据 `dplane_ctx_get_op(ctx)` 的不同，此处我们使用 `zebra_neigh_dplane_result(ctx)`来处理接口信息的更改消息，比如是增加还是删除`ip neighbor`表的内容等。这是第一大块关于`ip neighbor`表的内容，第二大块是`mac fdb`表的迁移，主要的迁移逻辑和前面的差不多，主要不同之处是中间产生的ctx信息主要存在`dplane_mac_info`中。

- 0714
    - 从讨论之后开始写代码，写到今天写了一个初步的
    - 但是编译一直过不了

    > 当在容器中执行 ip neigh add 命令时，这实际上是通过Linux内核的Netlink接口直接修改邻居表，而不是调用FRR的源代码。然而，如果FRR的zebra守护进程已启动，它会监听内核的Netlink消息，从而在邻居表发生变化时及时接收通知。FRR 的作用在于：同步和维护邻居信息，供上层协议（如 BGP、OSPF、EVPN/VXLAN）使用，并在邻居变化时触发相应的路由更新和封装处理。特别是在VXLAN或EVPN等场景中，zebra会根据邻居信息更新MACFDB表，确保数据包能够正确封装与转发。若未启动FRR，ip neigh add依然生效（因为这是内核行为），但是协议联动功能将无法发挥作用，frr不知道邻居变化，不会通知BGP、OSPF 等模块去响应变化。因此，虽然ip neigh是独立于FRR的命令，但FRR在整个网络协议栈中起到了监听、同步和协同处理的重要角色。
- 0715
    - `zebra_script.c`:中lua_pushzebra_dplane_ctx函数，将ctx中包含的路由/邻居/MAC/规则等结构化信息，压入Lua虚拟机栈中，生成一个结构化的Lua表，以便Lua脚本可以访问这些字段。
    - 查看当前FDB表
        - bridge fdb show dev eth0
    - 测试`ip addr add/del` 
    - 测试macfdb
        ```bash
            # 创建 bridge
            `sudo ip link add br0 type bridge`
            `sudo ip link set br0 up`
            # 创建 VXLAN 接口（VNI=100，绑定到eth0）
            `sudo ip link add vxlan100 type vxlan id 100 dev eth0 dstport 4789 nolearning`
            `sudo ip link set vxlan100 up`
            # 加入 bridge
            `sudo ip link set vxlan100 master br0`
        ```
    > VXLAN 是基于UDP的三层隧道协议，它需要通过一个物理或虚拟的三层接口（如eth0）发送VXLAN封装的UDP报文。所以创建vxlan接口时，必须指定一个底层设备（dev eth0）作为发送隧道封包的出口。
    > VXLAN 的封装过程：通过bridge或L2层发送的以太网帧 -> VXLAN接口接收 -> VXLAN将其封装成UDP包 -> 从eth0发送到远端VTEP。
    **Linux bridge（网桥）**就像一个二层交换机。
	- VXLAN 接口本质上是一个虚拟二层端口，它连接远端VTEP节点。
	- 把vxlan100加入到br0后，内核就会把VXLAN收到的包交给br0来统一做L2转发，就像是：把vxlan100这个网口插到了switch（br0）上。![alt text](image-2.png)
    - 测试命令
        - `sudo bridge fdb add bb:bb:bb:bb:bb:bb dev vxlan100 dst 192.192.192.192 self`
        - `bridge fdb show dev vxlan100`
    - 师兄说不用测试macfb，应为evpn没法测试

- 0716
    - 创建`zlog_debug`日志，修改`frrlab.yml`文件
        - `sudo mkdir -p /tmp`
        - `sudo touch /tmp/frr.log`
        - `sudo chown frr:frr /tmp/frr.log`
    - 修改frrlab的frr.conf文件
        - `log file /tmp/frr.log debugging`
        - `debug zebra events`
    - 进入router1的bash
        - `cat /tmp/frr.log`
    - 但是通过`sudo ip neigh add 192.1.1.1 lladdr aa:aa:aa:aa:aa:aa dev eth0`、`sudo ip neigh del 192.1.1.2 dev eth0`命令，如果是错误的命令，就没法添加进内核，也就不会产生给zebra的netlink消息，所以不会有日志输出；如果是正确的命令，也就不会触发代码中的`zlog_debug`，所以也不会有日志输出？
    - 重新测试了一下`ip addr add/del`命令，能捕捉到日志输出
    - fix bug：内存泄漏
        - 返回之前如果申请了ctx应该`dplane_ctx_fini(&ctx);`
    
- 0717
    - 早上去听了实习生见面大会，操佳敏学姐和另一位学长来传授经验咯，他们回顾了他们从实习生到正式入职的心得体会，并给我了一些建议
    - 怎么顺利生成日志
    - frrlab.yml的frr.config有什么用
        - 写入静态配置！
- 0718 与Donald讨论
    - 我这周把关于neighbor的代码改完了，已经可以在dplane线程中处理neighbor的netlink消息了，主要涉及了两个函数，分别是netlink_ipneigh_change和netlink_macfdb_change，当在dplane将netlink消息转换为ctx后，分别由zebra_neigh_ipaddr_update和zebra_neigh_macfdb_update进行处理。然后使用了ip addr add/del命令测试，使用gdb简单测试，能够正常收到来自内核发送的netlink消息，并且能够正确处理这些消息，就像这张图所示，当我执行了sudo ip neigh add 192.1.1.1 lladdr aa:aa:aa:aa:aa:aa dev eth0这行命令添加一个邻居，并且设置了断点netlink_ipneigh_change和zebra_neigh_ipaddr_update，在gdb中可以打印出ctx中的变量，和我输入的是一致的；同样的，像这幅图所示，我删除了一个邻居。不过我的测试比较简单，我想知道怎么全面的测试一下呢，然后谁会来审阅代码呢，以及如果我想pull request的话，要注意哪些问题？
    - run the topotests
        - https://aliyuque.antfin.com/galadriel.zyq/xg9x2g/bil7z9rg76g10mq8

- 0722 topotests
    - `docker run --init -it --privileged --name frr-ubuntu20 -v /lib/modules:/lib/modules frr:dev2 bash`
    - 如果已经有docker了，就`docker start frr-ubuntu20`然后`docker exec -it frr-ubuntu20 bash进入bash`
    - 进入topotests目录
    - 执行单个用例，进入该测试样例目录
        `sudo pytest xxx.py`
    - ![alt text](image-3.png)
    - 有coredump，与NHRP协议有关，但是我做的改动和NHRP协议感觉是完全没有关系的，不知道为啥，另外几个与EVPN相关

- 0723 debug
    - coredump
        - zebra 给 nhrpd 发了一条接口相关的消息（如 ZEBRA_INTERFACE_ADD），但 nhrpd 的 zclient 模块在解析这条消息时失败（可能是消息内容不完整或格式不符），最终在 STREAM_GETL 读取时触发断言并 abort
        - `zclient_read() -> zclient_interface_add() -> zebra_interface_if_set_value() -> STREAM_GETL -> assert failed`
        - 消息发送方：zebra 守护进程
            - 它向其他守护进程（这里是nhrpd）发送一条接口相关的消息，比如`ZEBRA_INTERFACE_ADD`
        - 消息接收方：nhrpd 守护进程
            - 它通过 zclient 读取这个接口消息，并尝试解析其中的字段。
            - 但在调用`STREAM_GETL`宏（解析字段如 MTU、标志位等）时失败，说明消息内容不完整或格式异常
        - gdb打开.dmp
            - `gdb /usr/lib/frr/nhrpd /tmp/topotests/nhrp_redundancy.test_nhrp_redundancy/nhs1/nhrpd_core-sig_6-pid_***.dmp`
            - `gdb /usr/lib/frr/nhrpd /tmp/topotests/nhrp_topo.test_nhrp_topo/r2/nhrpd_core-sig_6-pid_***.dmp`

            - `less /tmp/topotests/nhrp_topo.test_nhrp_topo/r2/nhrpd.log`
        - 问题定位
            1. crash原因
                - rt_netlink.c 中zsend_neighbor_notify函数
                - 怀疑是link_layer_ipv4这个sockunion没有正确赋值
                - encode和decode的函数
                - `static void zebra_interface_if_set_value(struct stream *s,struct interface *ifp)`
                - `static void zserv_encode_interface(struct stream *s, struct interface *ifp)`
                
                - update
                    - 确定问题是zsend_neighbor_notify函数有问题，注释了就行

            2. evpn相关报错
                - `sudo pytest -s --pdb test_bgp_evpn_vxlan_svd.py`
                - 测试脚本期望的是：在 PE1 上看到 host1 的 MAC 是 remote 类型的，通过 vxlan 口（vxlan0）学习到的
                - 但当前实际：MAC 是通过本地物理接口 PE1-eth0 学到的，而不是 remote 的（即不是通过 EVPN/VXLAN 传过来的）
- 0724 debug
    - 镜像名称：
        - v1debug_after_modify: 将link_layer_ipv4作为结构体参数传递给ctx
        - debug_zsend_neighbor_notify: 注释掉zsend_neighbor_notify之后的代码
        - raw: 官方frr的代码
    - 定位到了问题了
        - cmd赋值有问题，需要加上相应的过滤
        - 为啥有问题还不清楚
        - `grep "xxx" /tmp/topotests/nhrp_topo.test_nhrp_topo/r2/nhrpd.log`
    - 测试样例
        - `sudo pytest -nauto --dist=loadfile`
        - 测试某个样例时，`sudo pytest -s --topology-only`拉起拓扑但不运行测试，`sudo pytest -s --pdb test_bgp_evpn_vxlan_svd.py`可以进入pdb进行调试，也可以通过在运行命令中添加--log-file选项将本用例日志打存在当前目录下

- 0725 y与Donald同步
    - 前几天经过topotest之后，发现了两类问题，一类是nhrpd的crash，另一类是evpn协议相关的，前者是因为zsend_neighbor_notify函数有问题，在传入cmd参数的时候没有进行邻居消息的过滤，导致nhrpd zlcient在解析接口消息时断言失败，这个crash问题我已经解决了；然后剩余的几个evpn问题，都显示是处理evpn消息时，vxlan接口的MAC地址没有正确学习到，可能是我代码写的有问题，我计划使用pdb对照着原始代码进行调试。

- 0728
    - 今天把代码都整理了一下，然后已经push到我的仓库了，下午申请了一下开源贡献，但是专利法务审批一直没下来
    - 在看route相关的代码
        - 消息~~`RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_IPV4_MROUTE`~~
        `RTM_NEWROUTE(24), RTM_DELROUTE(25), RTM_GETROUTE(26)`

        - 对应操作`DPLANE_OP_ROUTE_INSTALL, DPLANE_OP_ROUTE_UPDATE, DPLANE_OP_ROUTE_DELETE`
            - ~~`DPLANE_OP_ROUTE_NOTIFY`~~在`rib_process_dplane_notify`中处理
        - 使用GDB debug 一下
        - 先关函数
            - 处理ctx的函数`rib_process_result`之前新增`zebra_route_dplane_result`
            - 生成ctx的函数`netlink_route_change_read_unicast_internal`
    - Eddie 周报学习

- 0729
    - 当`op==DPLANE_OP_ROUTE_NOTIFY`时，调用`rib_process_dplane_notify`函数，这个函数中会调用`dplane_route_notif_update`会通过`dplane_ctx_set_notif_provider`函数设置`ctx->zd_notif_provider`
    - 现在op没有被赋值`DPLANE_OP_ROUTE_INSTALL, DPLANE_OP_ROUTE_UPDATE, DPLANE_OP_ROUTE_DELETE，DPLANE_OP_ROUTE_NOTIFY`过，也就是现在`rib_process_dplane_results`里面关于route相关的代码不会被执行？
    - `ctx = dplane_ctx_alloc()`在分配内存时，因为XCALLOC会清零，所以调用后，整个struct zebra_dplane_ctx的所有字段一开始都是0（或等效空值）
    ```c
    if (dplane_ctx_get_notif_provider(ctx) == 0) 
		rib_process_result(ctx);
    else
        zebra_route_dplane_result(ctx); // notif_provider在生成时赋值为非0
    ```
    - gdb调试
        - `sudo ip route add 192.168.100.0/24 via 172.20.20.1 dev eth0`
        - `sudo ip route del 192.168.100.0/24 via 172.20.20.1 dev eth0`
        - ~~`watch * (struct zebra_dplane_ctx *) 0x563a8019e0b0`~~

    - 需要保存rtm_family和rtm_flags
    - 需要保存struct rtattr **tb的一些字段
        - tb[RTA_ENCAP]
        - RTA_DATA(tb[RTA_MULTIPATH])
        - PAYLOAD(tb[RTA_MULTIPATH])

    - `struct rtattr **tb_copy;`

- 0730
    - 早上起来，请求已经通过了，今天主要的任务就是提PR，但是CI编译一直过不了，我改了一会儿，考虑到了不同系统的差异，加上了条件编译，下午终于都编译过了，开始了topotest。
    - 今天提了一个PR
        - 感觉里面问题有点多，还得花时间改一下，争取尽快解决

- 0731
    - 继续解决bug
        - 为啥cmd会为0
        - `AddressSanitizer Debian 12 amd64 Part 9 failed`
        - `AddressSanitizer:DEADLYSIGNAL`
            - `ERROR: topo: test failed at "test_ospf6_point_to_multipoint/test_ospfv3_routingTable": OSPFv3 did not converge on r1`
            - `Error detected in ospf_tilfa_topo1.test_ospf_tilfa_topo1`
    - 发现了如何编译为debian的镜像
        - 需要修改为`FROM debian:bookworm`
    - PR规范
        - https://docs.frrouting.org/projects/dev-guide/en/latest/workflow.html#submitting-patches-and-enhancements
    - 参考comment我修改了一天的commit，一直都在force push
    - 只条件编译所必须要的，比如5549原来就在HAVE_NETLINK宏中的，处理消息的两个函数不应该被包裹

- 0801
    - 肩膀不舒服，把系统迁移到了自己的电脑上，因为也只是开发代码，然后上传到github啥的吗，但是环境啥的都变了，然后编译也有点问题

- 0802 
    - 尝试编译修改之后的route代码，然后肯定会有报错的，先修改一下报错吧

- 0806
    - 修改了一些有关neigh的宏和头文件
    - 然后又重新跑了一下CI
    - 现在route相关的内容还没有写好，老是编译出错
        - 需要了解一下头文件的相互包含关系，现在出的错都是什么重复定义或者为声明啥的
    - 月底之前争取先把topotest跑通
        - 争取先编译过
    - 15:30update
        - draft已经编译过了
        - 开始整体topotest
- 0807
    - topotest有5个报错
    - notif修改为了`NOTIF_PROVIDER_KERNEL`
    - 重新跑跑了5个单例，5个都过了
    - 但是跑全部的topotest还是有问题
    - 查一下问题

- 0808
  - topotest 已经过了
  - 应该就是notif当时写的有问题
  - 和Donald讨论了一下，明天他们应该会重新review一下neigh
  代码
  - 

- 转正答辩
    - 需要准备的内容
        - zebra的各个模块的功能和联系


