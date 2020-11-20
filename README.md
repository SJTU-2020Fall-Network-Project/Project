# Introduction
+ 被动推测TCP flavors（拥塞控制算法）

# Motivation
+ 深入学习TCP
+ 项目本身有趣，被动流量监控，可以进一步了解不同客户机详细信息。。。

# Background Knowledge
+ TCP 拥塞控制
+ Reno、Cubic、BBR等各种类型地拥塞控制算法
+ 不同TCP flavors有不同的窗口骤降的XX（丢包【Reno】/延迟【BBR】），拥塞避免时对RTT的依赖（【Reno】/【Cubic】），拥塞避免窗口改变（累加【Reno】/二分【Cubic】），通过这些不同点辨别【wjh的ns-3图】

# Solution Space
+ Libpcap库，tcpdump或者wireshark可以被动地抓取包
+ 展示CUBIC和RENO图，表示不同拥塞避免算法存在差异
+ 论文 *Inferring TCP Connection Characteristics Through Passive Measurements.* 和 *Measurement and classification of out-of-sequence packets in a tier-1 IP backbone.* 分别描述了用自动机推断和分类out-of-order包
