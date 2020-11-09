# Inferring TCP flavor throught passive measurement 

# conclusion
这篇文章提出一种判断TCP flavor的方法： 通过估计cwnd(congestion window)来推断是哪一种TCP flavor(e.g. Tahoe,Reno,New Reno)，因为每一种不同的flavor会对cwnd有不同的操作

# tracking the cwnd
这篇论文提出估计cwnd的方法是：
* 模拟sender的状态，对于每一种flavor，都构建它的有限状态机器（TSM)
* 对于测量点测量到的reciver-to-sender的ACK，根据flavor的不同来确定如何更新每一个TSM的状态（因为其中有一个flavor TSM是和sender的TSM一样的state transition pattern)
* 如何确定是哪一个flavor? 对于模拟的每一个TSM，它都会模拟sender的全部状态（其中就有cwnd），然后它会根据真实检测到的packet，来判断它是否会是当前窗口所能发出的包（size(packet)-size(header)<=cwnd，maybe),如果上述不等式不成立，则给这一个flavor TSM记一次violation。最后就根据哪个TSM的violation最小来确定是哪一个flavor

# RTT的估计
RTT-round-trip time，是一个包从发送到收到它的ACK所用的时间，可以看做是往返时间 \
估计方法：d1+d2 (论文里面有图)

# Evaluation
1. simulation
   * use ns(network simulation)
   * set bottleneck,network topology,data flows ,etc.
   * compare RTT from methodology and computed by the ns,the same as cwnd

2. Experiments over the network
   * 真实网络连接，两台主机，建立200个TCP连接
   * dummynet bridge 模拟瓶颈

3. 大型试验

# 误差的来源
## 低估cwnd
原因：当测量点（MP）检测到了三个重复ACK，但是这三个ACK没有到达sender。
这种情况下，MP就会采用快速重传与减小cwnd和ssthresh。但是由于这三个ACK没有到达sender，sender会超时，然后重传。这时MP会检测到sender发的超时，然后再度减小ssthresh。这样最终测量点估计的swnd就比sender小

## 高估cwnd
...
