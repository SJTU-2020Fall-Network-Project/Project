## install libpcap in linux

> wget http://www.tcpdump.org/release/libpcap-1.9.1.tar.gz

> tar zxvf libpacp-1.9.1

> cd libpacp-1.9.1

如果缺依赖，比如flex,bison,就apt install

> ./configure 

>make 
>make install

将工程文件git clone 下来，注意之后我们需要用git来管理代码，所以需要去学习一下怎么使用git

> git clone https://github.com/SJTU-2020Fall-Network-Project/Project.git

cd 到test文件夹

将libpcap库加入到环境变量中

> vim ~/.bashrc

在开头插入

> export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib

然后返回到test文件夹
> make

> ./hello

会输出你的网卡接口名字

> ens33