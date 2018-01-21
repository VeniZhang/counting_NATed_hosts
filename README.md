### 说明文档
#### 题目
* 判断NAT后有多少台主机

#### 说明
* 由于该算法并不能判断一台主机同时有几个进程在传输网络流量，遂在PC上开启了三个进程下载，以此来模拟NAT
* 曾在姚宏伟的帮助下，抓取了seclab实验室NAT的流量，但是分析后效果不理想，主要原因有以下几点，遂选择了第一种方法作为替代。
  * 实验室人员较多，即使统计出结果也无法和实际的联网主机数做比对。
  * 实验室有较多人使用MacOS.MacOS 是BSD系统的一个分支，该系统的ipid是使用伪随机数生成，算法无法从此类流量中得出结果。

#### 环境
 * ubuntu 16.03
 * python 2.7.12
 * tshark 2.2.6
 * matplotlib 2.1.0

#### 使用方法
 * python zhangqiang
    *  默认file、ip 是我自己抓取的包和我主机的ip
    * -i file: 使用tshark 抓包后的
    * -p ip: 主机ip，近使用主机发送的流量，不使用主机接受的流量
    * -h : 帮助
 * 参数设置，该参数是跟据经验进行设置，可在源代码的前几行处进行修改。

#### 结果说明
* 开启了三个进程进行流量传输：
  * ssh：远程登录
  * https: 公网下载
  * ftp:   内网下载
* 从origin图中，很容易看出，上方图形为https，中间较为稀疏的流量室ssh， 下方流量较稠密的是ftp流量
* 右下角有一处流量，这个是https流量，https流量出现这样一上一下的分布，是因为该进程在下载时，使用的使用的ip_id序号达到了最大值（65535）后，从0开始计数。在第三副图中，已经合并。
* 颜色相同的线段为同一进程（主机）。
