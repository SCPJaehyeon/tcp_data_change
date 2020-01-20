## tcp_data_change
BOB 8th - Network(3rd stage)



#### Usage

```shell
iptables -A INPUT -j NFQUEUE
iptables -A OUTPUT -j NFQUEUE
./tcp_data_change [From_String] [To_String]
```



##### Picture > ./tcp_data_change hello byebye

<img width="178" alt="1" src="https://user-images.githubusercontent.com/50411472/72729462-90660f00-3bd2-11ea-8024-fc32f7bb3119.PNG">

<img width="174" alt="2" src="https://user-images.githubusercontent.com/50411472/72729463-90fea580-3bd2-11ea-81a2-6edb0a7301d5.PNG">
