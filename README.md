# yunssh
SSH远程链接小工具

 * 不依赖本地ssh安装，终端实现类似ssh的登录
 * 自动适应终端大小
 * 可从配置文件指定启动项
 * 可以指定秘钥项（支持加密秘钥解析）

```
[root@root:~$]: yunssh -hV
yunssh version: yunssh/0.0.0
Usage: yunssh [-u user] [-p passwd] [-h host] [-port port]
	or yunssh user:passwd@host:port 
	or yunssh [-u user] [-h host] [-port port] [-prik privatekey] [-p passwd(this is the passwd of privatekey)]
	or yunssh [-c configfile] [-n suboptions]

Options:
  -h	this help
  -u string
    	user name,default is root (default "root")
  -p string
    	passwd of user(when -prik is not null,it's the passwd of privatekey)
  -H string
    	IP Address
  -P int
    	port (default 22)
  -prik string
    	the path of privatekey (if the passwd is nil,the passwd is the privatekey's passwd)
  -c string
    	configfile path (default "~/.ssh/yunssh.conf")
  -n string
    	the suboptions of the configfile
```

