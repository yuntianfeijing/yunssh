# yunssh
SSH远程链接小工具

```
yunssh version: yunssh/0.0.0
Usage: yunssh [-u user] [-p passwd] [-h host] [-port port]
	or yunssh user:passwd@host:port 
	or yunssh [-u user] [-h host] [-port port] [-prik privatekey] [-pubkey publickey]  [-p passwd(this is the passwd of privatekey)]
	or yunssh [-c configfile] [-n suboptions]

Options:
  -H string
    	IP Address
  -P int
    	port (default 22)
  -c string
    	configfile path (default "~/.ssh/yunssh.conf")
  -h	this help
  -n string
    	the suboptions of the configfile
  -p string
    	passwd of user(when -prik is not null,it's the passwd of privatekey)
  -prik string
    	the path of privatekey (if the passwd is nil,the passwd is the privatekey's passwd)
  -u string
    	user name,default is root (default "root")
```
