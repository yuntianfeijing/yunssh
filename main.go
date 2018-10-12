package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"github.com/BurntSushi/toml"
	"strings"
	"strconv"
	"os/user"
)

type ConnectParam struct {
	Port       int
	User       string
	Passwd     string
	Host       string
	PrivateKey string
}
var userParam = ConnectParam {
	Port:22,
	User:"root",
}
var (
	h bool
	conf string
	name string
)

func usage() {
	fmt.Fprintf(os.Stderr, `yunssh version: yunssh/0.0.0
Usage: yunssh [-u user] [-p passwd] [-h host] [-port port]
	or yunssh user:passwd@host:port 
	or yunssh [-u user] [-h host] [-port port] [-prik privatekey] [-pubkey publickey]  [-p passwd(this is the passwd of privatekey)]
	or yunssh [-c configfile] [-n suboptions]

Options:
`)
	flag.PrintDefaults()
}
func init(){
	user, err := user.Current()
	if nil != err {
		panic(err)
	}
	flag.BoolVar(&h, "h", false, "this help")
	flag.StringVar(&userParam.User,"u", "root", "user name,default is root")
	flag.StringVar(&userParam.Passwd,"p", "", "passwd of user(when -prik is not null,it's the passwd of privatekey)")
	flag.IntVar(&userParam.Port,"P", 22, "port")
	flag.StringVar(&userParam.Host,"H", "", "IP Address")
	flag.StringVar(&userParam.PrivateKey,"prik", "", "the path of privatekey (if the passwd is nil,the passwd is the privatekey's passwd)")
	flag.StringVar(&conf,"c", user.HomeDir + "/.ssh/yunssh.conf", "configfile path")
	flag.StringVar(&name,"n", "", "the suboptions of the configfile")
	flag.Usage = usage
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func useConfig(filePath string,Suboptions string,param *ConnectParam) error {
	var confMap = make(map[string]interface{})
	confExists, err := PathExists(filePath)
	if err != nil {
		return fmt.Errorf("error: config file %s status abnormal", filePath)
	}
	if !confExists {
		return fmt.Errorf("error: config file %s is not exist", filePath)
	}
	if _, err := toml.DecodeFile(filePath, &confMap); err != nil {
		return err
	}
	if subMap,ok := confMap[Suboptions]; !ok {
		return fmt.Errorf("error: config file %s have no Suboptions %s",filePath,Suboptions)
	}else{
		if subUser,okValue := subMap.(map[string]interface{})["user"];okValue {
			param.User = subUser.(string)
			if param.User == "" {
				return fmt.Errorf("error: user is nill in file:%s Suboptions:",filePath,Suboptions)
			}
		}
		if subHost,okValue := subMap.(map[string]interface{})["host"];okValue {
			param.Host = subHost.(string)
			if param.Host == "" {
				return fmt.Errorf("error: host is nill in file:%s Suboptions:",filePath,Suboptions)
			}
		}
		if subPasswd,okValue := subMap.(map[string]interface{})["passwd"];okValue {
			param.Passwd = subPasswd.(string)
		}
		if subPort,okValue := subMap.(map[string]interface{})["port"];okValue {
			param.Port =  int(subPort.(int64))
		}
		if subPrivate,okValue := subMap.(map[string]interface{})["privatekey"];okValue {
			param.PrivateKey = subPrivate.(string)
		}
	}
	return nil
}

func useSshFormat(cmdstring string,param *ConnectParam) error  {
	infolist := strings.Split(cmdstring,"@")
	if len(infolist) != 2 {
		return fmt.Errorf("Invalid fomat: %s \neg: user:passwd@host:port",cmdstring)
	}
	userInfo := strings.Split(infolist[0],":")
	addrInfo := strings.Split(infolist[1],":")
	if len(userInfo) > 2 || len(addrInfo) > 2 {
		return fmt.Errorf("Invalid fomat: %s \neg: user:passwd@host:port",cmdstring)
	}
	param.User = userInfo[0]
	if len(userInfo) == 2 {
		param.Passwd = userInfo[1]
	}
	param.Host = addrInfo[0]
	if len(addrInfo) == 2 {
		port,errPort := strconv.Atoi(addrInfo[1])
		if errPort != nil {
			return fmt.Errorf("Invalid fomat: %s \neg: user:passwd@host:port",cmdstring)
		}
		param.Port = port
	}
	return nil
}
func checkParam(param *ConnectParam)error  {
	if param.Host == "" {
		return fmt.Errorf("error: host is nill")
	}
	if param.Port == 0 {
		return fmt.Errorf("error: port is not set")
	}
	if param.PrivateKey == "" && param.Passwd == "" {
		fmt.Print("Please input your password: ")
		fmt.Scanln(&param.Passwd)
	}
	return nil
}


func main() {
	flag.Parse()
	if h {
		flag.Usage()
		return
	}
	if name != "" {
		if errParam := useConfig(conf,name,&userParam); errParam != nil {
			fmt.Printf("\n%s\n\n",errParam.Error())
			flag.Usage()
			return
		}
	}
	if len(os.Args) == 2 {
		if errParam := useSshFormat(os.Args[1],&userParam);errParam != nil{
			fmt.Printf("\n%s\n\n",errParam.Error())
			return
		}
	}
	if checkErr := checkParam(&userParam);checkErr != nil {
		fmt.Printf("\n%s\n\n",checkErr.Error())
		flag.Usage()
		return
	}
	if errConnect := connect(userParam, nil);errConnect != nil {
		log.Panic(errConnect)
	}
	return
}

func connect(param ConnectParam, cipherList []string) error {
	var (
		auth         []ssh.AuthMethod
		addr         string
		clientConfig *ssh.ClientConfig
		client       *ssh.Client
		config       ssh.Config
		session      *ssh.Session
		err          error
	)
	// get auth method
	auth = make([]ssh.AuthMethod, 0)
	if param.PrivateKey == "" {
		auth = append(auth, ssh.Password(param.Passwd))
	} else {
		var signer ssh.Signer
		pemBytes, err := ioutil.ReadFile(param.PrivateKey)
		if err != nil {
			return fmt.Errorf("error: open privatekey file %s error.[%s]", param.PrivateKey, err.Error())
		}
		if param.Passwd == "" {
			signer, err = ssh.ParsePrivateKey(pemBytes)
		} else {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(param.Passwd))
		}
		if err != nil {
			return fmt.Errorf("error: parse privatekey file %s error.[%s]", param.PrivateKey, err.Error())
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}

	if len(cipherList) == 0 {
		config = ssh.Config{
			Ciphers: []string{"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "arcfour256", "arcfour128", "aes128-cbc", "3des-cbc", "aes192-cbc", "aes256-cbc"},
		}
	} else {
		config = ssh.Config{
			Ciphers: cipherList,
		}
	}

	clientConfig = &ssh.ClientConfig{
		User:    param.User,
		Auth:    auth,
		Timeout: 30 * time.Second,
		Config:  config,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	addr = fmt.Sprintf("%s:%d", param.Host, param.Port)
	// connet to ssh
	if client, err = ssh.Dial("tcp", addr, clientConfig); err != nil {
		return fmt.Errorf("error: connect %s:%d error.[%s]", addr, param.Port, err.Error())
	}
	defer client.Close()

	// create session
	if session, err = client.NewSession(); err != nil {
		return fmt.Errorf("error: client NewSession error.[%s]", err.Error())
	}
	defer session.Close()

	fd := int(os.Stdin.Fd())
	oldState, err := terminal.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("error: terminal MakeRaw error.[%s]", err.Error())
	}
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	termWidth, termHeight, err := terminal.GetSize(fd)
	if err != nil {
		return fmt.Errorf("error: terminal GetSize error.[%s]", err.Error())
	}
	defer terminal.Restore(fd, oldState)

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	if err = session.RequestPty("xterm-256color", termHeight, termWidth, modes); err != nil {
		return fmt.Errorf("error: session RequestPty error.[%s]", err.Error())
	}
	// monitor for sigwinch
	go monWinCh(session, int(os.Stdin.Fd()))

	err = session.Shell()
	if err != nil {
		return fmt.Errorf("error: session Shell error.[%s]", err.Error())
	}

	err = session.Wait()
	if err != nil {
		return fmt.Errorf("error: session Wait error.[%s]", err.Error())
	}
	return nil
}

func termSize(fd int) []byte {
	size := make([]byte, 16)

	termWidth, termHeight, err := terminal.GetSize(fd)
	if err != nil {
		binary.BigEndian.PutUint32(size, uint32(80))
		binary.BigEndian.PutUint32(size[4:], uint32(24))
		return size
	}

	binary.BigEndian.PutUint32(size, uint32(termWidth))
	binary.BigEndian.PutUint32(size[4:], uint32(termHeight))

	return size
}

func monWinCh(session *ssh.Session, fd int) {
	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGWINCH)
	defer signal.Stop(sigs)

	// resize the tty if any signals received
	for range sigs {
		session.SendRequest("window-change", false, termSize(fd))
	}
}