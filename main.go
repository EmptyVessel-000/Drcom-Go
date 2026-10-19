package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type config struct {
	Server             string
	Username           string
	Password           string
	Interface          string
	HostName           string
	HostOS             string
	AuthVersion        string
	KeepAliveVersion   string
	ControlCheckStatus string
	AdapterNum         string
	IPDog              string
}

// hexField 把配置里的十六进制字段解成固定字节数，长度或写法不对就报错。
func hexField(name, s string, n int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != n {
		return nil, fmt.Errorf("%s 需要 %d 字节十六进制，当前为 %q", name, n, s)
	}
	return b, nil
}


func loadConfig(path string) (config, spec, error) {
	var c config
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.WriteFile(path, []byte(`{\n  "Server": "",\n  "Username": "",\n  "Password": "",\n  "Interface": "",\n  "HostName": "",\n  "HostOS": "",\n  "AuthVersion": "",\n  "KeepAliveVersion": "",\n  "ControlCheckStatus": "",\n  "AdapterNum": "",\n  "IPDog": ""\n}\n`), 0600); err != nil {
			return c, spec{}, err
		}
		return c, spec{}, fmt.Errorf("已生成配置模板 %s，请填写后重新启动", path)
	}
	if err != nil {
		return c, spec{}, err
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, spec{}, err
	}

	missing := []string{}
	for _, f := range []struct{ name, value string }{
		{"Server", c.Server},
		{"Username", c.Username},
		{"Password", c.Password},
		{"Interface", c.Interface},
		{"HostName", c.HostName},
		{"HostOS", c.HostOS},
		{"AuthVersion", c.AuthVersion},
		{"KeepAliveVersion", c.KeepAliveVersion},
		{"ControlCheckStatus", c.ControlCheckStatus},
		{"AdapterNum", c.AdapterNum},
		{"IPDog", c.IPDog},
	} {
		if f.value == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return c, spec{}, fmt.Errorf("配置缺少字段: %s", strings.Join(missing, "、"))
	}

	auth, err := hexField("AuthVersion", c.AuthVersion, 2)
	if err != nil {
		return c, spec{}, err
	}
	keep, err := hexField("KeepAliveVersion", c.KeepAliveVersion, 2)
	if err != nil {
		return c, spec{}, err
	}
	ctl, err := hexField("ControlCheckStatus", c.ControlCheckStatus, 1)
	if err != nil {
		return c, spec{}, err
	}
	adapter, err := hexField("AdapterNum", c.AdapterNum, 1)
	if err != nil {
		return c, spec{}, err
	}
	ipdog, err := hexField("IPDog", c.IPDog, 1)
	if err != nil {
		return c, spec{}, err
	}

	sp := spec{
		AuthVersion:        auth,
		KeepAliveVersion:   keep,
		ControlCheckStatus: ctl[0],
		AdapterNum:         adapter[0],
		IPDog:              ipdog[0],
		HostName:           c.HostName,
		HostOS:             c.HostOS,
	}
	return c, sp, nil
}

// defaultConfigPath 按平台给默认配置位置：Unix 走 /etc，Windows 与程序同目录。
func defaultConfigPath() string {
	if runtime.GOOS == "windows" {
		exe, err := os.Executable()
		if err == nil {
			return filepath.Join(filepath.Dir(exe), "config.json")
		}
		return "config.json"
	}
	return "/etc/drcom-go/config.json"
}

// localAddr 只在启动时读一次网卡；登录与重连都用这一份地址。
func localAddr(name string) (net.IP, net.HardwareAddr, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, nil, err
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if v4 := ipn.IP.To4(); v4 != nil {
				return v4, ifi.HardwareAddr, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("接口 %s 上没有 IPv4 地址", name)
}

func dial(cfg config) (*net.UDPConn, error) {
	raddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(cfg.Server, strconv.Itoa(serverPort)))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp4", &net.UDPAddr{Port: serverPort}, raddr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func login(conn *net.UDPConn, cfg config, sp spec, ip net.IP, mac net.HardwareAddr) (*session, error) {
	challenge := challengePacket(uint16(time.Now().UnixNano() % 0xFFFF))
	resp, err := exchange(conn, challenge, 0x02, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("挑战失败: %w", err)
	}
	if len(resp) < 8 {
		return nil, errors.New("挑战应答过短")
	}
	salt := append([]byte{}, resp[4:8]...)

	pkt := loginPacket(sp, cfg.Username, cfg.Password, salt, ip, mac)
	resp, err = exchange(conn, pkt, 0x04, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("登录无成功应答: %w", err)
	}
	if len(resp) < 39 {
		return nil, errors.New("登录应答过短")
	}
	return &session{salt: salt, loginTail: append([]byte{}, resp[23:39]...), tail4: make([]byte, 4), seq: 0x0b}, nil
}

// round 跑一轮保活：42 字节首保活用固定的登录尾，再发 40 字节的类型 1 与类型 3，
// 每次都把应答第 16..20 字节作为下一次的尾。
func round(conn *net.UDPConn, cfg config, sp spec, s *session, ip net.IP) error {
	resp, err := exchange(conn, keepAlive1Packet(cfg.Password, s.salt, s.loginTail), 0x07, 10*time.Second)
	if err != nil {
		return err
	}
	if len(resp) >= 20 {
		s.tail4 = append([]byte{}, resp[16:20]...)
	}
	s.seq++
	resp, err = exchange(conn, keepAlivePacket(sp, s.seq, 1, s.tail4, ip), 0x07, 10*time.Second)
	if err != nil {
		return err
	}
	if len(resp) >= 20 {
		s.tail4 = append([]byte{}, resp[16:20]...)
	}
	s.seq++
	resp, err = exchange(conn, keepAlivePacket(sp, s.seq, 3, s.tail4, ip), 0x07, 10*time.Second)
	if err != nil {
		return err
	}
	if len(resp) >= 20 {
		s.tail4 = append([]byte{}, resp[16:20]...)
	}
	return nil
}

func main() {
	cfgPath := flag.String("config", defaultConfigPath(), "配置文件路径")
	once := flag.Bool("once", false, "登录并跑一轮保活后退出")
	flag.Parse()

	cfg, sp, err := loadConfig(*cfgPath)
	if err != nil {
		log.Printf("读取配置失败: %v", err)
		os.Exit(1)
	}

	backoff := []time.Duration{5 * time.Second, 15 * time.Second, 60 * time.Second, 300 * time.Second}
	step := 0
	// 失败经 noteFailure，等待期内只输出一次。
	// 前缀只写“哪一步失败了”，原因由 %v 带入，不与错误文案重复。
	reported := false
	noteFailure := func(format string, a ...any) {
		if reported {
			return
		}
		reported = true
		log.Printf(format, a...)
	}

	// 配置与网卡地址只在启动时取一次，之后重连沿用同一份。
	ip, mac, err := localAddr(cfg.Interface)
	for err != nil {
		noteFailure("网卡 %s 暂不可用: %v，等待网络恢复", cfg.Interface, err)
		time.Sleep(20 * time.Second)
		ip, mac, err = localAddr(cfg.Interface)
	}

	// 套接字也只在启动时建一次；只有收发系统调用报错时才重建。
	reported = false // 网卡已就绪，套接字失败要能单独报一次。
	var conn *net.UDPConn
	openSocket := func() {
		for {
			c, err := dial(cfg)
			if err == nil {
				conn = c
				return
			}
			noteFailure("打开套接字失败: %v，等待网络恢复", err)
			time.Sleep(20 * time.Second)
		}
	}
	openSocket()
	reported = false // 启动准备结束，登录阶段的失败要能单独报一次。

	for {
		s, err := login(conn, cfg, sp, ip, mac)
		if err != nil {
			if errors.Is(err, errSocketIO) {
				noteFailure("套接字异常: %v，重建后重新登录", err)
				conn.Close()
				openSocket()
				continue
			}
			// 两类失败只差等待多久：无应答时固定 20 秒，协议错误按退避阶梯。
			var wait time.Duration
			if errors.Is(err, errNoReply) {
				wait = 20 * time.Second
			} else {
				wait = backoff[step]
				if step < len(backoff)-1 {
					step++
				}
			}
			noteFailure("登录失败: %v，%d 秒后重试", err, int(wait/time.Second))
			time.Sleep(wait)
			continue
		}
		step = 0

		// 登录成功只证明认证服务器应答了，保活跑通一轮才说明链路真的可用。
		// 内层第一轮成功即记一次上线，之后每轮静默。
		first := true
		for {
			if err := round(conn, cfg, sp, s, ip); err != nil {
				if errors.Is(err, errSocketIO) {
					noteFailure("套接字异常: %v，重建后重新登录", err)
					conn.Close()
					openSocket()
					break
				}
				noteFailure("保活中断: %v，重新登录", err)
				break
			}
			if first {
				first = false
				log.Printf("上线成功: 账号=%s 地址=%s 网卡=%s 服务器=%s", cfg.Username, ip, mac, cfg.Server)
			}
			if *once {
				conn.Close()
				return
			}
			time.Sleep(20 * time.Second)
		}
	}
}
