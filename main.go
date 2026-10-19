package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
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

func hexByte(s string, fallback byte) byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 1 {
		return fallback
	}
	return b[0]
}

func loadConfig(path string) (config, spec, error) {
	var c config
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, spec{}, err
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, spec{}, err
	}
	if c.Interface == "" {
		c.Interface = "enp1s0f0"
	}
	if c.HostName == "" {
		c.HostName = "Arch"
	}
	if c.HostOS == "" {
		c.HostOS = "8089D"
	}
	auth, err := hex.DecodeString(c.AuthVersion)
	if err != nil || len(auth) != 2 {
		auth = []byte{0x0a, 0x00}
	}
	keep, err := hex.DecodeString(c.KeepAliveVersion)
	if err != nil || len(keep) != 2 {
		keep = []byte{0xdc, 0x02}
	}
	sp := spec{
		AuthVersion:        auth,
		KeepAliveVersion:   keep,
		ControlCheckStatus: hexByte(c.ControlCheckStatus, 0x20),
		AdapterNum:         hexByte(c.AdapterNum, 0x07),
		IPDog:              hexByte(c.IPDog, 0x01),
		HostName:           c.HostName,
		HostOS:             c.HostOS,
	}
	return c, sp, nil
}

// localAddr 每次登录前重新读网卡，地址变了就用新的。
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
	raddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(cfg.Server, fmt.Sprint(serverPort)))
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
		return nil, fmt.Errorf("挑战无应答: %w", err)
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

// round 跑一轮保活：42 字节首保活加一对 40 字节往返，然后等 20 秒。
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
	cfgPath := flag.String("config", "/etc/drcom/config.json", "配置文件路径")
	once := flag.Bool("once", false, "登录并跑一轮保活后退出")
	flag.Parse()

	cfg, sp, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("读取配置失败: %v", err)
	}

	backoff := []time.Duration{5 * time.Second, 15 * time.Second, 60 * time.Second, 300 * time.Second}
	step := 0
	for {
		ip, mac, err := localAddr(cfg.Interface)
		if err != nil {
			log.Printf("取网卡地址失败: %v", err)
			time.Sleep(backoff[step])
			continue
		}
		conn, err := dial(cfg)
		if err != nil {
			log.Printf("打开套接字失败: %v", err)
			time.Sleep(backoff[step])
			continue
		}
		s, err := login(conn, cfg, sp, ip, mac)
		if err != nil {
			log.Printf("登录失败(%s): %v", ip, err)
			conn.Close()
			if step < len(backoff)-1 {
				step++
			}
			time.Sleep(backoff[step])
			continue
		}
		log.Printf("登录成功 账号=%s 地址=%s 网卡=%s 服务器=%s", cfg.Username, ip, mac, cfg.Server)
		step = 0

		for {
			if err := round(conn, cfg, sp, s, ip); err != nil {
				log.Printf("保活中断: %v，重新登录", err)
				break
			}
			if *once {
				log.Printf("单轮完成，退出")
				conn.Close()
				return
			}
			time.Sleep(20 * time.Second)
		}
		conn.Close()
	}
}
