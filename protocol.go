package main

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const serverPort = 61440

// spec 是所有静态协议字段，全部来自 drcom-generic 的校区条目与实测报文。
type spec struct {
	AuthVersion        []byte
	KeepAliveVersion   []byte
	ControlCheckStatus byte
	AdapterNum         byte
	IPDog              byte
	HostName           string
	HostOS             string
}

func sum(parts ...[]byte) []byte {
	h := md5.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func padTo(s string, n int) []byte {
	out := make([]byte, n)
	copy(out, s)
	return out
}

// checksum 是登录包尾部的 32 位校验。服务端按旧实现的字节分组校验，
// 旧代码用正则取四字节组，而正则的点号不匹配 0x0a，所以遇到 0x0a 会断开重新成组；
// 这里照此实现，否则校验值与原脚本不一致。
func checksum(b []byte) []byte {
	ret := uint32(1234)
	start := 0
	for i := 0; i <= len(b); i++ {
		if i == len(b) || b[i] == 0x0a {
			for j := start; j+4 <= i; j += 4 {
				ret ^= binary.LittleEndian.Uint32(b[j:])
			}
			start = i + 1
		}
	}
	ret = 1968 * ret
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, ret)
	return out
}

// challengePacket 是 20 字节挑战请求：01 02 + 随机数 + 09 + 15 个 0。
func challengePacket(random uint16) []byte {
	b := make([]byte, 20)
	b[0], b[1], b[4] = 0x01, 0x02, 0x09
	binary.LittleEndian.PutUint16(b[2:], random)
	return b
}

// loginPacket 构造 330 字节登录请求。salt 取自挑战应答的 4..8 字节。
func loginPacket(sp spec, user, pass string, salt []byte, ip net.IP, mac net.HardwareAddr) []byte {
	data := []byte{0x03, 0x01, 0x00, byte(len(user) + 20)}
	data = append(data, sum([]byte{0x03, 0x01}, salt, []byte(pass))...)
	data = append(data, padTo(user, 36)...)
	data = append(data, 0x20, 0x02)

	six := make([]byte, 6)
	copy(six, data[4:10])
	x := binary.BigEndian.Uint64(append([]byte{0, 0}, six...)) ^ macUint(mac)
	for i := 0; i < 6; i++ {
		data = append(data, byte(x>>(uint(5-i)*8)))
	}

	data = append(data, sum([]byte{0x01}, []byte(pass), salt, make([]byte, 4))...)
	data = append(data, 0x01)
	data = append(data, ip.To4()...)
	data = append(data, make([]byte, 12)...)
	data = append(data, sum(data, []byte{0x14, 0x00, 0x07, 0x0b})[:8]...)
	data = append(data, sp.IPDog)
	data = append(data, make([]byte, 4)...)
	data = append(data, padTo(sp.HostName, 32)...)
	data = append(data, 0x72, 0x72, 0x72, 0x72)
	data = append(data, 0x0a, 0xff, 0x00, 0xc5)
	data = append(data, 0x08, 0x08, 0x08, 0x08)
	data = append(data, make([]byte, 8)...)
	data = append(data, 0x94, 0x00, 0x00, 0x00)
	data = append(data, 0x05, 0x00, 0x00, 0x00)
	data = append(data, 0x01, 0x00, 0x00, 0x00)
	data = append(data, 0x28, 0x0a, 0x00, 0x00)
	data = append(data, 0x02, 0x00, 0x00, 0x00)
	data = append(data, padTo(sp.HostOS, 32)...)
	data = append(data, make([]byte, 96)...)
	data = append(data, sp.AuthVersion...)
	data = append(data, 0x02, 0x0c)

	tail := append([]byte{}, data...)
	tail = append(tail, 0x01, 0x26, 0x07, 0x11, 0x00, 0x00)
	tail = append(tail, mac...)
	data = append(data, checksum(tail)...)
	data = append(data, 0x00, 0x00)
	data = append(data, mac...)
	data = append(data, 0x00, 0x00, 0xc2, 0x66)
	return data
}

// keepAlive1Packet 是 42 字节首保活：ff + 摘要 + 000000 + 16 字节会话尾 + 时间 + 4 个 0。
func keepAlive1Packet(pass string, salt, sessionTail []byte) []byte {
	b := []byte{0xff}
	b = append(b, sum([]byte{0x03, 0x01}, salt, []byte(pass))...)
	b = append(b, 0x00, 0x00, 0x00)
	b = append(b, sessionTail...)
	b = binary.BigEndian.AppendUint16(b, uint16(time.Now().Unix()%0xFFFF))
	b = append(b, 0x00, 0x00, 0x00, 0x00)
	return b
}

// keepAlivePacket 是 40 字节保活，typ=1 与 typ=3 尾部不同。
func keepAlivePacket(sp spec, seq byte, typ byte, tail []byte, ip net.IP) []byte {
	b := []byte{0x07, seq, 0x28, 0x00, 0x0b, typ}
	b = append(b, sp.KeepAliveVersion...)
	b = append(b, 0x2f, 0x12)
	b = append(b, make([]byte, 6)...)
	b = append(b, tail...)
	b = append(b, make([]byte, 4)...)
	if typ == 3 {
		b = append(b, make([]byte, 4)...)
		b = append(b, ip.To4()...)
		b = append(b, make([]byte, 8)...)
	} else {
		b = append(b, make([]byte, 16)...)
	}
	return b
}

func macUint(mac net.HardwareAddr) uint64 {
	var x uint64
	for _, c := range mac {
		x = x<<8 | uint64(c)
	}
	return x
}

// errNoReply 表示认证服务器没有任何回应：多半是不在校园网内，也可能链路未通。
// 这种情况安静等待网络恢复即可，由调用方决定等待的时长。
var errNoReply = errors.New("服务器无应答")

// errSocketIO 表示套接字本身收发失败（例如没有到服务器的路由），需要重建套接字。
var errSocketIO = errors.New("套接字收发失败")

// session 持有登录后的会话尾与序号，掉线即整体丢弃重新登录。
// loginTail 是登录应答里的 16 字节尾，首保活每次都用它；
// tail4 是保活应答第 16..20 字节，只用于 40 字节保活包。
type session struct {
	salt      []byte
	loginTail []byte
	tail4     []byte
	seq       byte
}

// exchange 发一个包并等待首字节符合 want 的应答。
func exchange(conn *net.UDPConn, packet []byte, want byte, timeout time.Duration) ([]byte, error) {
	if _, err := conn.Write(packet); err != nil {
		return nil, fmt.Errorf("%w: %w", errSocketIO, err)
	}
	buf := make([]byte, 2048)
	deadline := time.Now().Add(timeout)
	for {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return nil, fmt.Errorf("%w: %w", errSocketIO, err)
		}
		n, err := conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errNoReply, err)
		}
		if n > 0 && buf[0] == want {
			out := make([]byte, n)
			copy(out, buf[:n])
			return out, nil
		}
		if time.Now().After(deadline) {
			return nil, errNoReply
		}
	}
}
