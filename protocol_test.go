package main

import (
	"encoding/hex"
	"net"
	"strings"
	"testing"
)

const golden = "03010020bb7f9da80018f9d09205b9bc558f8e4d3230323230303030303030300000000000000000000000000000000000000000000000002002b97fc3b800191a45af872acd9659dce0022d8172434c01cb0071090000000000000000000000000346661a560bc7a001000000006573742d70630000000000000000000000000000000000000000000000000000727272720aff00c5080808080000000000000000940000000500000001000000280a00000200000038303839440000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00020ca01c536c000002005e1000010000c266"

func TestGoldenLogin(t *testing.T) {
	sp := spec{
		AuthVersion:        []byte{0x0a, 0x00},
		KeepAliveVersion:   []byte{0xdc, 0x02},
		ControlCheckStatus: 0x20,
		AdapterNum:         0x07,
		IPDog:              0x01,
		HostName:           "est-pc",
		HostOS:             "8089D",
	}
	salt, _ := hex.DecodeString("99be9f00")
	mac, _ := net.ParseMAC("02:00:5e:10:00:01")
	got := loginPacket(sp, "202200000000", "example-pass", salt, net.ParseIP("203.0.113.9").To4(), mac)
	g := strings.ToLower(hex.EncodeToString(got))
	if g == golden {
		t.Logf("登录包逐字节一致，长度 %d", len(got))
		return
	}
	for i := 0; i < len(g) && i < len(golden); i++ {
		if g[i] != golden[i] {
			t.Fatalf("首个差异在字节 %d：得到 %s，应为 %s", i/2, g[i-2:i+6], golden[i-2:i+6])
		}
	}
	t.Fatalf("长度不一致：得到 %d 字节，期望 %d", len(got), len(golden)/2)
}
func TestPacketLengths(t *testing.T) {
	sp := spec{AuthVersion: []byte{0x0a, 0x00}, KeepAliveVersion: []byte{0xdc, 0x02}, IPDog: 0x01, HostName: "Arch", HostOS: "8089D"}
	ip := net.ParseIP("10.30.11.182").To4()
	if n := len(challengePacket(1)); n != 20 {
		t.Fatalf("挑战包长度 %d，应为 20", n)
	}
	if n := len(keepAlive1Packet("x", []byte{1, 2, 3, 4}, make([]byte, 16))); n != 42 {
		t.Fatalf("首保活长度 %d，应为 42", n)
	}
	if n := len(keepAlivePacket(sp, 1, 1, make([]byte, 4), ip)); n != 40 {
		t.Fatalf("保活类型1长度 %d，应为 40", n)
	}
	if n := len(keepAlivePacket(sp, 1, 3, make([]byte, 4), ip)); n != 40 {
		t.Fatalf("保活类型3长度 %d，应为 40", n)
	}
}
