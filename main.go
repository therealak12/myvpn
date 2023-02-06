package main

import (
	"bytes"
	"errors"
	"fmt"
	myvpn "github.com/therealak12/myvpn/internal"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"unsafe"
)

var (
	stopMarker = []byte{2, 2, 2, 2, 2, 2, 2, 2}
)

// Closing tun/tap devices doesn't interrupt blocking Read (in Linux/Windows).
// sendStopMarker is a dummy packet used to notify threads blocking on Read.
// We just quit processing in case such a packet is read from the tun device.
func sendStopMarker(src, dst string) {
	l, _ := net.ResolveUDPAddr("udp", src+":2222")
	r, _ := net.ResolveUDPAddr("udp", dst+":2222")
	conn, err := net.DialUDP("udp", l, r)
	if err != nil {
		log.Printf("fail to send stopmarker: %s", err)
		return
	}
	defer conn.Close()
	conn.Write(stopMarker)
}

func isStopMarker(pkt []byte, src, dst net.IP) bool {
	n := len(pkt)
	// at least should be 20(ip) + 8(udp) + 8(stopmarker)
	if n < 20+8+8 {
		return false
	}
	return pkt[0]&0xf0 == 0x40 && pkt[9] == 0x11 && src.Equal(pkt[12:16]) &&
		dst.Equal(pkt[16:20]) && bytes.Compare(pkt[n-8:n], stopMarker) == 0
}

type TunDev struct {
	name   string
	addr   string
	addrIP net.IP
	gw     string
	gwIP   net.IP
	marker []byte
	f      *os.File
}

func (td *TunDev) Read(data []byte) (int, error) {
	n, err := td.f.Read(data)
	if err == nil && isStopMarker(data[:n], td.addrIP, td.gwIP) {
		return 0, errors.New("received stop marker")
	}
	return n, err
}

func (td *TunDev) Write(data []byte) (int, error) {
	return td.f.Write(data)
}
func (td *TunDev) Close() error {
	log.Printf("send stop marker")
	sendStopMarker(td.addr, td.gw)
	return td.f.Close()
}

// TODO: use go-packet
func createTunDevice() (io.ReadWriteCloser, error) {
	ifName := "myvpn.tun0"
	ifAddr := "10.0.0.2"
	ifGW := "10.0.0.1"

	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	type ifReq struct {
		Name  [syscall.IFNAMSIZ]byte
		Flags uint16
		pad   [0x28 - syscall.IFNAMSIZ - 2]byte
	}
	var req ifReq
	copy(req.Name[:], ifName)
	req.Flags = syscall.IFF_TUN | syscall.IFF_NO_PI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return nil, fmt.Errorf("ioctl syscall failed with errno: %d", errno)
	}

	// Set nonblock flag to false so that the code block waiting for data on the tun interface.
	// If we set nonblock to true, the code would exit with error if it tries to read from
	// the tun interface while there's no data on it.
	// https://kernel.org/doc/Documentation/filesystems/mandatory-locking.txt
	if err := syscall.SetNonblock(int(file.Fd()), false); err != nil {
		return nil, fmt.Errorf("failed to SetNonblock: %s", err.Error())
	}

	cmd := exec.Command("ip", "link", "set", "dev", ifName, "mtu", "1500")
	err = cmd.Run()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to set device mtu, err: %s", err.Error())
	}

	cmd = exec.Command("ip", "addr", "add", fmt.Sprintf("%s/24", ifAddr), "dev", ifName)
	err = cmd.Run()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to set device addr, err: %s", err.Error())
	}

	cmd = exec.Command("ip", "link", "set", "dev", ifName, "up")
	err = cmd.Run()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to set device up, err: %s", err.Error())
	}

	return &TunDev{
		f:      file,
		addr:   ifAddr,
		addrIP: net.ParseIP(ifAddr).To4(),
		gw:     ifGW,
		gwIP:   net.ParseIP(ifGW).To4(),
		marker: nil,
	}, nil
}

func main() {
	log.SetFlags(log.Lshortfile)

	tunDev, err := createTunDevice()
	if err != nil {
		log.Printf("failed to create tun device, err: %v\n", err)
		return
	}
	tun := myvpn.NewTun(tunDev)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		<-signalCh
		tun.Stop()
	}()

	tun.Run()
}
