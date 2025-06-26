package proxy

import (
	"fmt"
	"io"
	"net"
	"strings"
)

func handleConnect(req *SOCKS5Request) error {
	destConn, err := net.Dial("tcp", req.DestAddr.ToString())
	if err != nil {
		msg := err.Error()
		var respCode byte

		if strings.Contains(msg, "refused") {
			respCode = ReplyConnectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			respCode = ReplyNetworkUnreachable
		} else {
			respCode = ReplyHostUnreachable
		}

		if err := sendSOCKS5Response(req.ClientConn, &SOCKS5Response{
			Request:  req,
			RespCode: respCode,
		}); err != nil {
			return fmt.Errorf(("failed to send reply: %v"), err)
		}
		return fmt.Errorf("failed to connect to %v: %v", req.DestAddr.ToString(), err)
	}
	defer destConn.Close()

	if err := sendSOCKS5Response(req.ClientConn, &SOCKS5Response{
		Request:  req,
		RespCode: ReplySucceeded,
	}); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	// Start relaying data between client and destination
	errChannel := make(chan error, 2)
	go relay(req.ClientConn, destConn, errChannel)
	go relay(destConn, req.ClientConn, errChannel)

	for i := 0; i < 2; i++ {
		if err := <-errChannel; err != nil {
			return fmt.Errorf("error during data relay: %v", err)
		}
	}
	return nil
}

func handleBind(req *SOCKS5Request) error {
	// The BIND command is not yet implemented
	return fmt.Errorf("BIND command is not implemented")
}

// RFC 1928 Section 7 defines this procedure for UDP ASSOCIATE
func handleUDPAssociate(req *SOCKS5Request) error {
	// Get an temporary port for UDP relay
	udpAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}
	req.BindAddr.IP = udpAddr.IP
	req.BindAddr.Port = uint16(udpAddr.Port)

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		msg := err.Error()
		var respCode byte

		if strings.Contains(msg, "refused") {
			respCode = ReplyConnectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			respCode = ReplyNetworkUnreachable
		} else {
			respCode = ReplyHostUnreachable
		}

		if err := sendSOCKS5Response(req.ClientConn, &SOCKS5Response{
			Request:  req,
			RespCode: respCode,
		}); err != nil {
			return fmt.Errorf(("failed to send reply: %v"), err)
		}
		return fmt.Errorf("failed to listen on UDP: %v", err)
	}
	defer udpConn.Close()

	if err := sendSOCKS5Response(req.ClientConn, &SOCKS5Response{
		Request:  req,
		RespCode: ReplySucceeded,
	}); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	// Start relaying data via seperate UDP connection
	clientMap := make(map[string]*net.UDPAddr)
	errChannel := make(chan error, 2)
	go relayUDPReqs(udpConn, errChannel, clientMap)
	go relayUDPResp(udpConn, errChannel, clientMap)

	for i := 0; i < 2; i++ {
		if err := <-errChannel; err != nil {
			return fmt.Errorf("error during data relay: %v", err)
		}
	}

	return nil
}

func relay(src io.Reader, dst io.Writer, errChannel chan error) {
	_, err := io.Copy(dst, src)
	if c, ok := dst.(interface{ CloseWrite() error }); ok {
		c.CloseWrite()
	}
	errChannel <- err
}

func relayUDPReqs(conn *net.UDPConn, errCh chan error, clientMap map[string]*net.UDPAddr) {
	buf := make([]byte, 65535) // max UDP size

	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			errCh <- fmt.Errorf("failed to read from UDP connection: %v", err)
			continue
		}
		if n < 10 {
			continue
		}

		// Parse UDP header and data
		rsv := buf[0:2]
		frg := buf[2:3]
		if rsv[0] != 0 || rsv[1] != 0 {
			errCh <- fmt.Errorf("invalid UDP header: reserved bytes must be zero")
			continue
		}
		// TODO: handle fragmentation if needed
		if frg[0] != 0 {
			errCh <- fmt.Errorf("invalid UDP header: we do not support fragmentation")
			continue
		}

		addrType := buf[3]
		var targetAddr *net.UDPAddr
		var headerLen int

		switch addrType {
		case AddrTypeIPv4:
			targetAddr = &net.UDPAddr{
				IP:   net.IP(buf[4:8]),
				Port: int(buf[8])<<8 | int(buf[9]),
			}
			headerLen = 10

		case AddrTypeIPv6:
			targetAddr = &net.UDPAddr{
				IP:   net.IP(buf[4:20]),
				Port: int(buf[20])<<8 | int(buf[21]),
			}
			headerLen = 22

		case AddrTypeDomain:
			domainLen := int(buf[4])
			targetAddr, err = net.ResolveUDPAddr("udp", fmt.Sprintf(
				"%s:%d",
				string(buf[5:5+domainLen]),
				int(buf[5+domainLen])<<8|int(buf[6+domainLen]),
			))
			if err != nil {
				errCh <- fmt.Errorf("failed to resolve domain: %v", err)
				continue
			}
			headerLen = 7 + domainLen

		default:
			errCh <- fmt.Errorf("invalid address type: %d", addrType)
			continue
		}

		payload := buf[headerLen:n]
		if targetAddr != nil {
			clientMap[targetAddr.String()] = clientAddr
		}

		// Send the data to the target address
		if _, err := conn.WriteToUDP(payload, targetAddr); err != nil {
			errCh <- fmt.Errorf("failed to write to target address %s: %v", targetAddr, err)
			continue
		}
	}
}

func relayUDPResp(conn *net.UDPConn, errCh chan error, clientMap map[string]*net.UDPAddr) {
	buf := make([]byte, 65535) // max UDP size

	for {
		n, targetAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			errCh <- fmt.Errorf("failed to read from UDP connection: %v", err)
			continue
		}

		clientAddr, ok := clientMap[targetAddr.String()]
		if !ok {
			errCh <- fmt.Errorf("no client address found for target %s", targetAddr)
			continue
		}

		// Prepare the UDP header
		resp := []byte{0x00, 0x00, 0x00} // rsv, rsv, frg
		if targetAddr.IP.To4() != nil {
			resp = append(resp, AddrTypeIPv4)
			resp = append(resp, targetAddr.IP.To4()...)
		} else {
			resp = append(resp, AddrTypeIPv6)
			resp = append(resp, targetAddr.IP.To16()...)
		}
		resp = append(resp, byte(targetAddr.Port>>8), byte(targetAddr.Port&0xFF))
		resp = append(resp, buf[:n]...)

		// Send the response back to the client
		if _, err := conn.WriteToUDP(resp, clientAddr); err != nil {
			errCh <- fmt.Errorf("failed to write to client address %s: %v", clientAddr, err)
			continue
		}
	}
}
