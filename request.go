package proxy

import (
	"fmt"
	"net"
)

// RFC 1928 Section 4 defines the request format
func parseSOCKS5Request(conn net.Conn) (*SOCKS5Request, error) {
	// Read the first 3 bytes: version, command, reserved
	header := make([]byte, 3)
	if _, err := conn.Read(header); err != nil {
		err = fmt.Errorf("failed to read version number in SOCKS5 request header: %v", err)
		return nil, err
	}

	if header[0] != SOCKS5Version {
		err := fmt.Errorf("invalid SOCKS5 version: %d", header[0])
		return nil, err
	}

	// Parse the Source address and port
	ClientAddr := &Address{}
	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ClientAddr.IP = client.IP
		ClientAddr.Port = uint16(client.Port)
	}

	if ClientAddr.IP.To4() != nil {
		ClientAddr.Type = AddrTypeIPv4
	} else if ClientAddr.IP.To16() != nil {
		ClientAddr.Type = AddrTypeIPv6
	} else {
		err := fmt.Errorf("invalid source address type: %s", ClientAddr.IP.String())
		return nil, err
	}

	// Parse the Bind address and port
	BindAddr := &Address{}
	if local, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		BindAddr.IP = local.IP
		BindAddr.Port = uint16(local.Port)
	}

	if BindAddr.IP.To4() != nil {
		BindAddr.Type = AddrTypeIPv4
	} else if BindAddr.IP.To16() != nil {
		BindAddr.Type = AddrTypeIPv6
	} else {
		err := fmt.Errorf("invalid local address type: %s", BindAddr.IP.String())
		return nil, err
	}

	// Parse the Destination address and port
	addrType := make([]byte, 1)
	if _, err := conn.Read(addrType); err != nil {
		err = fmt.Errorf("failed to read address type in SOCKS5 request header: %v", err)
		return nil, err
	}

	addr := &Address{Type: addrType[0]}
	switch addrType[0] {
	case AddrTypeIPv4:
		ip := make([]byte, net.IPv4len)
		if _, err := conn.Read(ip); err != nil {
			err = fmt.Errorf("failed to read IPv4 address in SOCKS5 request: %v", err)
			return nil, err
		}
		addr.IP = net.IP(ip)

	case AddrTypeDomain:
		domainLen := make([]byte, 1)
		if _, err := conn.Read(domainLen); err != nil {
			err = fmt.Errorf("failed to read domain length in SOCKS5 request: %v", err)
			return nil, err
		}
		domain := make([]byte, domainLen[0])
		if _, err := conn.Read(domain); err != nil {
			err = fmt.Errorf("failed to read domain name in SOCKS5 request: %v", err)
			return nil, err
		}
		addr.FQDN = string(domain)

	case AddrTypeIPv6:
		ip := make([]byte, net.IPv6len)
		if _, err := conn.Read(ip); err != nil {
			err = fmt.Errorf("failed to read IPv6 address in SOCKS5 request: %v", err)
			return nil, err
		}
		addr.IP = net.IP(ip)

	default:
		if err := sendSOCKS5Response(conn, &SOCKS5Response{
			Request: &SOCKS5Request{
				Version:    SOCKS5Version,
				Cmd:        header[1],
				ClientAddr: ClientAddr,
				BindAddr:   BindAddr,
				DestAddr:   addr,
				ClientConn: conn,
			},
			RespCode: ReplyAddressTypeNotSupported,
		}); err != nil {
			err = fmt.Errorf(("failed to send reply: %v"), err)
			return nil, err
		}

		err := fmt.Errorf("unsupported address type: %d", addrType[0])
		return nil, err
	}

	portBytes := make([]byte, 2)
	if _, err := conn.Read(portBytes); err != nil {
		err = fmt.Errorf("failed to read port in SOCKS5 request: %v", err)
		return nil, err
	}
	port := uint16(portBytes[0])<<8 | uint16(portBytes[1])
	addr.Port = port

	// Create the SOCKS5Request object
	return &SOCKS5Request{
		Version:    header[0],
		Cmd:        header[1],
		ClientAddr: ClientAddr,
		BindAddr:   BindAddr,
		DestAddr:   addr,
		ClientConn: conn,
	}, nil
}

// RFC 1928 Section 5 defines the reponse format
func sendSOCKS5Response(conn net.Conn, response *SOCKS5Response) error {
	// Prepare the response
	resp := []byte{
		SOCKS5Version,
		response.RespCode,
		0x00,
		response.Request.BindAddr.Type,
	}
	resp = append(resp, response.Request.BindAddr.ToByte()...)
	resp = append(resp, byte(response.Request.BindAddr.Port>>8), byte(response.Request.BindAddr.Port&0xFF))

	// Send the response
	_, err := conn.Write(resp)
	return err
}
