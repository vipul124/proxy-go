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

func handleUDPAssociate(req *SOCKS5Request) error {
	// The UDP ASSOCIATE command is not yet implemented
	return fmt.Errorf("UDP ASSOCIATE command is not implemented")
}

func relay(src io.Reader, dst io.Writer, errChannel chan error) {
	_, err := io.Copy(dst, src)
	if c, ok := dst.(interface{ CloseWrite() error }); ok {
		c.CloseWrite()
	}
	errChannel <- err
}
