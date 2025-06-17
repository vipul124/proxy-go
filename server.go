package proxy

import (
	"fmt"
	"net"
)

type SOCKS5Server struct {
}

func (server *SOCKS5Server) ServeSOCKS5Conn(conn net.Conn) {
	defer conn.Close()

	// Authenticate the client
	if err := readSOCKS5AuthMethods(conn); err != nil {
		server.handleError(conn, err)
		return
	}

	// Parse the request
	req, err := parseSOCKS5Request(conn)
	if err != nil {
		server.handleError(conn, err)
		return
	}

	// Handle the request based on the command
	switch req.Cmd {
	case CmdConnect:
		if err := handleConnect(req); err != nil {
			err = fmt.Errorf("failed to handle connect: %v", err)
			server.handleError(conn, err)
			return
		}
	case CmdBind:
		if err := handleBind(req); err != nil {
			err = fmt.Errorf("failed to handle bind: %v", err)
			server.handleError(conn, err)
			return
		}
	case CmdUDPAssociate:
		if err := handleUDPAssociate(req); err != nil {
			err = fmt.Errorf("failed to handle UDP associate: %v", err)
			server.handleError(conn, err)
			return
		}
	default:
		if err := sendSOCKS5Response(conn, &SOCKS5Response{
			Request:  req,
			RespCode: ReplyCommandNotSupported,
		}); err != nil {
			err = fmt.Errorf(("failed to send reply: %v"), err)
			server.handleError(conn, err)
			return
		}

		err := fmt.Errorf("unsupported command: %d", req.Cmd)
		server.handleError(conn, err)
		return
	}
}

func (server *SOCKS5Server) Start(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to start SOCKS5 server: %v", err)
	}
	defer listener.Close()
	fmt.Printf("SOCKS5 server listening on %s\n", address)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("failed to accept connection: %v\n", err)
			continue
		}
		go server.ServeSOCKS5Conn(conn)
	}
}

func (server *SOCKS5Server) handleError(conn net.Conn, err error) {
	if err != nil {
		fmt.Println(err)
	}
}
