package proxy

import (
	"fmt"
	"net"
)

type SOCKS5Server struct {
	enableUDPAssociate bool
	enableBind         bool
}

func CreateSOCKS5Server() *SOCKS5Server {
	return &SOCKS5Server{
		enableUDPAssociate: false,
		enableBind:         false,
	}
}

func (server *SOCKS5Server) EnableUDPAssociate() {
	server.enableUDPAssociate = true
}

func (server *SOCKS5Server) EnableBind() {
	server.enableBind = true
}

func (server *SOCKS5Server) ServeSOCKS5Conn(conn net.Conn) {
	defer conn.Close()

	// Authenticate the client
	if err := readSOCKS5AuthMethods(conn); err != nil {
		server.handleError(conn, ReplyGeneralFailure, err)
		return
	}

	// Parse the request
	req, err := parseSOCKS5Request(conn)
	if err != nil {
		server.handleError(conn, ReplyGeneralFailure, fmt.Errorf("failed to parse SOCKS5 request: %v", err))
		return
	}

	// Before processing the request, resolve the destination address
	// TODO: add a custom DNS resolver support
	if req.DestAddr.Type == AddrTypeDomain {
		ip, err := net.ResolveIPAddr("ip", req.DestAddr.FQDN)
		if err != nil {
			err = fmt.Errorf("failed to resolve domain %s: %v", req.DestAddr.FQDN, err)
			server.handleError(conn, ReplyHostUnreachable, err)
			return
		}
		req.DestAddr.IP = ip.IP
	}

	// Handle the request based on the command
	switch req.Cmd {
	case CmdConnect:
		if errCode, err := handleConnect(req); err != nil {
			err = fmt.Errorf("failed to handle connect: %v", err)
			server.handleError(conn, errCode, err)
			return
		}
	case CmdBind:
		if !server.enableBind {
			err := fmt.Errorf("BIND command is not implemented")
			server.handleError(conn, ReplyCommandNotSupported, err)
			return
		}
		if err := handleBind(req); err != nil {
			err = fmt.Errorf("failed to handle bind: %v", err)
			server.handleError(conn, ReplyGeneralFailure, err)
			return
		}
	case CmdUDPAssociate:
		if !server.enableUDPAssociate {
			err := fmt.Errorf("UDP ASSOCIATE command is not implemented")
			server.handleError(conn, ReplyCommandNotSupported, err)
			return
		}
		if errCode, err := handleUDPAssociate(req); err != nil {
			err = fmt.Errorf("failed to handle UDP associate: %v", err)
			server.handleError(conn, errCode, err)
			return
		}
	default:
		err := fmt.Errorf("unsupported command: %d", req.Cmd)
		server.handleError(conn, ReplyCommandNotSupported, err)
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

func (server *SOCKS5Server) handleError(conn net.Conn, errCode byte, err error) {
	fmt.Printf("error: %v\n", err)

	// for ReplyCloseConnection, we just close the connection
	if errCode == ReplyCloseConnection {
		conn.Close()
		return
	}

	if err := sendSOCKS5Response(conn, &SOCKS5Response{
		Request:  nil,
		BindAddr: &DefaultAddress,
		RespCode: errCode,
	}); err != nil {
		fmt.Printf("failed to send error response: %v\n", err)
		conn.Close()
	}
}
