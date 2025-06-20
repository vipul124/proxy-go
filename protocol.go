package proxy

import (
	"net"
	"strconv"
)

// SOCKS5 Protocol Constants (RFC 1928)
const (
	// Version
	SOCKS5Version = 0x05

	// Command Codes
	CmdConnect      = 0x01 // TCP/IP client connection
	CmdBind         = 0x02 // TCP/IP sever incoming connection bind
	CmdUDPAssociate = 0x03 // UDP relay association

	// Address Types
	AddrTypeIPv4   = 0x01
	AddrTypeDomain = 0x03
	AddrTypeIPv6   = 0x04

	// Reply Codes
	ReplySucceeded               = 0x00 // Succeeded
	ReplyGeneralFailure          = 0x01 // General SOCKS server failure
	ReplyNotAllowed              = 0x02 // Connection not allowed by ruleset
	ReplyNetworkUnreachable      = 0x03 // Network unreachable
	ReplyHostUnreachable         = 0x04 // Host unreachable
	ReplyConnectionRefused       = 0x05 // Connection refused
	ReplyTTLExpired              = 0x06 // TTL expired
	ReplyCommandNotSupported     = 0x07 // Command not supported
	ReplyAddressTypeNotSupported = 0x08 // Address type not supported

	// Authentication Methods
	AuthNoMethod            = 0x00 // No authentication required
	AuthGSSAPI              = 0x01 // GSSAPI authentication
	AuthUsernamePassword    = 0x02 // Username/password authentication
	AuthNoAcceptableMethods = 0xFF // No acceptable authentication methods
)

type Address struct {
	Type byte // Address type (AddrTypeIPv4, AddrTypeDomain, AddrTypeIPv6)
	FQDN string
	IP   net.IP
	Port uint16
}

func (a *Address) ToByte() []byte {
	switch a.Type {
	case AddrTypeIPv4:
		return []byte(a.IP.To4())
	case AddrTypeDomain:
		return append([]byte{byte(len(a.FQDN))}, []byte(a.FQDN)...)
	case AddrTypeIPv6:
		return []byte(a.IP.To16())
	default:
		return nil // Invalid address type
	}
}

func (a *Address) ToString() string {
	if len(a.IP) > 0 {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(int(a.Port)))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(int(a.Port)))
}

// Request Body Structure
type SOCKS5Request struct {
	Version    byte
	Cmd        byte
	ClientAddr *Address // Address of the client making the request
	BindAddr   *Address // Address from which the server will relay data to target
	DestAddr   *Address // Address of the target destination
	ClientConn net.Conn
}

// Response Body Structure
type SOCKS5Response struct {
	Request  *SOCKS5Request
	RespCode byte
}
