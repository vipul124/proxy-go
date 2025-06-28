package proxy

import (
	"fmt"
	"net"
)

type AuthMethod interface {
	ID() byte
	Authenticate(conn net.Conn) error
}

type NoAuth struct{}

func (m NoAuth) ID() byte {
	return AuthNoMethod
}
func (m NoAuth) Authenticate(conn net.Conn) error {
	_, err := conn.Write([]byte{SOCKS5Version, AuthNoMethod})
	return err
}

type UsernamePasswordAuth struct {
	Users map[string]string
}

func (m UsernamePasswordAuth) ID() byte {
	return AuthUsernamePassword
}
func (m UsernamePasswordAuth) Authenticate(conn net.Conn) error {
	if _, err := conn.Write([]byte{SOCKS5Version, AuthUsernamePassword}); err != nil {
		return fmt.Errorf("failed to send authentication method: %v", err)
	}

	// Read the username and password
	ver := make([]byte, 1)
	if _, err := conn.Read(ver); err != nil {
		return fmt.Errorf("failed to read version byte: %v", err)
	}

	usernameLen := make([]byte, 1)
	if _, err := conn.Read(usernameLen); err != nil {
		return fmt.Errorf("failed to read username length: %v", err)
	}
	username := make([]byte, usernameLen[0])
	if _, err := conn.Read(username); err != nil {
		return fmt.Errorf("failed to read username: %v", err)
	}

	passwordLen := make([]byte, 1)
	if _, err := conn.Read(passwordLen); err != nil {
		return fmt.Errorf("failed to read password length: %v", err)
	}
	password := make([]byte, passwordLen[0])
	if _, err := conn.Read(password); err != nil {
		return fmt.Errorf("failed to read password: %v", err)
	}

	// match the database
	usernameStr := string(username)
	passwordStr := string(password)
	if expectedPassword, ok := m.Users[usernameStr]; !ok || expectedPassword != passwordStr {
		_, err := conn.Write([]byte{SOCKS5Version, AuthUsernamePassword, 0x01})
		if err != nil {
			return fmt.Errorf("failed to send authentication failure: %v", err)
		}
		return fmt.Errorf("authentication failed for user: %s", usernameStr)
	}

	_, err := conn.Write([]byte{SOCKS5Version, AuthUsernamePassword, 0x00})
	if err != nil {
		return fmt.Errorf("failed to send authentication success: %v", err)
	}

	return nil
}

type NoAcceptableMethodsAuth struct{}

func (m NoAcceptableMethodsAuth) ID() byte {
	return AuthNoAcceptableMethods
}
func (m NoAcceptableMethodsAuth) Authenticate(conn net.Conn) error {
	_, err := conn.Write([]byte{SOCKS5Version, AuthNoAcceptableMethods})
	return fmt.Errorf("no acceptable authentication methods: %v", err)
}

// RFC 1928 Section 3 defines the authentication methods
func (server *SOCKS5Server) readSOCKS5AuthMethods(conn net.Conn) error {
	// Read the first byte: version
	version := make([]byte, 1)
	if _, err := conn.Read(version); err != nil {
		err = fmt.Errorf("failed to read version number in SOCKS5 request header: %v", err)
		return err
	}

	if version[0] != SOCKS5Version {
		err := fmt.Errorf("invalid SOCKS5 version: %d", version[0])
		return err
	}

	// Read the second byte: number of authentication methods
	nMethods := make([]byte, 1)
	if _, err := conn.Read(nMethods); err != nil {
		err = fmt.Errorf("failed to read number of authentication methods: %v", err)
		return err
	}

	// Read the authentication methods
	methods := make([]byte, nMethods[0])
	if _, err := conn.Read(methods); err != nil {
		err = fmt.Errorf("failed to read authentication methods: %v", err)
		return err
	}

	// Check for acceptable methods
	for _, method := range methods {
		for _, authMethod := range server.authMethods {
			if method == authMethod.ID() {
				if err := authMethod.Authenticate(conn); err != nil {
					err = fmt.Errorf("authentication failed: %v", err)
					return err
				}
				break
			}
		}
	}

	return nil
}
