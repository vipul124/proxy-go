package proxy

import (
	"fmt"
	"net"
)

// RFC 1928 Section 3 defines the authentication methods
func readSOCKS5AuthMethods(conn net.Conn) error {
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
	// We will implement other methods later, for now we only support no authentication
	var selectedAuth byte = AuthNoAcceptableMethods
	for _, method := range methods {
		if method == AuthNoMethod {
			selectedAuth = AuthNoMethod
			break
		}
	}

	if selectedAuth == AuthNoAcceptableMethods {
		if _, err := conn.Write([]byte{SOCKS5Version, AuthNoAcceptableMethods}); err != nil {
			err = fmt.Errorf("failed to send authentication methods response: %v", err)
			return err
		}
		return fmt.Errorf("no acceptable authentication methods")
	}
	if selectedAuth == AuthNoMethod {
		if _, err := conn.Write([]byte{SOCKS5Version, AuthNoMethod}); err != nil {
			err = fmt.Errorf("failed to send authentication methods response: %v", err)
			return err
		}
	}

	return nil
}
