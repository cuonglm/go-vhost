// Portions of the TLS code are:
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// TLS virtual hosting

package vhost

import (
	"io"
	"net"

	"github.com/Windscribe/go-vhost/crypto/tls"
)

// A TLSConn represents a secured connection.
// It implements the net.Conn interface.
type TLSConn struct {
	*SharedConn
	ClientHelloInfo *tls.ClientHelloInfo
}

// TLS parses the ClientHello message on conn and returns
// a new, unread connection with metadata for virtual host muxing
func TLS(conn net.Conn) (tlsConn *TLSConn, err error) {
	return tlsWithECHProvider(conn, nil)
}

// ECH same as TLS, but with ECH extension enabled.
func ECH(conn net.Conn, echProvider tls.ECHProvider) (tlsConn *TLSConn, err error) {
	return tlsWithECHProvider(conn, echProvider)
}

func tlsWithECHProvider(conn net.Conn, echProvider tls.ECHProvider) (tlsConn *TLSConn, err error) {
	c, rd := newShared(conn)

	tlsConn = &TLSConn{SharedConn: c}
	if tlsConn.ClientHelloInfo, err = readClientHello(rd, echProvider); err != nil {
		return
	}

	return
}

func (c *TLSConn) Host() string {
	if c.ClientHelloInfo == nil {
		return ""
	}
	return c.ClientHelloInfo.ServerName
}

func (c *TLSConn) Free() {
	c.ClientHelloInfo = nil
}

func readClientHello(r io.Reader, echProvider tls.ECHProvider) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo

	err := tls.Server(sniSniffConn{r: r}, &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = new(tls.ClientHelloInfo)
			*hello = *argHello
			return nil, nil
		},
		ECHEnabled:        echProvider != nil,
		ServerECHProvider: echProvider,
	}).Handshake()

	if hello == nil {
		return nil, err
	}

	return hello, nil
}

type sniSniffConn struct {
	net.Conn
	r io.Reader
}

func (conn sniSniffConn) Read(p []byte) (int, error)  { return conn.r.Read(p) }
func (conn sniSniffConn) Write(p []byte) (int, error) { return 0, io.EOF }
