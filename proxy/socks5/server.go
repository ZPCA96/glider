package socks5

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/nadoo/glider/pkg/log"
	"github.com/nadoo/glider/pkg/pool"
	"github.com/nadoo/glider/pkg/socks"
	"github.com/nadoo/glider/proxy"
)

var nm sync.Map

func init() {
	proxy.RegisterServer("socks5", NewSocks5Server)
}

// NewSocks5Server returns a socks5 proxy server.
func NewSocks5Server(s string, p proxy.Proxy) (proxy.Server, error) {
	return NewSocks5(s, nil, p)
}

// ListenAndServe serves socks5 requests.
func (s *Socks5) ListenAndServe() {
	go s.ListenAndServeUDP()
	s.ListenAndServeTCP()
}

// ListenAndServeTCP listen and serve on tcp port.
func (s *Socks5) ListenAndServeTCP() {
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		log.Fatalf("[socks5] failed to listen on %s: %v", s.addr, err)
		return
	}

	log.F("[socks5] listening TCP on %s", s.addr)

	for {
		c, err := l.Accept()
		if err != nil {
			log.F("[socks5] failed to accept: %v", err)
			continue
		}

		go s.Serve(c)
	}
}

// Serve serves a connection.
func (s *Socks5) Serve(c net.Conn) {
	defer c.Close()

	log.F("[socks5] Client address %s", c.RemoteAddr().String()) //127.0.0.0:NNNNN
	log.F("[socks5] Server address %s", c.LocalAddr().String())  //127.0.0.0:1080

	if c, ok := c.(*net.TCPConn); ok {
		c.SetKeepAlive(true)
	}

	//вызываем функцию handshake, чтобы прочесть адрес удалённого хоста для socks подклбюче
	//tgt, err := s.handshake(c)

	tgt, err, cmd := s.readAddrFromConn(c)

	log.F("[socks5] Remote target address %s", tgt.String())
	//надо починить параметр maxFailures, glider ошибочно считает, что прокси перестаёт работать
	//в моей имплементации UDP работать не будет, надо в этом участке кода его починить, см возврат ошибок в методе readAddrFromConn
	if err != nil {
		// UDP: keep the connection until disconnect then free the UDP socket
		if err == socks.Errors[socks.CommandNotSupported] {
			buf := pool.GetBuffer(1)
			defer pool.PutBuffer(buf)
			// block here
			for {
				_, err := c.Read(buf)
				if err, ok := err.(net.Error); ok && err.Timeout() {
					continue
				}
				// log.F("[socks5] servetcp udp associate end")
				return
			}
		}

		log.F("[socks5] failed in handshake with %s: %v", c.RemoteAddr(), err)
		return
	}
	var repCode byte
	rc, dialer, err := s.proxy.Dial("tcp", tgt.String())
	if err != nil {
		log.F("[socks5] %s <-> %s via %s, error in dial: %v", c.RemoteAddr(), tgt, dialer.Addr(), err)

		repCode = 5
		_ = s.handshake(c, cmd, repCode)
		return
	}
	repCode = 0
	_ = s.handshake(c, cmd, repCode)
	defer rc.Close()

	log.F("[socks5] %s <-> %s via %s", c.RemoteAddr(), tgt, dialer.Addr())

	if err = proxy.Relay(c, rc); err != nil {
		log.F("[socks5] %s <-> %s via %s, relay error: %v", c.RemoteAddr(), tgt, dialer.Addr(), err)
		// record remote conn failure only
		if !strings.Contains(err.Error(), s.addr) {
			s.proxy.Record(dialer, false)
		}
	}
}

// ListenAndServeUDP serves udp requests.
func (s *Socks5) ListenAndServeUDP() {
	lc, err := net.ListenPacket("udp", s.addr)
	if err != nil {
		log.Fatalf("[socks5] failed to listen on UDP %s: %v", s.addr, err)
		return
	}
	defer lc.Close()

	log.F("[socks5] listening UDP on %s", s.addr)

	s.ServePacket(lc)
}

// ServePacket implements proxy.PacketServer.
func (s *Socks5) ServePacket(pc net.PacketConn) {
	for {
		c := NewPktConn(pc, nil, nil, nil)
		buf := pool.GetBuffer(proxy.UDPBufSize)

		n, srcAddr, dstAddr, err := c.readFrom(buf)
		if err != nil {
			log.F("[socks5u] remote read error: %v", err)
			continue
		}

		var session *Session
		sessionKey := srcAddr.String()

		v, ok := nm.Load(sessionKey)
		if !ok || v == nil {
			session = newSession(sessionKey, srcAddr, dstAddr, c)
			nm.Store(sessionKey, session)
			go s.serveSession(session)
		} else {
			session = v.(*Session)
		}

		session.msgCh <- message{dstAddr, buf[:n]}
	}
}

func (s *Socks5) serveSession(session *Session) {
	dstPC, dialer, err := s.proxy.DialUDP("udp", session.srcPC.target.String())
	if err != nil {
		log.F("[socks5u] remote dial error: %v", err)
		nm.Delete(session.key)
		return
	}
	defer dstPC.Close()

	go func() {
		proxy.CopyUDP(session.srcPC, nil, dstPC, 2*time.Minute, 5*time.Second)
		nm.Delete(session.key)
		close(session.finCh)
	}()

	log.F("[socks5u] %s <-> %s via %s", session.src, session.srcPC.target, dialer.Addr())

	for {
		select {
		case msg := <-session.msgCh:
			_, err = dstPC.WriteTo(msg.msg, msg.dst)
			if err != nil {
				log.F("[socks5u] writeTo %s error: %v", msg.dst, err)
			}
			pool.PutBuffer(msg.msg)
			msg.msg = nil
		case <-session.finCh:
			return
		}
	}
}

type message struct {
	dst net.Addr
	msg []byte
}

// Session is a udp session
type Session struct {
	key   string
	src   net.Addr
	dst   net.Addr
	srcPC *PktConn
	msgCh chan message
	finCh chan struct{}
}

func newSession(key string, src, dst net.Addr, srcPC *PktConn) *Session {
	return &Session{key, src, dst, srcPC, make(chan message, 32), make(chan struct{})}
}

// Handshake fast-tracks SOCKS initialization to get target address to connect.
func (s *Socks5) handshake(c net.Conn, cmd byte, repCode byte) error {
	var err error
	switch cmd {
	case socks.CmdConnect:
		_, err = c.Write([]byte{5, repCode, 0, 1, 0, 0, 0, 0, 0, 0}) // SOCKS v5, reply succeeded
	case socks.CmdUDPAssociate:
		listenAddr := socks.ParseAddr(c.LocalAddr().String())
		if listenAddr == nil { // maybe it's unix socket
			listenAddr = socks.ParseAddr("127.0.0.1:0")
		}
		_, err = c.Write(append([]byte{5, 0, 0}, listenAddr...)) // SOCKS v5, reply succeeded
		if err != nil {
			return socks.Errors[socks.CommandNotSupported]
		}
		err = socks.Errors[socks.Socks5UDPAssociate]
	default:
		return socks.Errors[socks.CommandNotSupported]
	}
	return err
}

// Handshake fast-tracks SOCKS initialization to get target address to connect.
func (s *Socks5) readAddrFromConn(c net.Conn) (socks.Addr, error, byte) {
	// Read RFC 1928 for request and reply structure and sizes
	buf := pool.GetBuffer(socks.MaxAddrLen)
	defer pool.PutBuffer(buf)

	// read VER, NMETHODS, METHODS
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return nil, err, 0xff
	}

	nmethods := buf[1]
	if _, err := io.ReadFull(c, buf[:nmethods]); err != nil {
		return nil, err, 0xff
	}

	// write VER METHOD
	if s.user != "" && s.password != "" {
		_, err := c.Write([]byte{Version, socks.AuthPassword})
		if err != nil {
			return nil, err, 0xff
		}

		_, err = io.ReadFull(c, buf[:2])
		if err != nil {
			return nil, err, 0xff
		}

		// Get username
		userLen := int(buf[1])
		if userLen <= 0 {
			c.Write([]byte{1, 1})
			return nil, errors.New("auth failed: wrong username length"), 0xff
		}

		if _, err := io.ReadFull(c, buf[:userLen]); err != nil {
			return nil, errors.New("auth failed: cannot get username"), 0xff
		}
		user := string(buf[:userLen])

		// Get password
		_, err = c.Read(buf[:1])
		if err != nil {
			return nil, errors.New("auth failed: cannot get password len"), 0xff
		}

		passLen := int(buf[0])
		if passLen <= 0 {
			c.Write([]byte{1, 1})
			return nil, errors.New("auth failed: wrong password length"), 0xff
		}

		_, err = io.ReadFull(c, buf[:passLen])
		if err != nil {
			return nil, errors.New("auth failed: cannot get password"), 0xff
		}
		pass := string(buf[:passLen])

		// Verify
		if user != s.user || pass != s.password {
			_, err = c.Write([]byte{1, 1})
			if err != nil {
				return nil, err, 0xff
			}
			return nil, errors.New("auth failed, authinfo: " + user + ":" + pass), 0xff
		}

		// Response auth state
		_, err = c.Write([]byte{1, 0})
		if err != nil {
			return nil, err, 0xff
		}

	} else if _, err := c.Write([]byte{Version, socks.AuthNone}); err != nil {
		return nil, err, 0xff
	}

	// read VER CMD RSV ATYP DST.ADDR DST.PORT
	if _, err := io.ReadFull(c, buf[:3]); err != nil {
		return nil, err, 0xff
	}
	cmd := buf[1]
	addr, err := socks.ReadAddr(c)
	if err != nil {
		return nil, err, 0xff
	}
	return addr, err, cmd

}
