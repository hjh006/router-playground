package main

import (
	"anytls/proxy/padding"
	"anytls/proxy/session"
	"anytls/util"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	singbufio "github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

// Exercise the actual SOCKS inbound, TLS/authentication, session pool, stream
// framing and TCP relay. Every HTTP request closes its connection before the
// next starts; all six streams must use exactly one TLS connection.
func TestSOCKSSerialSessionReuse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	password := sha256.Sum256([]byte("local-session-reuse-test"))
	previousPassword := passwordSha256
	passwordSha256 = password[:]
	defer func() { passwordSha256 = previousPassword }()

	certificate, err := util.GenerateKeyPair(nil, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	server, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*certificate}, NextProtos: []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	var tlsConnections, streams atomic.Int32
	serverErrors := make(chan error, 16)
	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				return
			}
			tlsConnections.Add(1)
			go func(conn net.Conn) {
				defer conn.Close()
				auth := make([]byte, 34)
				if _, err := io.ReadFull(conn, auth); err != nil {
					serverErrors <- err
					return
				}
				if !bytes.Equal(auth[:32], password[:]) {
					serverErrors <- fmt.Errorf("invalid test authentication")
					return
				}
				if _, err := io.CopyN(io.Discard, conn, int64(binary.BigEndian.Uint16(auth[32:]))); err != nil {
					serverErrors <- err
					return
				}
				if conn.(*tls.Conn).ConnectionState().NegotiatedProtocol != "h2" {
					serverErrors <- fmt.Errorf("explicit h2 ALPN was not negotiated")
					return
				}
				session.NewServerSession(conn, func(stream *session.Stream) {
					streams.Add(1)
					defer stream.Close()
					destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
					if err != nil {
						serverErrors <- err
						return
					}
					outbound, err := net.DialTimeout("tcp", destination.String(), time.Second)
					if err != nil {
						stream.HandshakeFailure(err)
						serverErrors <- err
						return
					}
					defer outbound.Close()
					if err := stream.HandshakeSuccess(); err != nil {
						serverErrors <- err
						return
					}
					_ = singbufio.CopyConn(ctx, stream, outbound)
				}, &padding.DefaultPaddingFactory).Run()
			}(conn)
		}
	}()

	config, err := newTLSConfig(server.Addr().String(), "localhost", "h2", true)
	if err != nil {
		t.Fatal(err)
	}
	client := NewMyClient(ctx, func(ctx context.Context) (net.Conn, error) {
		return dialTLS(ctx, server.Addr().String(), config, "chrome", time.Second)
	}, 30*time.Second, 30*time.Second, 0)
	defer client.sessionClient.Close()
	inbound, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inbound.Close()
	handler := NewInboundListener("", "socks5", client)
	handled := make(chan struct{}, 8)
	go func() {
		for {
			conn, err := inbound.Accept()
			if err != nil {
				return
			}
			go func() {
				handler.handleConnection(ctx, conn)
				handled <- struct{}{}
			}()
		}
	}()

	for i := 0; i < 3; i++ {
		marker := fmt.Sprintf("destination-%d", i)
		destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Connection", "close")
			fmt.Fprint(w, marker+":"+r.URL.Path)
		}))
		defer destination.Close()
		for j := 0; j < 2; j++ {
			conn, err := net.DialTimeout("tcp", inbound.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := socks.ClientHandshake5(conn, socks5.CommandConnect, M.ParseSocksaddr(strings.TrimPrefix(destination.URL, "http://")), "", ""); err != nil {
				conn.Close()
				t.Fatalf("stream %d SOCKS handshake: %v", i*2+j+1, err)
			}
			io.WriteString(conn, "GET /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				conn.Close()
				t.Fatalf("stream %d response: %v", i*2+j+1, err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			conn.Close()
			if err != nil || string(body) != marker+":/echo" {
				t.Fatalf("stream %d body=%q, err=%v", i*2+j+1, body, err)
			}
			select {
			case <-handled: // Wait until this stream is returned to the pool.
			case <-time.After(3 * time.Second):
				t.Fatal("SOCKS relay did not close after HTTP response")
			}
		}
	}
	if got := tlsConnections.Load(); got != 1 {
		t.Fatalf("six serial streams opened %d TLS sessions, want exactly one reused session", got)
	}
	if got := streams.Load(); got != 6 {
		t.Fatalf("server accepted %d streams, want six", got)
	}
	select {
	case err := <-serverErrors:
		t.Fatal(err)
	default:
	}
}
