package reality

import (
	"io"
	"net"
	"sync"
	"time"
)

// [REALITY] SECTION: guard the Client Finished

// guardConn is the client's conn while REALITY waits for the Client Finished.
//
// The target has already seen the same Client Hello, so it gets the client's
// bytes too. Only the last byte of each record that REALITY has not finished
// with is held back, so a valid Client Finished never reaches the target. If
// REALITY rejects a record, or the target answers first, REALITY sends nothing
// of its own: the held bytes go to the target and the client gets the
// target's answer, so a replayed Client Hello followed by invalid data cannot
// tell REALITY apart from the target.
type guardConn struct {
	net.Conn
	target net.Conn

	pending []byte // read by REALITY but not yet sent to the target
	start   int    // stream offset of pending[0]
	read    int    // stream offset of the end of what REALITY has read
	done    int    // stream offset of the end of the last complete record REALITY has read

	header    [recordHeaderLen]byte // of the record being read
	headerLen int
	recordEnd int // stream offset of the end of the record being read, once its header is complete

	mutex    sync.Mutex
	state    int           // guardWaiting, guardVerified or guardHandedOver
	finished chan struct{} // closed when watch returns
}

const (
	guardWaiting = iota
	guardVerified
	guardHandedOver
)

func newGuardConn(conn, target net.Conn) *guardConn {
	return &guardConn{Conn: conn, target: target, finished: make(chan struct{})}
}

func (g *guardConn) Read(b []byte) (int, error) {
	g.send(g.done) // REALITY reads again, so it has accepted every complete record it had
	n, err := g.Conn.Read(b)
	g.pending = append(g.pending, b[:n]...)
	hold := -1
	for p := b[:n]; len(p) > 0 || g.headerLen == recordHeaderLen && g.read == g.recordEnd; {
		if g.headerLen < recordHeaderLen {
			c := copy(g.header[g.headerLen:], p)
			g.headerLen += c
			g.read += c
			p = p[c:]
			if g.headerLen == recordHeaderLen {
				g.recordEnd = g.read + (int(g.header[3])<<8 | int(g.header[4]))
			}
			continue
		}
		c := min(g.recordEnd-g.read, len(p))
		g.read += c
		p = p[c:]
		if g.read == g.recordEnd { // a complete record
			if hold == -1 {
				hold = g.recordEnd - 1 // the first one REALITY has not processed yet
			}
			g.done = g.recordEnd
			g.headerLen = 0
		}
	}
	if hold == -1 {
		hold = g.read
	}
	g.send(hold)
	return n, err
}

// Write drops what REALITY sends while it is guarded: only alerts for invalid data, which the target answers instead.
func (g *guardConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (g *guardConn) send(end int) {
	if n := end - g.start; n > 0 {
		g.target.Write(g.pending[:n])
		g.pending = g.pending[n:]
		g.start = end
	}
}

// watch forwards what the target sends after its handshake flight to the client
// once REALITY has handed the connection over, and hands it over itself if the
// target answers before the Client Finished is verified.
func (g *guardConn) watch(skip int, target net.Conn, client CloseWriteConn) {
	defer close(g.finished)
	buf := make([]byte, size)
	if skip > 0 {
		io.ReadFull(g.target, buf[:skip]) // the rest of the target's flight, which REALITY has replaced
	}
	for {
		n, err := target.Read(buf)
		g.mutex.Lock()
		if g.state == guardVerified {
			g.mutex.Unlock()
			return
		}
		if g.state == guardWaiting {
			g.state = guardHandedOver
			g.Conn.SetReadDeadline(time.Now()) // stop REALITY's read
		}
		g.mutex.Unlock()
		if n > 0 {
			client.Write(buf[:n])
		}
		if err != nil {
			client.CloseWrite()
			return
		}
	}
}

// verified reports whether REALITY keeps the connection, after it has read the
// Client Finished with error err. Otherwise the target gets everything the client sent.
func (g *guardConn) verified(err error) bool {
	g.mutex.Lock()
	if err == nil && g.state == guardWaiting {
		g.state = guardVerified
	} else {
		g.state = guardHandedOver
	}
	state := g.state
	g.mutex.Unlock()
	if state == guardVerified {
		return true
	}
	g.Conn.SetReadDeadline(time.Time{})
	g.send(g.start + len(g.pending))
	return false
}

func (g *guardConn) handedOver() bool {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	return g.state == guardHandedOver
}

// [REALITY] SECTION END
