package reality

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

type chunkConn struct {
	net.Conn
	chunks [][]byte
}

func (c *chunkConn) Read(b []byte) (int, error) {
	if len(c.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(b, c.chunks[0])
	c.chunks = c.chunks[1:]
	return n, nil
}

func (c *chunkConn) SetReadDeadline(time.Time) error { return nil }

type sinkConn struct {
	net.Conn
	written bytes.Buffer
}

func (c *sinkConn) Write(b []byte) (int, error) { return c.written.Write(b) }

func TestGuardConnHoldsLastByteOfUnprocessedRecords(t *testing.T) {
	ccs := []byte{20, 3, 3, 0, 1, 1}
	finished := append([]byte{23, 3, 3, 0, 53}, make([]byte, 53)...)
	empty := []byte{23, 3, 3, 0, 0}
	stream := append(append(append([]byte{}, ccs...), finished...), empty...)

	cases := []struct {
		name   string
		chunks []int // sizes of the client's reads
		sent   []int // what the target has after each Read returns
	}{
		// a partial header goes through, then CCS and Finished arrive: hold the CCS's last byte
		{"split header", []int{3, 61, 5}, []int{3, 5, 68}},
		// one read with everything: hold from the CCS's last byte
		{"one read", []int{69}, []int{5}},
		// a zero-length record completes with its header, so its last header byte waits
		{"zero-length record", []int{64, 4, 1}, []int{5, 68, 68}},
	}
	for _, c := range cases {
		client := &chunkConn{}
		for i := 0; i < len(stream); {
			n := c.chunks[len(client.chunks)]
			client.chunks = append(client.chunks, stream[i:i+n])
			i += n
		}
		target := &sinkConn{}
		g := newGuardConn(client, target)
		b := make([]byte, 100)
		for i, want := range c.sent {
			g.Read(b)
			if target.written.Len() != want {
				t.Errorf("%s: after read %d the target has %d bytes, want %d", c.name, i+1, target.written.Len(), want)
			}
		}
		g.verified(io.ErrUnexpectedEOF) // hand over: the target gets the rest
		if !bytes.Equal(target.written.Bytes(), stream) {
			t.Errorf("%s: after the hand-over the target has %d bytes, want the whole stream (%d)", c.name, target.written.Len(), len(stream))
		}
	}
}
