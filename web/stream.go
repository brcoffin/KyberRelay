package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
)

// Chunked streaming AEAD for stored message blobs, so large files are never
// held whole in memory (encrypt while reading the upload, decrypt while writing
// the download). This is the STREAM construction used by age/libsodium
// secretstream: the plaintext is split into fixed-size chunks, each sealed with
// AES-256-GCM under the per-message KEM key and a counter nonce. The final chunk
// carries an authenticated "last" flag, so truncating or reordering chunks fails
// to decrypt (defends against truncation attacks the single-shot format can't
// see). Blobs begin with a version byte; v1 (no byte) is the legacy single-shot
// format, still read via openWithKey.

const (
	streamVersion byte = 2
	streamChunk        = 64 * 1024 // plaintext bytes per chunk
	gcmTagSize         = 16
)

var (
	errBadStream       = errors.New("corrupt or tampered stream")
	errStreamTruncated = errors.New("stream truncated")
)

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// streamNonce builds the 12-byte GCM nonce for a chunk: an 8-byte big-endian
// counter (bytes 3..10) plus a final-chunk flag (byte 11). The key is unique per
// message (fresh ML-KEM encapsulation), so a deterministic counter nonce can't
// repeat across messages.
func streamNonce(counter uint64, last bool) []byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[3:11], counter)
	if last {
		n[11] = 1
	}
	return n[:]
}

// sealWriter encrypts everything written to it as a chunked stream. Whole chunks
// are sealed (non-final) as the buffer fills; Close seals the remaining bytes as
// the final chunk (possibly empty, when the input is an exact multiple of the
// chunk size).
type sealWriter struct {
	gcm          cipher.AEAD
	dst          io.Writer
	counter      uint64
	buf          []byte
	wroteVersion bool
}

func newSealWriter(key []byte, dst io.Writer) (*sealWriter, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return &sealWriter{gcm: gcm, dst: dst, buf: make([]byte, 0, streamChunk)}, nil
}

func (w *sealWriter) writeVersion() error {
	if w.wroteVersion {
		return nil
	}
	if _, err := w.dst.Write([]byte{streamVersion}); err != nil {
		return err
	}
	w.wroteVersion = true
	return nil
}

func (w *sealWriter) Write(p []byte) (int, error) {
	if err := w.writeVersion(); err != nil {
		return 0, err
	}
	total := len(p)
	for len(p) > 0 {
		space := streamChunk - len(w.buf)
		take := space
		if len(p) < take {
			take = len(p)
		}
		w.buf = append(w.buf, p[:take]...)
		p = p[take:]
		if len(w.buf) == streamChunk {
			if err := w.flush(false); err != nil {
				return 0, err
			}
		}
	}
	return total, nil
}

func (w *sealWriter) Close() error {
	if err := w.writeVersion(); err != nil {
		return err
	}
	return w.flush(true) // final chunk (possibly empty)
}

func (w *sealWriter) flush(last bool) error {
	ct := w.gcm.Seal(nil, streamNonce(w.counter, last), w.buf, nil)
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(ct)))
	if _, err := w.dst.Write(lp[:]); err != nil {
		return err
	}
	if _, err := w.dst.Write(ct); err != nil {
		return err
	}
	w.counter++
	w.buf = w.buf[:0]
	return nil
}

// streamReader decrypts a chunked stream produced by sealWriter. Each chunk's
// "last" flag is determined by peeking for more data, so a dropped final chunk
// is detected as a nonce/tag mismatch rather than a silent truncation.
type streamReader struct {
	gcm     cipher.AEAD
	src     *bufio.Reader
	counter uint64
	buf     []byte // decrypted, not yet consumed
	done    bool
}

func newStreamReader(key []byte, src io.Reader) (*streamReader, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	br := bufio.NewReader(src)
	ver, err := br.ReadByte()
	if err != nil {
		return nil, errBadStream
	}
	if ver != streamVersion {
		return nil, errBadStream
	}
	return &streamReader{gcm: gcm, src: br}, nil
}

func (r *streamReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if r.done {
			return 0, io.EOF
		}
		if err := r.next(); err != nil {
			return 0, err
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *streamReader) next() error {
	var lp [4]byte
	if _, err := io.ReadFull(r.src, lp[:]); err != nil {
		return errStreamTruncated // no final-flagged chunk before EOF
	}
	clen := binary.BigEndian.Uint32(lp[:])
	if clen < gcmTagSize || clen > streamChunk+gcmTagSize {
		return errBadStream
	}
	ct := make([]byte, clen)
	if _, err := io.ReadFull(r.src, ct); err != nil {
		return errStreamTruncated
	}
	// A chunk is final iff no bytes follow it.
	last := false
	if _, err := r.src.Peek(1); err == io.EOF {
		last = true
	} else if err != nil {
		return err
	}
	plain, err := r.gcm.Open(nil, streamNonce(r.counter, last), ct, nil)
	if err != nil {
		return errBadStream
	}
	r.counter++
	r.buf = plain
	if last {
		r.done = true
	}
	return nil
}

// countingReader tallies bytes read, for recording a stored message's size.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// readFilename reads the leading uint16-length-prefixed filename framed at the
// start of the (decompressed) payload by encryptAndStoreStream.
func readFilename(r io.Reader) (string, error) {
	var nl [2]byte
	if _, err := io.ReadFull(r, nl[:]); err != nil {
		return "", err
	}
	n := int(binary.LittleEndian.Uint16(nl[:]))
	if n == 0 {
		return "", nil
	}
	name := make([]byte, n)
	if _, err := io.ReadFull(r, name); err != nil {
		return "", err
	}
	return string(name), nil
}
