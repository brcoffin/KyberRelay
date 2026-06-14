package main

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"
)

func sealBytes(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	sw, err := newSealWriter(key, &buf)
	if err != nil {
		t.Fatalf("newSealWriter: %v", err)
	}
	if _, err := sw.Write(plaintext); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return buf.Bytes()
}

func openBytes(key, blob []byte) ([]byte, error) {
	sr, err := newStreamReader(key, bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(sr)
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// frames splits a sealed blob into its version byte and length-prefixed chunks.
func frames(blob []byte) (byte, [][]byte) {
	ver := blob[0]
	rest := blob[1:]
	var fr [][]byte
	for len(rest) >= 4 {
		n := int(binary.BigEndian.Uint32(rest[:4]))
		end := 4 + n
		if end > len(rest) {
			break
		}
		fr = append(fr, rest[:end])
		rest = rest[end:]
	}
	return ver, fr
}

func TestStreamRoundtrip(t *testing.T) {
	key := randBytes(t, 32)
	for _, size := range []int{0, 1, 100, streamChunk - 1, streamChunk, streamChunk + 1, 3 * streamChunk, 200000} {
		pt := randBytes(t, size)
		blob := sealBytes(t, key, pt)
		got, err := openBytes(key, blob)
		if err != nil {
			t.Fatalf("size %d: open: %v", size, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("size %d: roundtrip mismatch (got %d bytes)", size, len(got))
		}
	}
}

func TestStreamWrongKey(t *testing.T) {
	blob := sealBytes(t, randBytes(t, 32), randBytes(t, 5000))
	if _, err := openBytes(randBytes(t, 32), blob); err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestStreamTamper(t *testing.T) {
	key := randBytes(t, 32)
	blob := sealBytes(t, key, randBytes(t, 5000))
	blob[len(blob)/2] ^= 0x01 // flip a ciphertext bit
	if _, err := openBytes(key, blob); err == nil {
		t.Fatal("expected error decrypting tampered stream")
	}
}

func TestStreamTruncation(t *testing.T) {
	key := randBytes(t, 32)
	// Multi-chunk payload so dropping the final chunk leaves a now-final chunk
	// that was sealed as non-final → must fail (truncation detection).
	blob := sealBytes(t, key, randBytes(t, 2*streamChunk+500))
	ver, fr := frames(blob)
	if len(fr) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(fr))
	}
	truncated := []byte{ver}
	for _, f := range fr[:len(fr)-1] { // drop the last chunk
		truncated = append(truncated, f...)
	}
	if _, err := openBytes(key, truncated); err == nil {
		t.Fatal("expected error reading truncated stream")
	}
}

func TestStreamBadVersion(t *testing.T) {
	key := randBytes(t, 32)
	blob := sealBytes(t, key, randBytes(t, 100))
	blob[0] = 0x09 // wrong version byte
	if _, err := openBytes(key, blob); err == nil {
		t.Fatal("expected error on bad version byte")
	}
}

// TestFilenamePipeline mirrors encryptAndStoreStream + writeDecrypted: filename
// framing → deflate → chunk-encrypt, then decrypt → inflate → readFilename.
func TestFilenamePipeline(t *testing.T) {
	key := randBytes(t, 32)
	filename := "report final (v2).pdf"
	data := randBytes(t, 150000)

	var blob bytes.Buffer
	sw, err := newSealWriter(key, &blob)
	if err != nil {
		t.Fatal(err)
	}
	zw, err := flate.NewWriter(sw, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	var nl [2]byte
	binary.LittleEndian.PutUint16(nl[:], uint16(len(filename)))
	zw.Write(nl[:])
	zw.Write([]byte(filename))
	if _, err := io.Copy(zw, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}

	sr, err := newStreamReader(key, bytes.NewReader(blob.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	zr := flate.NewReader(sr)
	defer zr.Close()
	gotName, err := readFilename(zr)
	if err != nil {
		t.Fatal(err)
	}
	if gotName != filename {
		t.Fatalf("filename: got %q want %q", gotName, filename)
	}
	gotData, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotData, data) {
		t.Fatalf("data mismatch: got %d bytes want %d", len(gotData), len(data))
	}
}
