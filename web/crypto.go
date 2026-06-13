package main

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

// Symmetric, passphrase-based sealing for the link+passphrase model.
//
// The original filename is sealed *inside* the ciphertext (not stored in
// plaintext metadata), so without the passphrase the server's at-rest data
// reveals neither the contents nor the name. AES-256-GCM + a strong KDF are
// quantum-resistant, so this path is post-quantum-safe without ML-KEM; ML-KEM
// is reserved for the future public-key/accounts model.

const (
	saltLen    = 16
	keyLen     = 32      // AES-256
	pbkdf2Iter = 200_000 // MVP; swap for Argon2id when hardening
)

var errBadPassphrase = errors.New("wrong passphrase or corrupt data")

func deriveKey(passphrase string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, passphrase, salt, pbkdf2Iter, keyLen)
}

// packPayload frames {filename, data} as uint16(len(filename)) + filename + data.
func packPayload(filename string, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, uint16(len(filename))); err != nil {
		return nil, err
	}
	buf.WriteString(filename)
	buf.Write(data)
	return buf.Bytes(), nil
}

// unpackPayload reverses packPayload.
func unpackPayload(payload []byte) (filename string, data []byte, err error) {
	if len(payload) < 2 {
		return "", nil, errors.New("short payload")
	}
	nameLen := int(binary.LittleEndian.Uint16(payload[:2]))
	if 2+nameLen > len(payload) {
		return "", nil, errors.New("bad payload")
	}
	return string(payload[2 : 2+nameLen]), payload[2+nameLen:], nil
}

func deflateBytes(in []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(in); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func inflateBytes(in []byte) ([]byte, error) {
	zr := flate.NewReader(bytes.NewReader(in))
	defer zr.Close()
	return io.ReadAll(zr)
}

// seal compresses {filename, data} and encrypts it under the passphrase.
func seal(passphrase, filename string, data []byte) (salt, nonce, ct []byte, err error) {
	salt = make([]byte, saltLen)
	if _, err = rand.Read(salt); err != nil {
		return
	}
	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return
	}

	raw, err := packPayload(filename, data)
	if err != nil {
		return
	}
	compressed, err := deflateBytes(raw)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return
	}
	ct = gcm.Seal(nil, nonce, compressed, nil)
	return
}

// open reverses seal, returning the original filename and data.
func open(passphrase string, salt, nonce, ct []byte) (filename string, data []byte, err error) {
	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return "", nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, err
	}
	compressed, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", nil, errBadPassphrase
	}
	payload, err := inflateBytes(compressed)
	if err != nil {
		return "", nil, errBadPassphrase
	}
	fn, d, perr := unpackPayload(payload)
	if perr != nil {
		return "", nil, errBadPassphrase
	}
	return fn, d, nil
}
