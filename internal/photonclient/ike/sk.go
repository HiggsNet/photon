package ike

// CBC framing and integrity follow RFC 7296 section 3.14 and RFC 4868.
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"io"
)

const skICVLen = 16

// SealSK encrypts a single SK payload. Authentication covers the complete IKE
// header and SK payload, including the IV, but excludes the final ICV itself.
// firstPayload names the first encrypted inner payload, not a following outer
// payload. Fragmentation and cleartext payloads preceding SK are unsupported.
func SealSK(header Header, firstPayload uint8, plaintext, encryptionKey, integrityKey []byte, random io.Reader) ([]byte, error) {
	if len(encryptionKey) != 16 || len(integrityKey) != 32 || random == nil || len(plaintext) > MaxMessageSize || (firstPayload == 0) != (len(plaintext) == 0) {
		return nil, errors.New("IKE: invalid SK input")
	}
	padLength := (aes.BlockSize - (len(plaintext)+1)%aes.BlockSize) % aes.BlockSize
	cipherLength := len(plaintext) + padLength + 1
	payloadLength := 4 + aes.BlockSize + cipherLength + skICVLen
	packet, err := header.Marshal(PayloadSK, HeaderLen+payloadLength)
	if err != nil {
		return nil, err
	}
	packet = append(packet, make([]byte, payloadLength)...)
	packet[HeaderLen] = firstPayload
	binary.BigEndian.PutUint16(packet[HeaderLen+2:], uint16(payloadLength))
	iv := packet[HeaderLen+4 : HeaderLen+4+aes.BlockSize]
	if _, err := io.ReadFull(random, iv); err != nil {
		return nil, err
	}
	encrypted := packet[HeaderLen+4+aes.BlockSize : len(packet)-skICVLen]
	copy(encrypted, plaintext)
	encrypted[len(encrypted)-1] = byte(padLength)
	block, _ := aes.NewCipher(encryptionKey)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, encrypted)
	copy(packet[len(packet)-skICVLen:], PRFSHA256(integrityKey, packet[:len(packet)-skICVLen])[:skICVLen])
	return packet, nil
}

func OpenSK(packet, encryptionKey, integrityKey []byte) (uint8, []byte, error) {
	if len(encryptionKey) != 16 || len(integrityKey) != 32 {
		return 0, nil, errors.New("IKE: invalid SK keys")
	}
	_, next, err := DecodeHeader(packet)
	if err != nil {
		return 0, nil, err
	}
	if next != PayloadSK || len(packet) < HeaderLen+4+aes.BlockSize+aes.BlockSize+skICVLen || int(binary.BigEndian.Uint16(packet[HeaderLen+2:])) != len(packet)-HeaderLen {
		return 0, nil, errors.New("IKE: invalid SK framing")
	}
	encrypted := packet[HeaderLen+4+aes.BlockSize : len(packet)-skICVLen]
	if len(encrypted)%aes.BlockSize != 0 {
		return 0, nil, errors.New("IKE: invalid SK ciphertext length")
	}
	// Never decrypt or inspect padding until the entire packet is authenticated.
	mac := PRFSHA256(integrityKey, packet[:len(packet)-skICVLen])[:skICVLen]
	if !hmac.Equal(mac, packet[len(packet)-skICVLen:]) {
		return 0, nil, errors.New("IKE: SK integrity check failed")
	}
	plaintext := make([]byte, len(encrypted))
	block, _ := aes.NewCipher(encryptionKey)
	cipher.NewCBCDecrypter(block, packet[HeaderLen+4:HeaderLen+4+aes.BlockSize]).CryptBlocks(plaintext, encrypted)
	padding := int(plaintext[len(plaintext)-1]) + 1
	if padding > len(plaintext) {
		return 0, nil, errors.New("IKE: invalid SK padding length")
	}
	plaintext = plaintext[:len(plaintext)-padding]
	first := packet[HeaderLen]
	if (first == 0) != (len(plaintext) == 0) {
		return 0, nil, errors.New("IKE: inconsistent SK inner payload")
	}
	return first, plaintext, nil
}
