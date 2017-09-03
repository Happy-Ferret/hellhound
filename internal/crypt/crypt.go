package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/pkg/errors"
)

// Crypter offers encryption/decryption capabilities
type Crypter struct {
	key [32]byte
}

// New creates a new Crypter value, converts the given key
// into a cryptohraphically useful hash and returns it back
func New(key []byte) Crypter {
	c := Crypter{
		key: bytesToCryptoHash(key),
	}

	return c
}

// Encrypt encrypts the given slice of bytes into AES using the Cypher Key
func (c *Crypter) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key[0:])
	if err != nil {
		return nil, errors.Wrap(err, "can not create new AES cipher")
	}

	output := make([]byte, aes.BlockSize+len(data))
	iv := output[:aes.BlockSize]
	encryptedBytes := output[aes.BlockSize:]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, errors.Wrap(err, "can not populate iv with random data")
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encryptedBytes, data)

	return output, nil
}

// Decrypt decrypts the given crypted slice of bytes from AES into plain text using the Cypher Key
func (c *Crypter) Decrypt(cryptedData []byte) ([]byte, error) {
	// split input into IV and data and generate cipher block
	iv := cryptedData[:aes.BlockSize]
	data := cryptedData[aes.BlockSize:]
	block, err := aes.NewCipher(c.key[0:])
	if err != nil {
		return nil, errors.Wrap(err, "can not create new AES cipher")
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)

	return data, nil
}

// converts the given string into a 32 bytes key
func bytesToCryptoHash(key []byte) [32]byte {
	return sha256.Sum256([]byte(key))
}
