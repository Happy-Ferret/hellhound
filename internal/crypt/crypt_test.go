package crypt_test

import (
	"testing"

	"github.com/artix-linux/hellhound/internal/crypt"
)

const (
	succeed = "\x1b[32m\u2713\x1b[0m"
	fail    = "\x1b[31m\u2717\x1b[0m"
)

func TestEncryptDecrypt(t *testing.T) {
	tt := []struct {
		name  string
		input string
		key   []byte
	}{
		{"foo", "Foo", []byte("Bar")},
		{"bar", "Bar", []byte("Foo")},
		{"empty", "", []byte("")},
		{"quixote", "en un lugar de La Mancha de cuyo nombre no quiero acordarme", []byte("My Secret Key")},
	}

	t.Log("Given the need to test encryption and decryption")
	{
		for i, test := range tt {
			tf := func(t *testing.T) {
				t.Logf("\tTest: %d\tWhen encrypting %s with key %s", i, test.input, test.key)
				{
					c := crypt.New(test.key)
					enc, err := c.Encrypt([]byte(test.input))
					if err != nil {
						t.Fatalf("\t%s\tShould be able to encrypt the given data: %v", fail, err)
					}

					dec, err := c.Decrypt(enc)
					if err != nil {
						t.Fatalf("\t%s\tShould be able to decrypt %v with key %s: %v", fail, enc, test.key, err)
					}

					if stringDec := string(dec); stringDec != test.input {
						t.Errorf("\t%s\tExpected %s, got %s", fail, test.input, stringDec)
					}

					t.Logf("\t%s\tShould be decoded into %s", succeed, test.input)
				}
			}

			t.Run(test.name, tf)
		}
	}
}
