package cipherpwd_test

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/artix-linux/hellhound/internal/crypt"

	"github.com/artix-linux/hellhound/internal/cipherpwd"
)

const (
	succeed = "\x1b[32m\u2713\x1b[0m"
	fail    = "\x1b[31m\u2717\x1b[0m"
)

func TestGenerate(t *testing.T) {
	t.Log("Given the need to test cypher password generation")
	{
		t.Log("\tTest: 0\tWhen generating cipher password file")
		{
			key, pwd := []byte("Key"), []byte("Test")
			if err := cipherpwd.Generate(key, pwd); err != nil {
				t.Errorf("\t%s\tShould be able to generate a new cipher password file: %v", fail, err)
			}

			user, userErr := user.Current()
			if userErr != nil {
				t.Fatalf("\t%s\tCan not get current user information: %v", fail, userErr)
			}

			cipherpwdFile := filepath.Join(user.HomeDir, ".hellhound", fmt.Sprintf("%s.hh", hex.EncodeToString(key)))
			_, statErr := os.Stat(cipherpwdFile)
			if statErr != nil {
				t.Fatalf("\t%s\tShould be able to get stats for cipher password file: %v", fail, statErr)
			}
			defer func() {
				os.RemoveAll(cipherpwdFile)
			}()

			data, readErr := ioutil.ReadFile(cipherpwdFile)
			if readErr != nil {
				t.Fatalf("\t%s\tShould be able to read the cipher password file: %v", fail, readErr)
			}

			crypter := crypt.New(key)
			plaintext, decryptErr := crypter.Decrypt(data)
			if decryptErr != nil {
				t.Fatalf("\t%s\tShould be able to decrypt the cipher password file data: %v", fail, decryptErr)
			}

			if got, expected := string(plaintext), string(pwd); got != expected {
				t.Errorf("\t%s\tExpected %s got %s", fail, expected, got)
			}

			t.Logf("\t%s\tFile exists and contents are expected", succeed)
		}
	}
}
