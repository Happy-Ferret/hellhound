package cipherpwd

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	"github.com/artix-linux/hellhound/internal/crypt"
	"github.com/pkg/errors"
)

// Generate generates a new Cipher Password AES file
// The pwd is stored as an AES encrypted file into the
// user ~/.hellhound/
func Generate(key, pwd []byte) error {
	crypter := crypt.New(key)
	cryptedPwd, cryptErr := crypter.Encrypt(pwd)
	if cryptErr != nil {
		return errors.Wrap(cryptErr, "could not generate cipher password")
	}

	user, userErr := user.Current()
	if userErr != nil {
		return errors.Wrap(userErr, "could not get current user home path")
	}

	outputDir := filepath.Join(user.HomeDir, ".hellhound")
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return errors.Wrap(err, "could not create user .hellhound directory")
	}

	dst := hex.EncodeToString(key)
	filePath := filepath.Join(outputDir, fmt.Sprintf("%s.hh", dst))
	if err := ioutil.WriteFile(filePath, cryptedPwd, 0600); err != nil {
		return errors.Wrapf(err, "could not write cipher file into %s", filePath)
	}

	return nil
}
