package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	"github.com/artix-linux/hellhound/internal/cipherpwd"
	"github.com/artix-linux/hellhound/internal/crypt"
	"github.com/artix-linux/hellhound/internal/key"
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "%s generate <pwd>", os.Args[0])
		flag.PrintDefaults()
	}
}

func main() {
	// parse command line flags
	flag.Parse()

	pwd, parseErr := parse()
	if parseErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", parseErr)
		usage()
	}

	key, keyErr := key.New()
	if keyErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", keyErr)
		os.Exit(-1)
	}

	if err := cipherpwd.Generate(key, pwd); err != nil {
		fmt.Fprintf(os.Stderr, "can not generate ciphered password: %v", err)
		os.Exit(-1)
	}

	fmt.Printf("generated cipher passphrase!\n")
}

// parses the command line and return back the given password
// if the user did not provide the right arguments an error is
// returned and the application should show the Usage and exit
func parse() ([]byte, error) {

	command := flag.Arg(0)
	switch command {
	case "generate":
		if len(flag.Args()) < 2 {
			return nil, fmt.Errorf("not enough arguments provided")
		}
		return []byte(flag.Arg(1)), nil
	case "retrieve":
		retrieve()
	}

	return nil, fmt.Errorf("unknown command %s", command)
}

// prints the usage information and exit with error
func usage() {
	flag.Usage()
	os.Exit(1)
}

// retrieve password and die
func retrieve() {
	key, keyErr := key.New()
	if keyErr != nil {
		fmt.Fprintf(os.Stderr, "can not generate new user key: %v", keyErr)
		os.Exit(-1)
	}

	user, userErr := user.Current()
	if userErr != nil {
		fmt.Fprintf(os.Stderr, "can not get data for current user: %v", userErr)
		os.Exit(-1)
	}

	cipherFile := filepath.Join(user.HomeDir, ".hellhound", fmt.Sprintf("%s.hh", hex.EncodeToString(key)))
	data, readErr := ioutil.ReadFile(cipherFile)
	if readErr != nil {
		fmt.Fprintf(os.Stderr, "can not read cipher file: %v", readErr)
		os.Exit(-1)
	}

	crypter := crypt.New(key)
	plaintext, decryptErr := crypter.Decrypt(data)
	if decryptErr != nil {
		fmt.Fprintf(os.Stderr, "can not decrypt ciphered data: %v", decryptErr)
		os.Exit(-1)
	}

	fmt.Fprintf(os.Stdout, "%s", plaintext)
	os.Exit(0)
}
