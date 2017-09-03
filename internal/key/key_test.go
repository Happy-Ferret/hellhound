package key_test

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/artix-linux/hellhound/internal/key"
)

const (
	succeed = "\x1b[32m\u2713\x1b[0m"
	fail    = "\x1b[31m\u2717\x1b[0m"
)

func TestNew(t *testing.T) {
	t.Log("Given the need to test encryption key automated creation")
	{
		t.Logf("\tTest: 0\tWhen generating Key")
		{
			k, err := key.New()
			if err != nil {
				t.Fatalf("\t%s\tShould be able to generate a new Key: %v", fail, err)
			}

			t.Run("KeyLength", func(t *testing.T) {
				if keyLen := len(k); keyLen != 32 {
					t.Errorf("\t%s\tExpected key to be 32 bytes long but it is %d bytes long", fail, keyLen)
				}

				t.Logf("\t%s\tKey should be 32 bytes long", succeed)
			})

			t.Run("MacInFirstSixBytes", func(t *testing.T) {
				userID, groupID := os.Geteuid(), os.Getegid()
				if got := k[6]; got != uint8(userID) {
					t.Errorf("\t%s\tExpected key index 6 to be %d but got %d", fail, k[6], got)
				}

				b := make([]byte, 2)
				binary.LittleEndian.PutUint16(b, uint16(userID))
				if k[6] != b[0] && k[7] != b[1] {
					t.Errorf("\t%s\tExpected indexes 6 and 7 to be %v but got %v", fail, k[6:7], b)
				}

				b = make([]byte, 2)
				binary.LittleEndian.PutUint16(b, uint16(groupID))
				if k[8] != b[0] && k[9] != b[1] {
					t.Errorf("\t%s\tExpected indexes 8 and 9 to be %v but got %v", fail, k[8:9], b)
				}

				for i, elem := range []byte{55, 46, 50, 57, 55, 32, 51, 53, 50, 32, 53, 54, 54, 52, 49, 55, 120, 49, 48, 45, 51} {
					if k[10+i] != elem {
						t.Errorf("\t%s\tExpected index %d to be %v but got %v", fail, i, k[10+i], elem)
					}
				}

				t.Logf("\t%s\tShould match userID, groupID and fine-structure constant", succeed)
			})
		}
	}
}
