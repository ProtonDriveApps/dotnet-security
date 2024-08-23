package main

/*
#include "common.h"
#include "gopenpgp.h"
*/
import "C"
import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"unsafe"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

func getPublicKey(cPublicKey *C.PublicKey) (*crypto.Key, error) {
	var publicKey *crypto.Key
	var err error

	if cPublicKey.IsArmored != 0 {
		publicKey, err = crypto.NewKeyFromArmored(cArrayToString(&cPublicKey.Data))
		if err != nil {
			return nil, fmt.Errorf("unable to unarmor public key: %w", err)
		}
	} else {
		publicKey, err = crypto.NewKey(cArrayToBytes(&cPublicKey.Data))
		if err != nil {
			return nil, fmt.Errorf("unable to use public key: %w", err)
		}
	}

	if publicKey.IsPrivate() {
		defer publicKey.ClearPrivateParams()

		publicKey, err = publicKey.ToPublic()
		if err != nil {
			return nil, fmt.Errorf("unable to extract public key from private key: %w", err)
		}
	}

	return publicKey, nil
}

func getPrivateKey(cPrivateKey *C.PrivateKey) (*crypto.Key, error) {
	var lockedPrivateKey *crypto.Key
	var err error

	if cPrivateKey.IsArmored != 0 {
		lockedPrivateKey, err = crypto.NewKeyFromArmored(cArrayToString(&cPrivateKey.Data))
		if err != nil {
			return nil, fmt.Errorf("unable to unarmor private key: %w", err)
		}
	} else {
		lockedPrivateKey, err = crypto.NewKey(cArrayToBytes(&cPrivateKey.Data))
		if err != nil {
			return nil, fmt.Errorf("unable to use private key: %w", err)
		}
	}

	privateKey, err := lockedPrivateKey.Unlock(cArrayToBytes(&cPrivateKey.Passphrase))
	if err != nil {
		return nil, fmt.Errorf("unable to unlock private key: %w", err)
	}

	return privateKey, nil
}

func getPublicKeyRing(cPublicKey *C.PublicKey) (*crypto.KeyRing, error) {
	if cPublicKey == nil {
		return nil, nil
	}

	publicKey, err := getPublicKey(cPublicKey)
	if err != nil {
		return nil, err
	}

	publicKeyRing, err := crypto.NewKeyRing(publicKey)
	return publicKeyRing, err
}

func getPrivateKeyRing(cPrivateKeys *C.PrivateKey, privateKeyCount C.int) (*crypto.KeyRing, error) {
	cPrivateKeySlice := unsafe.Slice(cPrivateKeys, privateKeyCount)

	privateKeyRing, _ := crypto.NewKeyRing(nil)

	var err error
	var hasKey bool

	for i := 0; i < len(cPrivateKeySlice); i++ {
		privateKey, currentError := getPrivateKey(&cPrivateKeySlice[i])
		if currentError != nil {
			err = currentError
			continue
		}

		err = privateKeyRing.AddKey(privateKey)
		if err != nil {
			privateKey.ClearPrivateParams()
			err = fmt.Errorf("unable to add key to private key ring: %w", currentError)
			continue
		} else {
			hasKey = true
		}
	}

	if !hasKey {
		return nil, err
	}

	return privateKeyRing, err
}

func cSessionKeyToSessionKey(cSessionKey *C.SessionKey) *crypto.SessionKey {
	return crypto.NewSessionKeyFromToken(cArrayToBytes(&cSessionKey.Data), C.GoString(cSessionKey.AlgorithmId))
}

func sessionKeyToCSessionKey(sessionKey *crypto.SessionKey) *C.SessionKey {
	if sessionKey == nil {
		return nil
	}

	cSessionKey := C.alloc_SessionKey()
	fillCArrayFromBytes(&cSessionKey.Data, sessionKey.Key)
	cSessionKey.AlgorithmId = C.CString(sessionKey.Algo)

	return cSessionKey
}

// Duplicated from GopenPGP to avoid cloning the slices
func SplitMessage(msg *crypto.PGPMessage) (*crypto.PGPSplitMessage, error) {
	bytesReader := bytes.NewReader(msg.Data)
	packets := packet.NewReader(bytesReader)
	splitPoint := int64(0)
Loop:
	for {
		p, err := packets.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch p.(type) {
		case *packet.SymmetricKeyEncrypted, *packet.EncryptedKey:
			splitPoint = bytesReader.Size() - int64(bytesReader.Len())
		case *packet.SymmetricallyEncrypted, *packet.AEADEncrypted:
			break Loop
		}
	}
	return &crypto.PGPSplitMessage{
		KeyPacket:  msg.Data[:splitPoint],
		DataPacket: msg.Data[splitPoint:],
	}, nil
}
