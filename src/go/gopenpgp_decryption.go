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
	"reflect"
	"unsafe"

	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// UnlockPrivateKey unlocks a private key protected by a passphrase.
// The caller needs to release the memory allocated for the returned structure by calling ReleaseArrayResultMemory.
//
//export UnlockPrivateKey
func UnlockPrivateKey(lockedPrivateKey *C.VoidArray, isArmored C.int, passphrase *C.VoidArray) *C.ArrayResult {
	result := C.alloc_ArrayResult()

	var cPrivateKey C.PrivateKey
	cPrivateKey.Data = *lockedPrivateKey
	cPrivateKey.IsArmored = isArmored
	cPrivateKey.Passphrase = *passphrase

	privateKey, err := getPrivateKey(&cPrivateKey)
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	defer privateKey.ClearPrivateParams()

	privateKeyBytes, err := privateKey.Serialize()
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	result.Array = bytesToCArray(privateKeyBytes)

	return result
}

// Decrypt decrypts a PGP message and optionally verifies it against a signature.
// The caller needs to release the memory allocated for the returned structure by calling ReleaseDecryptionResultMemory.
// If verificationInput is not nil, the caller is requesting verification and must specify at least one public key.
// Also in that case, if a detached signature is specified, then it will be verified, and any attached signature will be ignored.
// If no detached signature is specified, the attached signature will be verified.
//
//export Decrypt
func Decrypt(decryptionInput *C.DecryptionInput, verificationInput *C.VerificationInput, includeSessionKeyInResult bool) *C.DecryptionResult {
	result := C.alloc_DecryptionResult()

	var plainMessage *crypto.PlainMessage
	var err error
	var verificationError *crypto.SignatureVerificationError

	message, err := getMessage(decryptionInput)
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	var sessionKey *crypto.SessionKey

	if decryptionInput.PrivateKeys != nil {
		var privateKeyRing *crypto.KeyRing
		privateKeyRing, privateKeyRingError := getPrivateKeyRing(decryptionInput.PrivateKeys, decryptionInput.PrivateKeysLength)
		if privateKeyRing == nil {
			result.Error = errorToCError(privateKeyRingError)
			return result
		}

		defer privateKeyRing.ClearPrivateParams()

		var publicKeyRing *crypto.KeyRing
		publicKeyRing, err = getPublicKeyRingIfVerificationRequested(verificationInput)
		if err != nil {
			result.Error = errorToCError(err)
			return result
		}

		var keyRingForAttachedSignatureVerification *crypto.KeyRing = nil
		if publicKeyRing != nil && verificationInput.DetachedSignature == nil {
			keyRingForAttachedSignatureVerification = publicKeyRing
		}

		plainMessage, sessionKey, verificationError, err = decrypt(privateKeyRing, nil, message, keyRingForAttachedSignatureVerification)

		if err != nil {
			if privateKeyRingError != nil {
				err = errors.Join(privateKeyRingError, err)
			}

			result.Error = errorToCError(err)
			return result
		}

		if verificationInput != nil && verificationInput.DetachedSignature != nil {
			verificationError, err = verifyDetached(plainMessage, verificationInput.DetachedSignature, privateKeyRing, publicKeyRing)
		}
	} else if decryptionInput.Password != nil {
		plainMessage, sessionKey, _, err = decrypt(nil, cArrayToBytes(decryptionInput.Password), message, nil)
	} else {
		err = errors.New("unable to decrypt: no private key ring or password provided")
	}

	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	result.DecryptionOutput = C.alloc_DecryptionOutput()

	if plainMessage != nil {
		plainData := plainMessage.GetBinary()
		fillCArrayFromBytes(&result.DecryptionOutput.DecryptedData, plainData)
	}

	if includeSessionKeyInResult {
		result.DecryptionOutput.SessionKey = sessionKeyToCSessionKey(sessionKey)
	}

	result.VerificationOutput = getVerificationOutput(verificationInput, verificationError)

	return result
}

//export ReleaseDecryptionResultMemory
func ReleaseDecryptionResultMemory(result *C.DecryptionResult) {
	C.free_DecryptionResult(result)
}

// DecryptSessionKey decrypts a PGP key packet and returns the session key.
// The caller needs to release the memory allocated for the returned structure by calling ReleaseSessionKeyResultMemory.
//
//export DecryptSessionKey
func DecryptSessionKey(cPrivateKeys *C.PrivateKey, privateKeyCount C.int, password *C.VoidArray, keyPacket *C.VoidArray) *C.SessionKeyResult {
	result := C.alloc_SessionKeyResult()

	var sessionKey *crypto.SessionKey
	var err error

	if cPrivateKeys != nil {
		var privateKeyRing *crypto.KeyRing
		privateKeyRing, privateKeyRingError := getPrivateKeyRing(cPrivateKeys, privateKeyCount)
		if privateKeyRing == nil {
			result.Error = errorToCError(privateKeyRingError)
			return result
		}

		defer privateKeyRing.ClearPrivateParams()

		sessionKey, err = privateKeyRing.DecryptSessionKey(cArrayToBytes(keyPacket))

		if err != nil && privateKeyRingError != nil {
			err = errors.Join(privateKeyRingError, err)
		}
	} else if password != nil {
		sessionKey, err = crypto.DecryptSessionKeyWithPassword(cArrayToBytes(keyPacket), cArrayToBytes(password))
	} else {
		err = errors.New("unable to decrypt: no private key ring or password provided")
	}

	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	result.SessionKey = sessionKeyToCSessionKey(sessionKey)

	return result
}

// Verify checks that the signature matches the given data for one of the given keys.
// The caller needs to release the memory allocated for the returned structure by calling ReleaseVerificationResultMemory.
//
//export Verify
func Verify(data *C.VoidArray, verificationInput *C.VerificationInput) *C.VerificationResult {
	result := C.alloc_VerificationResult()

	plainMessage := crypto.NewPlainMessage(cArrayToBytes(data))

	var publicKeyRing *crypto.KeyRing
	publicKeyRing, err := getPublicKeyRingIfVerificationRequested(verificationInput)
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	verificationError, err := verifyDetached(plainMessage, verificationInput.DetachedSignature, nil, publicKeyRing)
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	result.VerificationOutput = getVerificationOutput(verificationInput, verificationError)

	return result
}

//export ReleaseVerificationResultMemory
func ReleaseVerificationResultMemory(result *C.VerificationResult) {
	C.free_VerificationResult(result)
}

// TestSessionKey tests that the session key is able to decrypt enough bytes from a given data packet to match the given plain data.
// Only a sufficiently long prefix of the data packet is required, not the entire data packet.
//
//export TestSessionKey
func TestSessionKey(cSessionKey *C.SessionKey, cDataPacketPrefix *C.VoidArray, cExpectedPlainDataPrefix *C.VoidArray) C.int {
	sessionKey := cSessionKeyToSessionKey(cSessionKey)
	dataPacketPrefix := cArrayToBytes(cDataPacketPrefix)
	expectedPlainDataPrefix := cArrayToBytes(cExpectedPlainDataPrefix)

	dataPacketReader := bytes.NewReader(dataPacketPrefix)

	plainMessageReader, err := sessionKey.DecryptStream(dataPacketReader, nil, 0)
	if err != nil {
		return 0
	}

	plainMessageBytes := make([]byte, len(expectedPlainDataPrefix))
	numberOfBytesRead, err := plainMessageReader.Read(plainMessageBytes)
	if err != nil || numberOfBytesRead < len(expectedPlainDataPrefix) {
		return 0
	}

	isMatch := bytes.Equal(plainMessageBytes, expectedPlainDataPrefix)
	if !isMatch {
		return 0
	}

	return 1
}

func getMessage(decryptionInput *C.DecryptionInput) (*crypto.PGPMessage, error) {
	var message *crypto.PGPMessage

	if decryptionInput.MessageIsArmored != 0 {
		var err error
		message, err = crypto.NewPGPMessageFromArmored(cArrayToString(&decryptionInput.Message))
		if err != nil {
			return nil, fmt.Errorf("unable to unarmor message: %w", err)
		}
	} else {
		message = crypto.NewPGPMessage(cArrayToBytes(&decryptionInput.Message))
	}

	return message, nil
}

func decrypt(
	privateKeyRing *crypto.KeyRing,
	password []byte,
	message *crypto.PGPMessage,
	publicKeyRing *crypto.KeyRing) (*crypto.PlainMessage, *crypto.SessionKey, *crypto.SignatureVerificationError, error) {
	var err error
	var plainMessage *crypto.PlainMessage
	var sessionKey *crypto.SessionKey
	var verificationError *crypto.SignatureVerificationError

	splitMessage, err := SplitMessage(message)

	if privateKeyRing != nil {
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to split message into key and data packets: %w", err)
		}

		sessionKey, err = privateKeyRing.DecryptSessionKey(splitMessage.KeyPacket)
	} else {
		sessionKey, err = crypto.DecryptSessionKeyWithPassword(splitMessage.KeyPacket, password)
	}

	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to decrypt sessionKey: %w", err)
	}

	plainMessage, err = sessionKey.DecryptAndVerify(splitMessage.DataPacket, publicKeyRing, crypto.GetUnixTime())

	if err != nil {
		verr, ok := err.(crypto.SignatureVerificationError)
		if !ok {
			err = fmt.Errorf("unable to decrypt message: %w", err)
			return nil, nil, nil, err
		} else {
			verificationError = &verr
		}
	}

	return plainMessage, sessionKey, verificationError, nil
}

func verifyDetached(
	plainMessage *crypto.PlainMessage,
	detachedSignature *C.Signature,
	privateKeyRing *crypto.KeyRing,
	publicKeyRing *crypto.KeyRing) (*crypto.SignatureVerificationError, error) {
	var signature *crypto.PGPSignature
	var verificationError *crypto.SignatureVerificationError
	var err error

	if detachedSignature.IsEncrypted != 0 {
		var signatureMessage *crypto.PGPMessage

		if detachedSignature.IsArmored != 0 {
			signatureMessage, err = crypto.NewPGPMessageFromArmored(cArrayToString(&detachedSignature.Data))
			if err != nil {
				return nil, fmt.Errorf("unable to unarmor signature message: %w", err)
			}
		} else {
			signatureMessage = crypto.NewPGPMessage(cArrayToBytes(&detachedSignature.Data))
		}

		plainSignatureMessage, err := privateKeyRing.Decrypt(signatureMessage, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("unable to decrypt signature message: %w", err)
		}

		signature = crypto.NewPGPSignature(plainSignatureMessage.GetBinary())
	} else if detachedSignature.IsArmored != 0 {
		signature, err = crypto.NewPGPSignatureFromArmored(cArrayToString(&detachedSignature.Data))
		if err != nil {
			return nil, fmt.Errorf("unable to unarmor signature: %w", err)
		}
	} else {
		signature = crypto.NewPGPSignature(cArrayToBytes(&detachedSignature.Data))
	}

	err = publicKeyRing.VerifyDetached(plainMessage, signature, crypto.GetUnixTime())
	if err != nil {
		verr, ok := err.(crypto.SignatureVerificationError)
		if !ok {
			return nil, err
		} else {
			verificationError = &verr
		}
	}

	return verificationError, nil
}

func getPublicKeyRingIfVerificationRequested(verificationInput *C.VerificationInput) (*crypto.KeyRing, error) {
	if verificationInput == nil {
		return nil, nil
	}

	var cPublicKeys []C.PublicKey
	sliceHeader := (*reflect.SliceHeader)(unsafe.Pointer(&cPublicKeys))
	sliceHeader.Cap = int(verificationInput.PublicKeysLength)
	sliceHeader.Len = int(verificationInput.PublicKeysLength)
	sliceHeader.Data = uintptr(unsafe.Pointer(verificationInput.PublicKeys))

	publicKeyRing, _ := crypto.NewKeyRing(nil)

	for i := 0; i < len(cPublicKeys); i++ {
		publicKey, err := getPublicKey(&cPublicKeys[i])
		if err != nil {
			return nil, err
		}

		err = publicKeyRing.AddKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("unable to add key to public key ring: %w", err)
		}
	}

	return publicKeyRing, nil
}

func getVerificationOutput(verificationInput *C.VerificationInput, verificationError *crypto.SignatureVerificationError) *C.VerificationOutput {
	if verificationInput == nil {
		return nil
	}

	result := C.alloc_VerificationOutput()
	if verificationError != nil {
		result.Code = C.int(verificationError.Status)
		result.Message = C.CString(verificationError.Message)
	} else {
		result.Code = C.int(constants.SIGNATURE_OK)
	}

	return result
}
