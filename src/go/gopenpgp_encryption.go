package main

/*
#include "common.h"
#include "gopenpgp.h"
*/
import "C"
import (
	"bytes"

	"github.com/ProtonMail/gopenpgp/v2/armor"
	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/pkg/errors"
)

// Encrypt encrypts plain data into PGP packets, optionally with a signature packet.
// If no public key or password is provided, no key packet will be produced.
// If signatureInput is not nil, the caller is requesting a signature and must specify a private key.
// The caller needs to release the memory allocated for the returned structure by calling ReleaseEncryptionResultMemory.
//
//export Encrypt
func Encrypt(encryptionInput *C.EncryptionInput, signatureInput *C.SignatureInput, timestampSeconds C.longlong, includeSessionKeyInResult C.char) *C.EncryptionResult {
	cryptoTimestamp := int64(timestampSeconds)
	if cryptoTimestamp > 0 {
		crypto.UpdateTime(cryptoTimestamp)
	}

	result := C.alloc_EncryptionResult()

	plainMessage := crypto.NewPlainMessage(cArrayToBytes(&encryptionInput.PlainData))
	if encryptionInput.Name != nil {
		plainMessage.Filename = C.GoString(encryptionInput.Name)
	}

	var privateKeyForSignature *crypto.Key
	var sessionKey *crypto.SessionKey
	var err error

	if encryptionInput.SessionKey != nil {
		sessionKey = cSessionKeyToSessionKey(encryptionInput.SessionKey)
	} else {
		sessionKey, err = crypto.GenerateSessionKey()
		if err != nil {
			result.Error = errorToCError(err)
			return result
		}
	}
	defer sessionKey.Clear()

	var publicKeyRing *crypto.KeyRing
	publicKeyRing, err = getPublicKeyRing(encryptionInput.PublicKey)
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	privateKeyForSignature, err = getPrivateKeyForSignature(signatureInput)
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	if privateKeyForSignature != nil {
		defer privateKeyForSignature.ClearPrivateParams()
	}

	attachedSignatureRequested := signatureInput != nil && signatureInput.Detachment == nil
	var privateKeyForAttachedSignature *crypto.Key
	if attachedSignatureRequested {
		privateKeyForAttachedSignature = privateKeyForSignature
	} else {
		privateKeyForAttachedSignature = nil
	}

	result.EncryptionOutput, err = encrypt(
		plainMessage,
		sessionKey,
		publicKeyRing,
		cArrayToBytes(encryptionInput.Password),
		privateKeyForAttachedSignature,
		encryptionInput.MessageMustBeArmored != 0,
		encryptionInput.MessageMustBeCompressed != 0)

	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	if cBooleanToBoolean(includeSessionKeyInResult) {
		result.SessionKey = sessionKeyToCSessionKey(sessionKey)
	}

	detachedSignatureRequested := privateKeyForSignature != nil && signatureInput != nil && signatureInput.Detachment != nil
	if detachedSignatureRequested {
		if encryptionInput.Name != nil {
			plainMessage.Filename = C.GoString(encryptionInput.Name)
		}

		result.DetachedSignature, err = sign(
			plainMessage,
			privateKeyForSignature,
			signatureInput.Detachment.PublicKeyForEncryption,
			signatureInput.Detachment.IsArmored != 0)

		if err != nil {
			result.Error = errorToCError(err)
			return result
		}
	}

	return result
}

//export ReleaseEncryptionResultMemory
func ReleaseEncryptionResultMemory(result *C.EncryptionResult) {
	C.free_EncryptionResult(result)
}

// EncryptSessionKey encrypts a session key and returns the PGP key packet.
// The caller needs to release the memory allocated for the returned structure by calling ReleaseArrayResultMemory.
//
//export EncryptSessionKey
func EncryptSessionKey(cSessionKey *C.SessionKey, cPublicKey *C.PublicKey, password *C.VoidArray) *C.ArrayResult {
	result := C.alloc_ArrayResult()

	var keyPacket []byte
	var err error

	sessionKey := cSessionKeyToSessionKey(cSessionKey)

	if cPublicKey != nil {
		var publicKeyRing *crypto.KeyRing
		publicKeyRing, err = getPublicKeyRing(cPublicKey)

		if err != nil {
			result.Error = errorToCError(err)
			return result
		}

		keyPacket, err = publicKeyRing.EncryptSessionKey(sessionKey)
	} else if password != nil {
		keyPacket, err = crypto.EncryptSessionKeyWithPassword(sessionKey, cArrayToBytes(password))
	} else {
		err = errors.New("unable to encrypt: no public key or password provided")
	}

	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	result.Array = bytesToCArray(keyPacket)

	return result
}

// Sign returns a signature for the given data.
// The caller needs to release the memory allocated for the returned structure by calling ReleaseArrayResultMemory.
//
//export Sign
func Sign(data *C.VoidArray, name *C.char, signatureInput *C.SignatureInput, timestampSeconds C.longlong) *C.ArrayResult {
	cryptoTimestamp := int64(timestampSeconds)
	if cryptoTimestamp > 0 {
		crypto.UpdateTime(cryptoTimestamp)
	}

	result := C.alloc_ArrayResult()

	privateKey, err := getPrivateKeyForSignature(signatureInput)
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	defer privateKey.ClearPrivateParams()

	plainMessage := crypto.NewPlainMessage(cArrayToBytes(data))

	if name != nil {
		plainMessage.Filename = C.GoString(name)
	}

	result.Array, err = sign(
		plainMessage,
		privateKey,
		signatureInput.Detachment.PublicKeyForEncryption,
		signatureInput.Detachment.IsArmored != 0)

	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	return result
}

func encrypt(
	plainMessage *crypto.PlainMessage,
	sessionKey *crypto.SessionKey,
	publicKeyRing *crypto.KeyRing,
	password []byte,
	signatureKey *crypto.Key,
	mustBeArmored bool,
	mustBeCompressed bool) (*C.VoidArray, error) {
	var err error

	var estimatedMessageSize = estimateMessageSize(plainMessage, publicKeyRing, password != nil, mustBeArmored)
	buffer := bytes.NewBuffer(make([]byte, estimatedMessageSize))
	buffer.Reset()

	if publicKeyRing != nil {
		// TODO: write the key packets directly to the buffer
		keyPackets, err := publicKeyRing.EncryptSessionKey(sessionKey)
		if err != nil {
			return nil, err
		}

		buffer.Write(keyPackets)
	}

	if password != nil {
		// TODO: write the key packet directly to the buffer
		keyPacket, err := crypto.EncryptSessionKeyWithPassword(sessionKey, password)
		if err != nil {
			return nil, err
		}

		buffer.Write(keyPacket)
	}

	var metadata = crypto.PlainMessageMetadata{
		IsBinary: plainMessage.IsBinary(),
		Filename: plainMessage.GetFilename(),
		ModTime:  int64(plainMessage.GetTime()),
	}

	var signatureKeyRing *crypto.KeyRing
	if signatureKey != nil {
		signatureKeyRing, err = crypto.NewKeyRing(signatureKey)
		if err != nil {
			return nil, err
		}

		defer signatureKeyRing.ClearPrivateParams()
	}

	var writer crypto.WriteCloser

	if mustBeCompressed {
		writer, err = sessionKey.EncryptStreamWithCompression(buffer, &metadata, signatureKeyRing)
	} else {
		writer, err = sessionKey.EncryptStream(buffer, &metadata, signatureKeyRing)
	}

	if err != nil {
		return nil, err
	}

	_, err = writer.Write(plainMessage.Data)
	if err != nil {
		return nil, err
	}

	err = writer.Close()
	if err != nil {
		return nil, err
	}

	return getMessageCBytes(buffer.Bytes(), mustBeArmored)
}

func sign(plainMessage *crypto.PlainMessage, privateKey *crypto.Key, cPublicKey *C.PublicKey, mustBeArmored bool) (*C.VoidArray, error) {
	privateKeyRing, err := crypto.NewKeyRing(privateKey)
	if err != nil {
		return nil, err
	}

	signature, err := privateKeyRing.SignDetached(plainMessage)
	if err != nil {
		return nil, err
	}

	publicKeyRing, err := getPublicKeyRing(cPublicKey)
	if err != nil {
		return nil, err
	}

	mustEncryptSignature := publicKeyRing != nil
	if mustEncryptSignature {
		signaturePlainMessage := crypto.NewPlainMessage(signature.GetBinary())

		signatureMessage, err := publicKeyRing.Encrypt(signaturePlainMessage, nil)
		if err != nil {
			return nil, err
		}

		return getMessageCBytes(signatureMessage.Data, mustBeArmored)
	} else {
		return getSignatureCBytes(signature, mustBeArmored)
	}
}

func getPrivateKeyForSignature(signatureInput *C.SignatureInput) (*crypto.Key, error) {
	if signatureInput == nil {
		return nil, nil
	}

	privateKey, err := getPrivateKey(signatureInput.PrivateKey)

	return privateKey, err
}

func getSignatureCBytes(signature *crypto.PGPSignature, mustBeArmored bool) (*C.VoidArray, error) {
	if mustBeArmored {
		signatureString, err := signature.GetArmored()
		if err != nil {
			return nil, err
		}

		return stringToCArray(signatureString), nil
	} else {
		signatureBytes := signature.GetBinary()
		return bytesToCArray(signatureBytes), nil
	}
}

func getMessageCBytes(messageBytes []byte, mustBeArmored bool) (*C.VoidArray, error) {
	if mustBeArmored {
		messageString, err := armor.ArmorWithType(messageBytes, constants.PGPMessageHeader)
		if err != nil {
			return nil, err
		}

		return stringToCArray(messageString), nil
	} else {
		return bytesToCArray(messageBytes), nil
	}
}

func estimateMessageSize(plainMessage *crypto.PlainMessage, asymmetricKeyRing *crypto.KeyRing, unlockableWithPassword, mustBeArmored bool) int {
	const encryptionMaxAlignmentOverhead int = 15
	const base64Multiplier float32 = 1.3
	const armorHeader int = 200
	const keyPacketSize int = 100
	const overprovisioningMultiplier float32 = 1.1

	result := len(plainMessage.Data) + encryptionMaxAlignmentOverhead

	if asymmetricKeyRing != nil {
		result += asymmetricKeyRing.CountEntities() * keyPacketSize
	}

	if unlockableWithPassword {
		result += keyPacketSize
	}

	if mustBeArmored {
		result = int(float32(result)*base64Multiplier) + armorHeader
	}

	result = int(float32(result) * overprovisioningMultiplier)

	return result
}
