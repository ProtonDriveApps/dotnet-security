package main

/*
#include "common.h"
#include "gopenpgp.h"
*/
import "C"
import (
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

// GeneratePrivateKey generates a private key of the given keyType ("rsa" or "x25519"), encrypts it, and returns an armored string.
// If keyType is "rsa", bits is the RSA bitsize of the key.
// If keyType is "x25519", bits is unused.
// The caller needs to release the memory allocated for the returned structure by calling ReleaseArrayResultMemory.
//
//export GeneratePrivateKey
func GeneratePrivateKey(name, email *C.char, passphrase *C.VoidArray, keyType *C.char, bits C.int, timestampSeconds C.longlong) *C.ArrayResult {
	cryptoTimestamp := int64(timestampSeconds)
	if cryptoTimestamp > 0 {
		crypto.UpdateTime(cryptoTimestamp)
	}

	result := C.alloc_ArrayResult()

	key, err := helper.GenerateKey(C.GoString(name), C.GoString(email), cArrayToBytes(passphrase), C.GoString(keyType), int(bits))
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	result.Array = stringToCArray(key)

	return result
}

// GenerateSessionKey generates a session key.
// The caller needs to release the memory allocated for the returned structure by calling ReleaseSessionKeyResultMemory.
//
//export GenerateSessionKey
func GenerateSessionKey() *C.SessionKeyResult {
	result := C.alloc_SessionKeyResult()

	sessionKey, err := crypto.GenerateSessionKey()
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	result.SessionKey = sessionKeyToCSessionKey(sessionKey)

	return result
}

//export ReleaseSessionKeyResultMemory
func ReleaseSessionKeyResultMemory(result *C.SessionKeyResult) {
	C.free_SessionKeyResult(result)
}

// GenerateKeyPacket generates a session key and encrypts it into a key packet.
// The caller needs to release the memory allocated for the returned structure by calling ReleaseKeyPacketGenerationResultMemory.
//
//export GenerateKeyPacket
func GenerateKeyPacket(cPublicKey *C.PublicKey) *C.KeyPacketGenerationResult {
	result := C.alloc_KeyPacketGenerationResult()

	sessionKey, err := crypto.GenerateSessionKey()
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	publicKeyRing, err := getPublicKeyRing(cPublicKey)
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	keyPacket, err := publicKeyRing.EncryptSessionKey(sessionKey)

	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	result.SessionKey = sessionKeyToCSessionKey(sessionKey)
	result.KeyPacket = bytesToCArray(keyPacket)

	return result
}

//export ReleaseKeyPacketGenerationResultMemory
func ReleaseKeyPacketGenerationResultMemory(result *C.KeyPacketGenerationResult) {
	C.free_KeyPacketGenerationResult(result)
}

// GenerateRandomToken generates a random token with the specified key size.
// The caller needs to release the memory allocated for the returned structure by calling ReleaseArrayResultMemory.
//
//export GenerateRandomToken
func GenerateRandomToken(size C.int) *C.ArrayResult {
	result := C.alloc_ArrayResult()

	token, err := crypto.RandomToken(int(size))
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	result.Array = bytesToCArray(token)

	return result
}
