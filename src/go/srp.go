package main

/*
#include "common.h"
#include "srp.h"
*/
import "C"
import (
	"unsafe"

	srp "github.com/ProtonMail/go-srp"
)

// GenerateChallenge generates and returns a server ephemeral
// The caller needs to release the memory allocated for the result by calling ReleaseArrayResultMemory.
//export GenerateChallenge
func GenerateChallenge(modulusBytes, verifier, secretBytes *C.VoidArray, bitLength C.int) *C.ArrayResult {
	result := C.alloc_ArrayResult()

	server, err := srp.NewServerWithSecret(cArrayToBytes(modulusBytes), cArrayToBytes(verifier), cArrayToBytes(secretBytes), int(bitLength))
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	serverEphemeral, err := server.GenerateChallenge()
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	result.Array = bytesToCArray(serverEphemeral)

	return result
}

// VerifyClientProof verifies the client proof and returns the server proof
// The caller needs to release the memory allocated for the result by calling ReleaseArrayResultMemory.
//export VerifyClientProof
func VerifyClientProof(modulusBytes, verifier, secretBytes, clientProofBytes, clientEphemeralBytes *C.VoidArray, bitLength C.int) *C.ArrayResult {
	result := C.alloc_ArrayResult()

	server, err := srp.NewServerWithSecret(cArrayToBytes(modulusBytes), cArrayToBytes(verifier), cArrayToBytes(secretBytes), int(bitLength))
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	_, err = server.GenerateChallenge()
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	serverProof, err := server.VerifyProofs(cArrayToBytes(clientEphemeralBytes), cArrayToBytes(clientProofBytes))
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	result.Array = bytesToCArray(serverProof)

	return result
}

// GenerateVerifier generates an SRP verifier
// The caller needs to release the memory allocated for the result by calling ReleaseArrayResultMemory.
//export GenerateVerifier
func GenerateVerifier(password, salt *C.VoidArray, signedModulus *C.char, bitLength C.int) *C.ArrayResult {
	result := C.alloc_ArrayResult()

	passwordBytes := cArrayToBytes(password)
	saltBytes := cArrayToBytes(salt)
	auth, err := srp.NewAuthForVerifier(passwordBytes, C.GoString(signedModulus), saltBytes)
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	verifier, err := auth.GenerateVerifier(int(bitLength))
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	result.Array = bytesToCArray(verifier)

	return result
}

// GenerateProofs generates the client proof, a challenge for the server and the expected server proof
// The caller needs to release the memory allocated for the result by calling ReleaseProofGenerationResultMemory.
//export GenerateProofs
func GenerateProofs(version C.int, username *C.char, password *C.VoidArray, salt, signedModulus, serverEphemeral *C.char, bitLength C.int) *C.ProofGenerationResult {
	result := C.alloc_ProofGenerationResult()

	passwordBytes := cArrayToBytes(password)
	auth, err := srp.NewAuth(int(version), C.GoString(username), passwordBytes, C.GoString(salt), C.GoString(signedModulus), C.GoString(serverEphemeral))
	clear(passwordBytes)

	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	proofs, err := auth.GenerateProofs(int(bitLength))
	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	result.ClientProof = bytesToCArray(proofs.ClientProof)
	result.ClientEphemeral = bytesToCArray(proofs.ClientEphemeral)
	result.ExpectedServerProof = bytesToCArray(proofs.ExpectedServerProof)

	return result
}

//export ReleaseProofGenerationResultMemory
func ReleaseProofGenerationResultMemory(result *C.ProofGenerationResult) {
	C.free_ProofGenerationResult(result)
}

// Gets mailbox password hash (see go-srp documentation)
// The caller needs to release the memory allocated for the result by calling ReleaseArrayResultMemory.
//export MailboxPassword
func MailboxPassword(password *C.VoidArray, salt unsafe.Pointer, saltLength C.int) *C.ArrayResult {
	result := C.alloc_ArrayResult()

	passwordBytes := cArrayToBytes(password)
	hash, err := srp.MailboxPassword(passwordBytes, C.GoBytes(salt, saltLength))
	clear(passwordBytes)

	if err != nil {
		result.Error = errorToCError(err)
		return result
	}

	result.Array = bytesToCArray(hash)

	return result
}
