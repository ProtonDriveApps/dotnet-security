package main

/*
#include "common.h"
*/
import "C"
import (
	"errors"
	"reflect"
	"strings"
	"unsafe"
)

const (
	Unknown           C.int = 0
	InvalidPassphrase C.int = 1
)

func main() {}

//export ReleaseArrayResultMemory
func ReleaseArrayResultMemory(result *C.ArrayResult) {
	C.free_ArrayResult(result)
}

func fillCArrayFromBytes(cArray *C.VoidArray, goArray []byte) {
	cArray.Pointer = C.CBytes(goArray)
	cArray.Length = C.int(len(goArray))
}

func bytesToCArray(goArray []byte) *C.VoidArray {
	var cArray = C.alloc_VoidArray()
	fillCArrayFromBytes(cArray, goArray)
	return cArray
}

func stringToCArray(goString string) *C.VoidArray {
	var cArray = C.alloc_VoidArray()
	cArray.Pointer = unsafe.Pointer(C.CString(goString))
	cArray.Length = C.int(len(goString))
	return cArray
}

func cArrayToBytes(cArray *C.VoidArray) []byte {
	if cArray == nil {
		return nil
	}

	goArray := (*[1 << 30]byte)(unsafe.Pointer(cArray.Pointer))[:cArray.Length]
	(*reflect.SliceHeader)(unsafe.Pointer(&goArray)).Cap = int(cArray.Length)
	return goArray
}

func cArrayToString(cArray *C.VoidArray) string {
	return C.GoStringN((*C.char)(cArray.Pointer), cArray.Length)
}

func cBooleanToBoolean(value C.char) bool {
	return value != 0
}

func errorToCError(err error) *C.Error {
	if err == nil {
		return nil
	}

	var message = err.Error()

	var result = C.alloc_Error()
	result.Type = Unknown
	result.Message = C.CString(message)

	var typeFound bool = false

	for err != nil && !typeFound {
		typeFound = true

		switch err.(type) {
		// At the moment there is no recognized type
		default:
			if strings.HasPrefix(message, "unable to unlock private key") {
				result.Type = InvalidPassphrase
			} else {
				typeFound = false
				err = errors.Unwrap(err)
			}
		}
	}

	return result
}

func clear(w []byte) {
	for k := range w {
		w[k] = 0x00
	}
}
