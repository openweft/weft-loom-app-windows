// keychain_windows.go — Windows Credential Manager Get/Set/Delete for
// the session-token blob via direct Win32 calls (CredWriteW /
// CredReadW / CredDeleteW from advapi32.dll). No third-party deps.
//
// We persist a single JSON blob (the marshalled Token) under one
// CRED_TYPE_GENERIC item per (service, account) pair. service defaults
// to "weft-app", account is the issuer URL so an operator can keep
// multiple clusters logged in side by side — the TargetName is the
// composite "<service>\<account>" which Credential Manager treats as
// an opaque per-user key.
//
// All Win32 strings are UTF-16. The CREDENTIAL struct is fixed shape
// matching wincred.h ; we lay it out manually so we can hand it to
// CredWriteW / receive it from CredReadW without cgo.
package main

import (
	"encoding/json"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CRED_TYPE_GENERIC : opaque app-defined blob (this is what we want —
// the Credential Manager UI surfaces it as "Generic Credentials").
const credTypeGeneric uint32 = 1

// CRED_PERSIST_LOCAL_MACHINE : persists across sign-outs (matches the
// macOS Keychain default).
const credPersistLocalMachine uint32 = 2

// errorNotFound (ERROR_NOT_FOUND, decimal 1168) maps to the OSX
// errSecItemNotFound sentinel used by the orchestration code path.
const errorNotFound = 1168

// credential mirrors the wincred.h CREDENTIALW layout. The variable
// blob lives in heap memory ; CredentialBlob points into it.
//
// Field order matches the Windows headers exactly. The blob pointer
// is typed as *byte so the Go GC tracks it correctly on Set (a
// uintptr would be opaque) and `unsafe.Slice` is straightforward on
// Get. The pointer fields we never write (Attributes) stay as
// `uintptr` so the layout matches the native struct on both 386 and
// amd64 builds.
type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

// procCredReadW / procCredWriteW / procCredFree / procCredDeleteW are
// resolved lazily from advapi32. CredWrite + CredRead use the W
// variants for UTF-16 names.
var (
	modAdvapi32     = windows.NewLazySystemDLL("advapi32.dll")
	procCredReadW   = modAdvapi32.NewProc("CredReadW")
	procCredWriteW  = modAdvapi32.NewProc("CredWriteW")
	procCredFree    = modAdvapi32.NewProc("CredFree")
	procCredDeleteW = modAdvapi32.NewProc("CredDeleteW")
)

// targetName builds the composite "<service>\<account>" string the
// Credential Manager uses to key the item. Matches the macOS Keychain
// pair (kSecAttrService, kSecAttrAccount) projected onto one slot.
func targetName(service, account string) string {
	return service + "\\" + account
}

// defaultKeychain returns the real Credential Manager-backed store.
// Kept named "Keychain" so the orchestration code in auth.go is
// identical to the macOS build.
func defaultKeychain() KeychainStore { return winKeychain{} }

type winKeychain struct{}

func (winKeychain) Get(service, account string) (Token, bool, error) {
	blob, ok, err := credRead(targetName(service, account))
	if err != nil {
		return Token{}, false, err
	}
	if !ok {
		return Token{}, false, nil
	}
	var tok Token
	if err := json.Unmarshal(blob, &tok); err != nil {
		return Token{}, false, fmt.Errorf("credential manager get: parse blob: %w", err)
	}
	return tok, true, nil
}

func (winKeychain) Set(service, account string, tok Token) error {
	blob, err := json.Marshal(tok)
	if err != nil {
		return fmt.Errorf("credential manager set: marshal: %w", err)
	}
	return credWrite(targetName(service, account), account, blob)
}

func (winKeychain) Delete(service, account string) error {
	return credDelete(targetName(service, account))
}

// credWrite is the low-level Win32 CredWriteW wrapper. userName is
// stamped into the CredentialManager UI's "User name" column ; the
// secret material is the blob bytes.
func credWrite(target, userName string, blob []byte) error {
	tgt, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return fmt.Errorf("credential manager set: target name: %w", err)
	}
	usr, err := windows.UTF16PtrFromString(userName)
	if err != nil {
		return fmt.Errorf("credential manager set: user name: %w", err)
	}
	var blobPtr *byte
	if len(blob) > 0 {
		blobPtr = &blob[0]
	}
	cred := credential{
		Type:               credTypeGeneric,
		TargetName:         tgt,
		CredentialBlobSize: uint32(len(blob)),
		CredentialBlob:     blobPtr,
		Persist:            credPersistLocalMachine,
		UserName:           usr,
	}
	// CredWriteW(PCREDENTIALW Credential, DWORD Flags) returns BOOL.
	r1, _, lastErr := procCredWriteW.Call(
		uintptr(unsafe.Pointer(&cred)),
		0,
	)
	if r1 == 0 {
		return fmt.Errorf("credential manager set: CredWriteW: %w", lastErr)
	}
	return nil
}

// credRead is the low-level Win32 CredReadW wrapper. Returns the
// stored blob ; (nil, false, nil) on miss so callers can treat it as
// "no cached session". Other Win32 failures surface as errors.
func credRead(target string) ([]byte, bool, error) {
	tgt, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return nil, false, fmt.Errorf("credential manager get: target name: %w", err)
	}
	var pcred *credential
	r1, _, lastErr := procCredReadW.Call(
		uintptr(unsafe.Pointer(tgt)),
		uintptr(credTypeGeneric),
		0,
		uintptr(unsafe.Pointer(&pcred)),
	)
	if r1 == 0 {
		if errno, ok := lastErr.(syscall.Errno); ok && uint32(errno) == errorNotFound {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("credential manager get: CredReadW: %w", lastErr)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(pcred)))
	// Copy the blob bytes out of Win32-owned memory before we CredFree.
	n := int(pcred.CredentialBlobSize)
	if n == 0 || pcred.CredentialBlob == nil {
		return []byte{}, true, nil
	}
	src := unsafe.Slice(pcred.CredentialBlob, n)
	out := make([]byte, n)
	copy(out, src)
	return out, true, nil
}

// credDelete is the low-level Win32 CredDeleteW wrapper. ERROR_NOT_FOUND
// is swallowed — the caller's expectation is "make sure it's gone".
func credDelete(target string) error {
	tgt, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return fmt.Errorf("credential manager delete: target name: %w", err)
	}
	r1, _, lastErr := procCredDeleteW.Call(
		uintptr(unsafe.Pointer(tgt)),
		uintptr(credTypeGeneric),
		0,
	)
	if r1 == 0 {
		if errno, ok := lastErr.(syscall.Errno); ok && uint32(errno) == errorNotFound {
			return nil
		}
		return fmt.Errorf("credential manager delete: CredDeleteW: %w", lastErr)
	}
	return nil
}
