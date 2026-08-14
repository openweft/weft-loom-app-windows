// ssh_passphrase_windows.go — Credential Manager getter/setter for
// SSH key passphrases. Separate Credential Manager target prefix
// ("weft-ssh-passphrase") from the session-token store
// (keychain_windows.go) so removing one doesn't affect the other.
//
// Win32 mirror of the keychain_windows.go pattern : CredWriteW /
// CredReadW / CredDeleteW keyed by service + account (the canonical
// SSH key file path). Windows gates Read via the standard user account
// password (the Credential Manager is itself encrypted with the
// account's DPAPI master key) ; we layer Windows Hello on top
// opportunistically — if the box is enrolled, the user gets the
// biometric prompt before the passphrase is released.
package main

import (
	"errors"
	"fmt"

	"github.com/go-mswin/winrt"
)

// sshPassphraseService is the Credential Manager service identifier
// under which every passphrase entry lives. The composite
// "<sshPassphraseService>\<key path>" is the per-key TargetName.
const sshPassphraseService = "weft-ssh-passphrase"

// sshPassphraseGet returns the passphrase bytes stored for the given
// key path, or nil if no entry exists (the caller can then prompt the
// user via --store-ssh-passphrase). On a Windows Hello-enrolled
// machine the user is prompted to confirm biometry ; the function
// silently skips the biometric step when the machine isn't enrolled
// (the Credential Manager already gates on the account password in
// that case, so we don't add a second prompt with no biometric path).
func sshPassphraseGet(keyPath string) ([]byte, error) {
	// Best-effort biometric gate. Failure to surface Windows Hello
	// is downgraded to a log line — the Credential Manager retains
	// its own protection regardless.
	if err := requestUserConsent("Unlock your SSH key passphrase to connect to the Weft cluster"); err != nil {
		return nil, fmt.Errorf("windows hello : %w", err)
	}
	blob, ok, err := credRead(targetName(sshPassphraseService, keyPath))
	if err != nil {
		return nil, fmt.Errorf("credential manager get (target=%s\\%s): %w", sshPassphraseService, keyPath, err)
	}
	if !ok {
		return nil, nil
	}
	return blob, nil
}

// sshPassphraseSet stores or replaces the passphrase for the given key
// path. Credential Manager Generic items are bound to the local Windows
// user account and encrypted with the account's DPAPI master key, so
// no further at-rest tuning is needed.
func sshPassphraseSet(keyPath string, passphrase []byte) error {
	if err := credWrite(targetName(sshPassphraseService, keyPath), keyPath, passphrase); err != nil {
		return fmt.Errorf("credential manager set (target=%s\\%s): %w", sshPassphraseService, keyPath, err)
	}
	return nil
}

// sshPassphraseDelete removes the passphrase entry for the given key
// path (no-op when nothing is cached).
func sshPassphraseDelete(keyPath string) error {
	if err := credDelete(targetName(sshPassphraseService, keyPath)); err != nil {
		return fmt.Errorf("credential manager delete (target=%s\\%s): %w", sshPassphraseService, keyPath, err)
	}
	return nil
}

// ----- Windows Hello via UserConsentVerifier (WinRT) -----------------
//
// The WinRT plumbing (RoInitialize, activation-factory resolution,
// HSTRING, IAsyncOperation) now lives in the owned pure-Go wrapper
// github.com/go-mswin/winrt, which is built on the reference projection
// saltosystems/winrt-go. This file keeps only the Hello-specific policy.

// errUserConsentDeclined is returned when Windows Hello is available and
// the user explicitly declines or cancels the verification prompt.
var errUserConsentDeclined = errors.New("windows hello: user consent declined")

// requestUserConsent surfaces the Windows Hello prompt with the given
// reason. Best-effort posture (now actually functional — the previous
// hand-rolled combase call used a wrong IUserConsentVerifierStatics IID
// and never resolved the factory): when Windows Hello is unavailable
// (no PIN, no fingerprint reader, disabled by policy) or the WinRT
// runtime can't be reached, no extra gate is added and the Credential
// Manager's own DPAPI protection applies. Only when Hello IS available
// and the user explicitly declines or cancels do we refuse the release.
func requestUserConsent(reason string) error {
	avail, err := winrt.Available()
	if err != nil || !avail {
		// No Hello, or the runtime is unreachable: best-effort, no gate.
		return nil
	}
	verified, err := winrt.RequireUserConsent(reason)
	if err != nil {
		// Runtime failure while prompting: best-effort, do not block.
		return nil
	}
	if !verified {
		return errUserConsentDeclined
	}
	return nil
}
