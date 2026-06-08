// keypair_windows.go — Credential Manager Get/Set/Delete for the
// ed25519 private key used by the keypair-fallback flow.
//
// We deliberately store the raw 64-byte ed25519 private key (the
// canonical seed||pubkey form ed25519.NewKeyFromSeed produces) rather
// than a PEM / JSON wrapper : the keypair item never leaves the local
// Windows account, the Credential Manager already provides at-rest
// protection (DPAPI under the hood), and the simpler blob makes the
// Set/Get path obvious.
//
// Target pattern is the composite "weft-app-keypair\<issuer>". A
// different "account" (issuer) per cluster keeps multiple clusters
// using distinct keypairs side-by-side.
package main

import (
	"crypto/ed25519"
	"fmt"
)

// defaultKeypairStore returns the real Credential Manager-backed store.
func defaultKeypairStore() KeypairStore { return winKeypair{} }

type winKeypair struct{}

func (winKeypair) Get(service, account string) (ed25519.PrivateKey, bool, error) {
	blob, ok, err := credRead(targetName(service, account))
	if err != nil {
		return nil, false, fmt.Errorf("keypair credential manager get: %w", err)
	}
	if !ok {
		return nil, false, nil
	}
	if len(blob) != ed25519.PrivateKeySize {
		return nil, false, fmt.Errorf("keypair credential manager get: stored blob length = %d, want %d", len(blob), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(blob), true, nil
}

func (winKeypair) Set(service, account string, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("keypair credential manager set: private key length = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if err := credWrite(targetName(service, account), account, []byte(priv)); err != nil {
		return fmt.Errorf("keypair credential manager set: %w", err)
	}
	return nil
}

func (winKeypair) Delete(service, account string) error {
	if err := credDelete(targetName(service, account)); err != nil {
		return fmt.Errorf("keypair credential manager delete: %w", err)
	}
	return nil
}
