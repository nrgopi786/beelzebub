package SSH

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	gossh "golang.org/x/crypto/ssh"
)

// loadOrCreateHostKey returns the signer stored at path, generating and
// persisting a new ed25519 key when the file does not exist yet.
func loadOrCreateHostKey(path string) (gossh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		signer, err := gossh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse host key %s: %w", path, err)
		}
		return signer, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read host key %s: %w", path, err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("marshal host key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create host key dir: %w", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, fmt.Errorf("write host key %s: %w", path, err)
	}
	return gossh.NewSignerFromKey(priv)
}
