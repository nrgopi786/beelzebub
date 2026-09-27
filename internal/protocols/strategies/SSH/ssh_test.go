package SSH

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/stretchr/testify/assert"
)

type mockTracer struct {
	events []tracer.Event
}

func (m *mockTracer) TraceEvent(event tracer.Event) {
	m.events = append(m.events, event)
}

func TestBuildPrompt(t *testing.T) {
	tests := []struct {
		user       string
		serverName string
		expected   string
	}{
		{"root", "ubuntu", "root@ubuntu:~$ "},
		{"admin", "debian", "admin@debian:~$ "},
		{"", "", "@:~$ "},
		{"user", "", "user@:~$ "},
		{"", "server", "@server:~$ "},
	}
	for _, tt := range tests {
		t.Run(tt.user+"@"+tt.serverName, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildPrompt(tt.user, tt.serverName))
		})
	}
}

func TestSSHStrategy_Init_ValidAddress(t *testing.T) {
	strategy := &SSHStrategy{}
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:                "127.0.0.1:0",
		Description:            "test SSH",
		DeadlineTimeoutSeconds: 2,
		PasswordRegex:          ".*",
	}

	err := strategy.Init(servConf, mt)
	assert.NoError(t, err)
	assert.NotNil(t, strategy.Sessions)
}

func TestSSHStrategy_Init_ReusesExistingSessions(t *testing.T) {
	strategy := &SSHStrategy{}
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:                "127.0.0.1:0",
		DeadlineTimeoutSeconds: 1,
		PasswordRegex:          ".*",
	}

	assert.NoError(t, strategy.Init(servConf, mt))
	assert.NotNil(t, strategy.Sessions)

	original := strategy.Sessions

	// A second Init must reuse the same Sessions store, not replace it.
	assert.NoError(t, strategy.Init(servConf, mt))
	assert.Same(t, original, strategy.Sessions)
}

func TestSSHStrategy_Init_InvalidAddress(t *testing.T) {
	strategy := &SSHStrategy{}
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:       "invalid-address-no-port",
		PasswordRegex: ".*",
	}

	// SSH runs the listener asynchronously; Init itself should not return an error.
	assert.NoError(t, strategy.Init(servConf, mt))
}

func TestLoadOrCreateHostKey_PersistsKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "ssh_host_ed25519_key")

	first, err := loadOrCreateHostKey(path)
	assert.NoError(t, err)
	assert.Equal(t, "ssh-ed25519", first.PublicKey().Type())

	info, err := os.Stat(path)
	assert.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	second, err := loadOrCreateHostKey(path)
	assert.NoError(t, err)
	assert.Equal(t, first.PublicKey().Marshal(), second.PublicKey().Marshal())
}

func TestLoadOrCreateHostKey_InvalidKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad_key")
	assert.NoError(t, os.WriteFile(path, []byte("not a key"), 0o600))

	_, err := loadOrCreateHostKey(path)
	assert.Error(t, err)
}

func TestSSHStrategy_Init_InvalidHostKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad_key")
	assert.NoError(t, os.WriteFile(path, []byte("not a key"), 0o600))

	servConf := parser.BeelzebubServiceConfiguration{
		Address:       "127.0.0.1:0",
		PasswordRegex: ".*",
		HostKeyPath:   path,
	}
	assert.Error(t, (&SSHStrategy{}).Init(servConf, &mockTracer{}))
}
