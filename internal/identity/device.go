package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

var (
	ErrInvalidSeed         = errors.New("invalid device identity seed")
	ErrInsecurePermissions = errors.New("device identity file permissions are too broad")
	ErrIdentitySymlink     = errors.New("device identity path must not be a symlink")
)

type Device struct {
	private ed25519.PrivateKey
}

func New() (*Device, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Device{private: append(ed25519.PrivateKey(nil), privateKey...)}, nil
}

func LoadOrCreate(path string) (*Device, error) {
	if path == "" {
		return nil, ErrInvalidSeed
	}
	device, err := load(path)
	if err == nil {
		return device, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	device, err = New()
	if err != nil {
		return nil, err
	}
	if err := persistSeed(path, device.private.Seed()); err != nil {
		if errors.Is(err, os.ErrExist) {
			return load(path)
		}
		return nil, err
	}
	return device, nil
}

func load(path string) (*Device, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrIdentitySymlink
	}
	if !info.Mode().IsRegular() {
		return nil, ErrInvalidSeed
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, ErrInsecurePermissions
	}
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, ErrInvalidSeed
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return &Device{private: append(ed25519.PrivateKey(nil), privateKey...)}, nil
}

func persistSeed(path string, seed []byte) error {
	if len(seed) != ed25519.SeedSize {
		return ErrInvalidSeed
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".maxrc-device-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(seed); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		if _, statErr := os.Lstat(path); statErr == nil {
			return os.ErrExist
		}
		return err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (d *Device) PublicKey() ed25519.PublicKey {
	publicKey := d.private.Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), publicKey...)
}

func (d *Device) PrivateKey() ed25519.PrivateKey {
	return append(ed25519.PrivateKey(nil), d.private...)
}

func DeviceID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", ErrInvalidSeed
	}
	digest := sha256.Sum256(publicKey)
	return "dev_" + base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func (d *Device) ID() string {
	id, _ := DeviceID(d.PublicKey())
	return id
}

func GeneratePairingCode() (string, [32]byte, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", [32]byte{}, err
	}
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	return code, sha256.Sum256([]byte(code)), nil
}

func PairingCodeMatches(expected [32]byte, code string) bool {
	got := sha256.Sum256([]byte(code))
	return subtle.ConstantTimeCompare(expected[:], got[:]) == 1
}
