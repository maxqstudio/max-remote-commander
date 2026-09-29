package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type protocolIdentityVector struct {
	Seed      string `json:"seed_b64url"`
	PublicKey string `json:"public_key_b64url"`
}

type commandSigningVector struct {
	SchemaVersion int `json:"schema_version"`
	Identities struct {
		Controller protocolIdentityVector `json:"controller"`
	} `json:"identities"`
	CommandEnvelope struct {
		Value           CommandEnvelope `json:"value"`
		CanonicalJSON   string          `json:"canonical_json"`
		CanonicalSHA256 string          `json:"canonical_sha256"`
	} `json:"command_envelope"`
}

func loadCommandSigningVector(t *testing.T) commandSigningVector {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "protocol", "v1", "signing-vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vector commandSigningVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.SchemaVersion != CurrentVersion {
		t.Fatalf("vector schema version %d", vector.SchemaVersion)
	}
	return vector
}

func decodeVectorBytes(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestProtocolV1CommandSigningVector(t *testing.T) {
	vector := loadCommandSigningVector(t)
	seed := decodeVectorBytes(t, vector.Identities.Controller.Seed)
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("controller seed length %d", len(seed))
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := decodeVectorBytes(t, vector.Identities.Controller.PublicKey)
	if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		t.Fatal("controller public key does not match deterministic seed")
	}

	envelope := vector.CommandEnvelope.Value
	canonical, err := envelope.canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != vector.CommandEnvelope.CanonicalJSON {
		t.Fatalf("canonical bytes changed\n got: %s\nwant: %s", canonical, vector.CommandEnvelope.CanonicalJSON)
	}
	sum := sha256.Sum256(canonical)
	if hex.EncodeToString(sum[:]) != vector.CommandEnvelope.CanonicalSHA256 {
		t.Fatalf("canonical sha256 %x", sum)
	}

	expectedSignature := envelope.Signature
	unsigned := envelope
	unsigned.Signature = ""
	if err := unsigned.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	if unsigned.Signature != expectedSignature {
		t.Fatalf("signature changed\n got: %s\nwant: %s", unsigned.Signature, expectedSignature)
	}

	now := time.Unix(envelope.IssuedAt, 0)
	replay := NewMemoryReplayStore()
	if err := envelope.Verify(ed25519.PublicKey(publicKey), now, 0, replay); err != nil {
		t.Fatalf("valid vector: %v", err)
	}
	if err := envelope.Verify(ed25519.PublicKey(publicKey), now, 0, replay); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay vector: %v", err)
	}

	tampered := envelope
	tampered.Tool = "filesystem.write"
	if err := tampered.Verify(ed25519.PublicKey(publicKey), now, 0, nil); !errors.Is(err, ErrInvalidSig) {
		t.Fatalf("tamper vector: %v", err)
	}
	if err := envelope.Verify(ed25519.PublicKey(publicKey), time.Unix(envelope.ExpiresAt, 0), 0, nil); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry vector: %v", err)
	}
}
