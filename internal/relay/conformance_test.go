package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

type relayIdentityVector struct {
	Seed      string `json:"seed_b64url"`
	PublicKey string `json:"public_key_b64url"`
}

type relaySigningVector struct {
	SchemaVersion int `json:"schema_version"`
	Identities struct {
		Device     relayIdentityVector `json:"device"`
		Controller relayIdentityVector `json:"controller"`
	} `json:"identities"`
	DeviceAssertion struct {
		Value           DeviceAssertion `json:"value"`
		CanonicalJSON   string          `json:"canonical_json"`
		CanonicalSHA256 string          `json:"canonical_sha256"`
	} `json:"device_assertion"`
	ControllerAssertion struct {
		Value           ControllerAssertion `json:"value"`
		CanonicalJSON   string              `json:"canonical_json"`
		CanonicalSHA256 string              `json:"canonical_sha256"`
	} `json:"controller_assertion"`
}

type restartSemanticsVector struct {
	SchemaVersion          int    `json:"schema_version"`
	OriginalAgentSessionID string `json:"original_agent_session_id"`
	Cases []struct {
		ID                   string `json:"id"`
		NextAgentSessionID   string `json:"next_agent_session_id"`
		AdvanceSeconds       int64  `json:"advance_seconds"`
		ExpectedRequestState string `json:"expected_request_state"`
	} `json:"cases"`
}

func loadRelayVectorFile(t *testing.T, name string, target any) {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "protocol", "v1", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatal(err)
	}
}

func decodeRelayVectorBytes(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertRelayCanonicalVector(t *testing.T, canonical []byte, expectedJSON, expectedSHA string) {
	t.Helper()
	if string(canonical) != expectedJSON {
		t.Fatalf("canonical bytes changed\n got: %s\nwant: %s", canonical, expectedJSON)
	}
	sum := sha256.Sum256(canonical)
	if hex.EncodeToString(sum[:]) != expectedSHA {
		t.Fatalf("canonical sha256 %x", sum)
	}
}

func TestProtocolV1RelaySigningVectors(t *testing.T) {
	var vector relaySigningVector
	loadRelayVectorFile(t, "signing-vectors.json", &vector)
	if vector.SchemaVersion != 1 {
		t.Fatalf("vector schema version %d", vector.SchemaVersion)
	}

	deviceSeed := decodeRelayVectorBytes(t, vector.Identities.Device.Seed)
	controllerSeed := decodeRelayVectorBytes(t, vector.Identities.Controller.Seed)
	if len(deviceSeed) != ed25519.SeedSize || len(controllerSeed) != ed25519.SeedSize {
		t.Fatal("invalid deterministic vector seed length")
	}
	devicePrivate := ed25519.NewKeyFromSeed(deviceSeed)
	controllerPrivate := ed25519.NewKeyFromSeed(controllerSeed)
	devicePublic := decodeRelayVectorBytes(t, vector.Identities.Device.PublicKey)
	controllerPublic := decodeRelayVectorBytes(t, vector.Identities.Controller.PublicKey)
	if !bytes.Equal(devicePrivate.Public().(ed25519.PublicKey), devicePublic) {
		t.Fatal("device public key does not match deterministic seed")
	}
	if !bytes.Equal(controllerPrivate.Public().(ed25519.PublicKey), controllerPublic) {
		t.Fatal("controller public key does not match deterministic seed")
	}

	deviceAssertion := vector.DeviceAssertion.Value
	deviceCanonical, err := deviceAssertion.signingBytes()
	if err != nil {
		t.Fatal(err)
	}
	assertRelayCanonicalVector(t, deviceCanonical, vector.DeviceAssertion.CanonicalJSON, vector.DeviceAssertion.CanonicalSHA256)
	deviceSignature := deviceAssertion.Signature
	deviceAssertion.Signature = ""
	if err := SignDeviceAssertion(&deviceAssertion, devicePrivate); err != nil {
		t.Fatal(err)
	}
	if deviceAssertion.Signature != deviceSignature {
		t.Fatalf("device assertion signature changed\n got: %s\nwant: %s", deviceAssertion.Signature, deviceSignature)
	}
	if !ed25519.Verify(ed25519.PublicKey(devicePublic), deviceCanonical, decodeRelayVectorBytes(t, deviceSignature)) {
		t.Fatal("device assertion vector signature is invalid")
	}

	controllerAssertion := vector.ControllerAssertion.Value
	controllerCanonical, err := controllerAssertion.signingBytes()
	if err != nil {
		t.Fatal(err)
	}
	assertRelayCanonicalVector(t, controllerCanonical, vector.ControllerAssertion.CanonicalJSON, vector.ControllerAssertion.CanonicalSHA256)
	controllerSignature := controllerAssertion.Signature
	controllerAssertion.Signature = ""
	if err := SignControllerAssertion(&controllerAssertion, controllerPrivate); err != nil {
		t.Fatal(err)
	}
	if controllerAssertion.Signature != controllerSignature {
		t.Fatalf("controller assertion signature changed\n got: %s\nwant: %s", controllerAssertion.Signature, controllerSignature)
	}
	if !ed25519.Verify(ed25519.PublicKey(controllerPublic), controllerCanonical, decodeRelayVectorBytes(t, controllerSignature)) {
		t.Fatal("controller assertion vector signature is invalid")
	}
}

func TestProtocolV1RestartSemanticsVectors(t *testing.T) {
	var vector restartSemanticsVector
	loadRelayVectorFile(t, "restart-semantics.json", &vector)
	if vector.SchemaVersion != 1 || len(vector.Cases) == 0 {
		t.Fatal("invalid restart semantics vector")
	}

	for i, tc := range vector.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			now := time.Unix(1_800_000_000, 0)
			path := filepath.Join(t.TempDir(), "relay-state.json")
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}

			first := durableStoreForTest(t, path, key)
			device, pairing, controllerPrivate, _, controllerSession := durablePairedFixture(t, first, now)
			if controllerSession.AgentSessionID != vector.OriginalAgentSessionID {
				t.Fatalf("fixture session %q does not match vector %q", controllerSession.AgentSessionID, vector.OriginalAgentSessionID)
			}
			requestID := "req-vector-" + tc.ID
			command := signedCommandForPairing(t, pairing, controllerPrivate, controllerSession.AgentSessionID, requestID, "command-vector-"+tc.ID, now)
			if err := first.QueuePairedCommand(pairing.DeviceID, controllerSession.Token, command, now); err != nil {
				t.Fatal(err)
			}

			restartNow := now.Add(time.Duration(tc.AdvanceSeconds) * time.Second)
			second := durableStoreForTest(t, path, key)
			assertion := signedDeviceAssertion(t, device, pairing, restartNow, tc.NextAgentSessionID, "device-vector-"+tc.ID)
			deviceSession, err := second.AuthenticateDevice(assertion, restartNow)
			if err != nil {
				t.Fatal(err)
			}

			switch tc.ExpectedRequestState {
			case "deliverable":
				controllerAssertion := signedControllerAssertion(t, pairing, controllerPrivate, restartNow, "controller-vector-"+tc.ID)
				if _, err := second.AuthenticateController(controllerAssertion, restartNow); err != nil {
					t.Fatal(err)
				}
				next, err := second.NextCommand(context.Background(), pairing.DeviceID, deviceSession.Token, func() time.Time { return restartNow })
				if err != nil {
					t.Fatal(err)
				}
				if next.RequestID != requestID {
					t.Fatalf("next request %q, want %q", next.RequestID, requestID)
				}
			case "pruned":
				if _, err := second.RequestOwner(requestID); !errors.Is(err, ErrUnknownRequest) {
					t.Fatalf("request state %q: %v", tc.ExpectedRequestState, err)
				}
				third := durableStoreForTest(t, path, key)
				if _, err := third.RequestOwner(requestID); !errors.Is(err, ErrUnknownRequest) {
					t.Fatalf("pruned request returned after another restart: %v", err)
				}
			default:
				t.Fatalf("unknown expected_request_state %q for case %d", tc.ExpectedRequestState, i)
			}
		})
	}
}
