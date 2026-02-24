package node

import "encoding/json"

// MessageType indicates what the decrypted payload contains.
type MessageType string

const (
	// MsgTypeDirect is a message directly addressed to the recipient.
	MsgTypeDirect MessageType = "msg"

	// MsgTypeForward wraps an inner packet for re-broadcast.
	// The relay decrypts the outer layer, extracts the inner packet,
	// and injects it into the broadcast stream — indistinguishable from
	// any other locally-originated packet. This hides the sender's IP.
	MsgTypeForward MessageType = "forward"

	// MsgTypeDirectoryEntry carries a key directory registration.
	MsgTypeDirectoryEntry MessageType = "directory"
)

// Envelope is the JSON structure inside every encrypted payload.
type Envelope struct {
	Type    MessageType `json:"type"`
	From    string      `json:"from,omitempty"`    // sender's enc_pub hex (optional)
	Content string      `json:"content,omitempty"` // plaintext message body
	Inner   []byte      `json:"inner,omitempty"`   // inner packet bytes for MsgTypeForward
}

func marshalEnvelope(e Envelope) ([]byte, error) {
	return json.Marshal(e)
}

func unmarshalEnvelope(b []byte) (Envelope, error) {
	var e Envelope
	return e, json.Unmarshal(b, &e)
}
