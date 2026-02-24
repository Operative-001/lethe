// Package directory maintains the local key directory — a mapping of
// human-readable names to X25519 public keys.
//
// The directory is replicated across all nodes via the broadcast stream.
// Every node holds a complete local copy; no query ever leaves the node.
// Directory entries are signed by the registering identity so fakes are rejected.
package directory

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucketEntries = []byte("entries")

// Entry is a signed directory record broadcast to all nodes.
type Entry struct {
	Name      string `json:"name"`       // human-readable label
	EncPub    string `json:"enc_pub"`    // X25519 pubkey hex (the network address)
	SignPub   string `json:"sign_pub"`   // Ed25519 pubkey hex (for signature verification)
	Timestamp int64  `json:"timestamp"`  // Unix seconds; newer entries replace older ones
	Sig       []byte `json:"sig"`        // Ed25519 signature over canonical JSON (sans sig)
}

// canonical returns the bytes that must be signed: JSON without the sig field.
func (e *Entry) canonical() ([]byte, error) {
	type canon struct {
		Name      string `json:"name"`
		EncPub    string `json:"enc_pub"`
		SignPub   string `json:"sign_pub"`
		Timestamp int64  `json:"timestamp"`
	}
	return json.Marshal(canon{e.Name, e.EncPub, e.SignPub, e.Timestamp})
}

// Verify checks the entry's signature.
func (e *Entry) Verify() error {
	pubBytes, err := hex.DecodeString(e.SignPub)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return errors.New("directory: invalid sign_pub")
	}
	canonical, err := e.canonical()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), canonical, e.Sig) {
		return errors.New("directory: signature verification failed")
	}
	return nil
}

// Sign signs the entry using the provided Ed25519 private key.
func (e *Entry) Sign(priv ed25519.PrivateKey) error {
	e.Timestamp = time.Now().Unix()
	canonical, err := e.canonical()
	if err != nil {
		return err
	}
	e.Sig = ed25519.Sign(priv, canonical)
	return nil
}

// Directory is a persistent local key store backed by bbolt.
type Directory struct {
	db *bolt.DB
}

// New opens (or creates) a directory database at the given path.
func New(path string) (*Directory, error) {
	db, err := bolt.Open(path+"/directory.db", 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketEntries)
		return err
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Directory{db: db}, nil
}

// Close closes the underlying database.
func (d *Directory) Close() error {
	return d.db.Close()
}

// Add inserts or updates an entry after verifying its signature.
// Entries with older timestamps are silently ignored.
func (d *Directory) Add(e *Entry) error {
	if err := e.Verify(); err != nil {
		return err
	}
	return d.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bucketEntries)
		key := []byte(e.Name)

		// Check existing entry timestamp
		if existing := bkt.Get(key); existing != nil {
			var old Entry
			if json.Unmarshal(existing, &old) == nil && old.Timestamp >= e.Timestamp {
				return nil // not newer; ignore
			}
		}

		data, err := json.Marshal(e)
		if err != nil {
			return err
		}
		return bkt.Put(key, data)
	})
}

// Lookup finds an entry by name. Returns nil if not found.
func (d *Directory) Lookup(name string) *Entry {
	var e Entry
	err := d.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bucketEntries)
		data := bkt.Get([]byte(name))
		if data == nil {
			return errors.New("not found")
		}
		return json.Unmarshal(data, &e)
	})
	if err != nil {
		return nil
	}
	return &e
}

// LookupByKey finds an entry by its encryption public key hex.
func (d *Directory) LookupByKey(encPubHex string) *Entry {
	var found *Entry
	d.db.View(func(tx *bolt.Tx) error { //nolint:errcheck
		bkt := tx.Bucket(bucketEntries)
		return bkt.ForEach(func(_, v []byte) error {
			var e Entry
			if json.Unmarshal(v, &e) == nil && e.EncPub == encPubHex {
				found = &e
				return errors.New("stop") // break ForEach
			}
			return nil
		})
	})
	return found
}

// All returns every entry in the directory.
func (d *Directory) All() []Entry {
	var out []Entry
	d.db.View(func(tx *bolt.Tx) error { //nolint:errcheck
		return tx.Bucket(bucketEntries).ForEach(func(_, v []byte) error {
			var e Entry
			if json.Unmarshal(v, &e) == nil {
				out = append(out, e)
			}
			return nil
		})
	})
	return out
}
