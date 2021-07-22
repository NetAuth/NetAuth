// +build !windows

package bitcask

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-hclog"
	"git.mills.io/prologic/bitcask"
	"github.com/spf13/viper"

	"github.com/netauth/netauth/internal/db"
	"github.com/netauth/netauth/internal/startup"
)

func init() {
	startup.RegisterCallback(cb)
}

func cb() {
	db.RegisterKV("bitcask", New)
}

// BCStore is a store implementation based on the bitcask storage
// engine.
type BCStore struct {
	s *bitcask.Bitcask
	l hclog.Logger

	eF func(db.Event)
}

// event is an enum for what type of event to fire and subsequently
// map to a DB event.
type eventType int

const (
	eventUpdate eventType = iota
	eventDelete
)

// New creates a new instance of the bitcask store.
func New(l hclog.Logger) (db.KVStore, error) {
	p := filepath.Join(viper.GetString("core.home"), "bc")

	x := &BCStore{}
	x.l = l.Named("bitcask")
	opts := []bitcask.Option{
		bitcask.WithMaxKeySize(1024),
		bitcask.WithMaxValueSize(1024 * 1000 * 5), // 5MiB
		bitcask.WithSync(true),
	}
	b, err := bitcask.Open(p, opts...)
	if err != nil {
		return nil, err
	}
	x.s = b
	return x, nil
}

// Put stores the bytes of v at a location identitified by the key k.
// If the operation fails an error will be returned explaining why.
func (bcs *BCStore) Put(k string, v []byte) error {
	if err := bcs.s.Put([]byte(k), v); err != nil {
		return err
	}
	bcs.fireEventForKey(k, eventUpdate)
	return nil
}

// Get returns the key at k or an error explaning why no data was
// returned.
func (bcs *BCStore) Get(k string) ([]byte, error) {
	v, err := bcs.s.Get([]byte(k))
	switch err {
	case nil:
		return v, nil
	default:
		return nil, db.ErrNoValue
	}
}

// Del removes any existing value at the location specified by the
// provided key.
func (bcs *BCStore) Del(k string) error {
	// I can come up with nothing that causes this delete call to
	// fail, up to and including nuking the entire data directory.
	// If you can write a way to check this error and its
	// associated test, open a PR.
	bcs.s.Delete([]byte(k))
	bcs.fireEventForKey(k, eventDelete)
	return nil
}

// Keys is a way to enumerate the keys in the key/value store and to
// optionally filter them based on a globbing expression.  This cheats
// and uses superior knowledge that NetAuth uses only a single key
// namespace with a single layer of keys below it.  Its technically
// possible to do something dumb with an entity or group name that
// includes a path seperator, but this should be filtered out at a
// higher level.
func (bcs *BCStore) Keys(f string) ([]string, error) {
	out := []string{}
	for bk := range bcs.s.Keys() {
		k := string(bk)
		if m, _ := path.Match(f, k); m {
			out = append(out, k)
		}
	}
	return out, nil
}

// Close terminates the connection to the bitcask and flushes it to
// disk.  The cask must not be used after Close() is called.
func (bcs *BCStore) Close() error {
	return bcs.s.Close()
}

// Capabilities returns that this key/value store supports te mutable
// property, allowing it to be writeable to the higher level systems.
func (bcs *BCStore) Capabilities() []db.KVCapability {
	return []db.KVCapability{db.KVMutable}
}

// fireEventForKey maps from a key to an entity or group and fires an
// appropriate event for the given key.
func (bcs *BCStore) fireEventForKey(k string, t eventType) {
	switch {
	case t == eventUpdate && strings.HasPrefix(k, "/entities/"):
		bcs.eF(db.Event{
			PK:   filepath.Base(k),
			Type: db.EventEntityUpdate,
		})
	case t == eventDelete && strings.HasPrefix(k, "/entities/"):
		bcs.eF(db.Event{
			PK:   filepath.Base(k),
			Type: db.EventEntityDestroy,
		})
	case t == eventUpdate && strings.HasPrefix(k, "/groups/"):
		bcs.eF(db.Event{
			PK:   filepath.Base(k),
			Type: db.EventGroupUpdate,
		})
	case t == eventDelete && strings.HasPrefix(k, "/groups/"):
		bcs.eF(db.Event{
			PK:   filepath.Base(k),
			Type: db.EventGroupDestroy,
		})
	default:
		bcs.l.Warn("Event translation called with unknown key prefix", "type", t, "key", k)
	}
}

// SetEventFunc sets up a function to call to fire events to
// subscribers.
func (bcs *BCStore) SetEventFunc(f func(db.Event)) {
	bcs.eF = f
}
