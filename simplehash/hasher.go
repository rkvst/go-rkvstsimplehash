package simplehash

import (
	"crypto/sha256"
	"hash"

	v2assets "github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/datatrails/go-datatrails-common-api-gen/marshalers/simpleoneof"
)

type Hasher struct {
	hasher    hash.Hash
	marshaler *simpleoneof.Marshaler
}

func NewHasher() Hasher {
	h := Hasher{
		hasher:    sha256.New(),
		marshaler: NewEventMarshaler(),
	}
	return h
}

func (h *Hasher) Sum(b []byte) []byte { return h.hasher.Sum(b) }

// Reset resets the hasher state
// This is only useful in combination with WithAccumulate
func (h *Hasher) Reset() { h.hasher.Reset() }

// NewEventMarshaler creates a flat marshaler to transform events to api format.
//
// otherwise attributes look like this: {"foo":{"str_val": "bar"}} instead of {"foo": "bar"}
// this mimics the public list events api response, so minimises changes to the
// public api response, to reproduce the anchor
func NewEventMarshaler() *simpleoneof.Marshaler {
	return v2assets.NewFlatMarshalerForEvents()
}

func (h *Hasher) applyEventOptions(o HashOptions, event *v2assets.EventResponse) {
	if o.publicFromPermissioned {
		PublicFromPermissionedEvent(event)
	}

	// force the commited time in the hash. only useful to the service that is
	// actually doing the committing. public consumers only ever see confirmed
	// events with the timestamp already in place.
	if o.committed != nil {
		event.TimestampCommitted = o.committed
	}
}

func (h *Hasher) applyHashingOptions(o HashOptions) {

	// By default, one hash at at time with a reset.
	if !o.accumulateHash {
		h.hasher.Reset()
	}

	// If the prefix is provided it must be first.
	if len(o.prefix) != 0 {
		h.hasher.Write(o.prefix)
	}

	// If the idcommitted is provided, add it to the hash immediately before the
	// event data.
	if o.idcommitted != nil {
		h.hasher.Write(o.idcommitted)
	}
}
