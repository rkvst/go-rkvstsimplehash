package simplehash

import (
	"encoding/binary"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// These options are not part of the event schema. The can be used to adjust how
// the schema is applied to produce a hash for  different purposes.

type HashOptions struct {
	accumulateHash         bool
	publicFromPermissioned bool
	asConfirmed            bool
	prefix                 []byte
	committed              *timestamppb.Timestamp
	idcommitted            []byte
}

type HashOption func(*HashOptions)

// WithIDCommitted includes the snowflakeid unique commitment timestamp in the hash
// idcommitted is never (legitimately) zero
func WithIDCommitted(idcommitted uint64) HashOption {
	return func(o *HashOptions) {
		o.idcommitted = make([]byte, 8)
		binary.BigEndian.PutUint64(o.idcommitted, idcommitted)
	}
}

// WithPrefix pre-pends the provided bytes to the hash. This option can be used
// multiple times and the successive bytes are appended to the prefix. This is
// typically used to provide hash domain seperation where second pre-image
// collisions are a concerne.
func WithPrefix(b []byte) HashOption {
	return func(o *HashOptions) {
		o.prefix = append(o.prefix, b...)
	}
}

func WithTimestampCommitted(committed *timestamppb.Timestamp) HashOption {
	return func(o *HashOptions) {
		o.committed = committed
	}
}

func WithAccumulate() HashOption {
	return func(o *HashOptions) {
		o.accumulateHash = true
	}
}

func WithPublicFromPermissioned() HashOption {
	return func(o *HashOptions) {
		o.publicFromPermissioned = true
	}
}

func WithAsConfirmed() HashOption {
	return func(o *HashOptions) {
		o.asConfirmed = true
	}
}
