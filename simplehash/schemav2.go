package simplehash

// Public go lang implementation of the simplehash RKVST event encoding scheme

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"

	v2assets "github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/datatrails/go-datatrails-common-api-gen/marshalers/simpleoneof"
	"github.com/zeebo/bencode"
)

var (
	ErrInvalidOption = errors.New("option not supported by this method")
)

type HasherV2 struct {
	hasher    hash.Hash
	marshaler *simpleoneof.Marshaler
}

func NewHasherV2() HasherV2 {
	h := HasherV2{
		hasher:    sha256.New(),
		marshaler: NewEventMarshaler(),
	}
	return h
}

// Reset resets the hasher state
// This is only useful in combination with WithAccumulate
func (h *HasherV2) Reset() { h.hasher.Reset() }

// HashEvent hashes a single event according to the canonical simple hash event
// format available to api consumers. The source event is in the grpc proto buf
// format. GRPC endpoints are not presently exposed by the platform.
//
// Options:
//   - WithTimestampCommitted set the timestamp_commited before hashing
//   - WithPrefix is used to provide domain seperation, the provided bytes are
//     pre-pended to the data to be hashed.  Eg H(prefix || data)
//     This option can be used multiple times, the prefix bytes are appended to
//     any previously supplied.
//   - WithAccumulate callers wishing to implement batched hashing of multiple
//     events in series should set this. They should call Reset() at their batch
//     boundaries.
//   - WithPublicFromPermissioned should be set if the event is the
//     permissioned (owner) counter part of a public attestation.
//   - WithAsConfirmed should be set if the caller is implementing CONFIRMATION
//     as part of an evidence subsystem implementation. The expectation is that
//     the caller has a PENDING record to hand, and is in the process of
//     creating the CONFIRMED record. It is the CONFIRMED record that needs to
//     be publicly verifiable.
func (h *HasherV2) HashEvent(event *v2assets.EventResponse, opts ...HashOption) error {
	o := HashOptions{}
	for _, opt := range opts {
		opt(&o)
	}

	var err error

	// By default, one hash at at time with a reset.
	if !o.accumulateHash {
		h.hasher.Reset()
	}

	if len(o.prefix) != 0 {
		h.hasher.Write(o.prefix)
	}

	if o.publicFromPermissioned {
		PublicFromPermissionedEvent(event)
	}

	// If the caller is responsible for evidence confirmation they will have a
	// pending event in their hand. But ultimately it is the confirmed record
	// that is evidential and subject to public verification.
	if o.asConfirmed {
		event.ConfirmationStatus = v2assets.ConfirmationStatus_CONFIRMED
	}

	// force the commited time in the hash. only useful to the service that is
	// actually doing the committing. public consumers only ever see confirmed
	// events with the timestamp already in place.
	if o.committed != nil {
		event.TimestampCommitted = o.committed
	}

	// Note that we _don't_ take any notice of confirmation status.

	v2Event, err := V2FromEventResponse(h.marshaler, event)
	if err != nil {
		return err
	}

	// If the idcommitted is provided, add it to the hash first
	if o.idcommitted != nil {
		h.hasher.Write(o.idcommitted)
	}

	return V2HashEvent(h.hasher, v2Event)
}

// HashEventJSON hashes a single event according to the canonical simple hash
// event format available to api consumers. The source event data is in the form
// returned by our apis
//
// Options:
//   - WithAccumulate callers wishing to implement batched hashing of multiple
//     events in series should set this. They should call Reset() at their batch
//     boundaries.
//   - WithAsConfirmed should be set if the caller wishes to anticipate the hash
//     of a confirmed event based on a pending response
func (h *HasherV2) HashEventJSON(event []byte, opts ...HashOption) error {
	o := HashOptions{}
	for _, opt := range opts {
		opt(&o)
	}

	var err error

	// By default, one hash at at time with a reset.
	if !o.accumulateHash {
		h.hasher.Reset()
	}

	if o.publicFromPermissioned {
		// It is api response data, so the details of protected vs public should already have been dealt with.
		return ErrInvalidOption
	}

	v2Event, err := V2FromEventJSON(event)
	if err != nil {
		return err
	}

	// If the caller is responsible for evidence confirmation they will have a
	// pending event in their hand. But ultimately it is the confirmed record
	// that is evidential and subject to public verification.
	if o.asConfirmed {
		// TODO: This probably is also not legit for an api consumer, but it
		// does let the customer *anticipate* the hash and check we produce the
		// correct one.
		v2Event.ConfirmationStatus = v2assets.ConfirmationStatus_name[int32(v2assets.ConfirmationStatus_CONFIRMED)]
	}

	// If the idcommitted is provided, add it to the hash first
	if o.idcommitted != nil {
		h.hasher.Write(o.idcommitted)
	}

	return V2HashEvent(h.hasher, v2Event)
}

func (h *HasherV2) Sum() []byte {
	return h.hasher.Sum(nil)
}

// V2Event is a struct that contains ONLY the event fields we want to hash for schema v2
type V2Event struct {
	Identity           string         `json:"identity"`
	AssetIdentity      string         `json:"asset_identity"`
	EventAttributes    map[string]any `json:"event_attributes"`
	AssetAttributes    map[string]any `json:"asset_attributes"`
	Operation          string         `json:"operation"`
	Behaviour          string         `json:"behaviour"`
	TimestampDeclared  string         `json:"timestamp_declared"`
	TimestampAccepted  string         `json:"timestamp_accepted"`
	TimestampCommitted string         `json:"timestamp_committed"`
	PrincipalAccepted  map[string]any `json:"principal_accepted"`
	PrincipalDeclared  map[string]any `json:"principal_declared"`
	ConfirmationStatus string         `json:"confirmation_status"`
	From               string         `json:"from"`
	TenantIdentity     string         `json:"tenant_identity"`
}

// NewEventMarshaler creates a flat marshaler to transform events to api format.
//
// otherwise attributes look like this: {"foo":{"str_val": "bar"}} instead of {"foo": "bar"}
// this mimics the public list events api response, so minimises changes to the
// public api response, to reproduce the anchor
func NewEventMarshaler() *simpleoneof.Marshaler {
	return v2assets.NewFlatMarshalerForEvents()
}

// V2FromEventJSON unmarshals rest api formated json into the event struct
func V2FromEventJSON(eventJson []byte) (V2Event, error) {
	var err error

	eventShashV2 := V2Event{}
	err = json.Unmarshal(eventJson, &eventShashV2)
	if err != nil {
		return V2Event{}, err
	}
	return eventShashV2, nil
}

// V2FromEventResponse transforms a single event in grpc proto format (message bus
// compatible) to the canonical, publicly verifiable, api format.
func V2FromEventResponse(marshaler *simpleoneof.Marshaler, event *v2assets.EventResponse) (V2Event, error) {
	eventJson, err := marshaler.Marshal(event)
	if err != nil {
		return V2Event{}, err
	}
	return V2FromEventJSON(eventJson)
}

// PublicFromPermissionedEvent translates the permissioned event and asset identities to
// their public counter parts.
func PublicFromPermissionedEvent(event *v2assets.EventResponse) {
	event.Identity = v2assets.PublicIdentityFromPermissioned(event.Identity)
	event.AssetIdentity = v2assets.PublicIdentityFromPermissioned(event.AssetIdentity)
}

// EventSimpleHashV2 hashes a single event according to the canonical simple hash event format
// available to api consumers.
//
//   - If the event is the permissioned (owner) counter part of a public
//     attestation, you must call PublicFromPermissionedEvent first.
//   - No special treatment is given to confirmation status (PENDING vs
//     CONFIRMED). Because the rules for forestrie and PENDING events are *NOT
//     THE SAME* as those for proof_mechanism simplehash.
func EventSimpleHashV2(hasher hash.Hash, marshaler *simpleoneof.Marshaler, event *v2assets.EventResponse) error {

	var err error

	// Note that we _don't_ take any notice of confirmation status.

	v2Event, err := V2FromEventResponse(marshaler, event)
	if err != nil {
		return err
	}

	return V2HashEvent(hasher, v2Event)
}

func V2HashEvent(hasher hash.Hash, v2Event V2Event) error {

	var err error

	// Note that we _don't_ take any notice of confirmation status.

	// XXX: TODO I don't think the following step is necessary (we should get snake case due to the struct tags)
	//    we get the correct fields by the definition of our structure, but we need to marshal and unmarshal our struct
	//    into a generic []any, in order to get the correct field names, otherwise they would be camelcase
	eventJson, err := json.Marshal(v2Event)
	if err != nil {
		return fmt.Errorf("EventSimpleHashV2: failed to marshal event : %v", err)
	}

	var jsonAny any

	if err = json.Unmarshal(eventJson, &jsonAny); err != nil {
		return fmt.Errorf("EventSimpleHashV2: failed to unmarshal events: %v", err)
	}

	bencodeEvent, err := bencode.EncodeBytes(jsonAny)
	if err != nil {
		return fmt.Errorf("EventSimpleHashV2: failed to bencode events: %v", err)
	}

	hasher.Write(bencodeEvent)
	return nil
}
