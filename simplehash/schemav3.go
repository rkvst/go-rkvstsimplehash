package simplehash

import (
	"encoding/json"
	"fmt"
	"hash"
	"time"

	v2assets "github.com/datatrails/go-datatrails-api/assets/v2/assets"
	"github.com/datatrails/go-datatrails-api/marshalers/simpleoneof"
	"github.com/zeebo/bencode"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// V3Event is a struct that contains ONLY the event fields we want to hash for schema v3
type V3Event struct {
	Identity           string         `json:"identity"`
	EventAttributes    map[string]any `json:"event_attributes"`
	AssetAttributes    map[string]any `json:"asset_attributes"`
	Operation          string         `json:"operation"`
	Behaviour          string         `json:"behaviour"`
	TimestampDeclared  string         `json:"timestamp_declared"`
	TimestampAccepted  string         `json:"timestamp_accepted"`
	TimestampCommitted string         `json:"timestamp_committed"`
	PrincipalAccepted  map[string]any `json:"principal_accepted"`
	PrincipalDeclared  map[string]any `json:"principal_declared"`
	TenantIdentity     string         `json:"tenant_identity"`
}

// ToPublicIdentity converts the identity of the event into a public identity
func (e *V3Event) ToPublicIdentity() {
	e.Identity = v2assets.PublicIdentityFromPermissioned(e.Identity)
}

// SetTimestampCommitted sets the timestamp committed to the given timestamp
func (e *V3Event) SetTimestampCommitted(timestamp *timestamppb.Timestamp) {
	e.TimestampCommitted = timestamp.AsTime().Format(time.RFC3339Nano)
}

func V3HashEvent(hasher hash.Hash, v3Event V3Event) error {

	var err error

	// Note that we _don't_ take any notice of confirmation status.

	// TODO: we ought to be able to avoid this double encode decode, but it is fiddly
	eventJson, err := json.Marshal(v3Event)
	if err != nil {
		return fmt.Errorf("EventSimpleHashV3: failed to marshal event : %v", err)
	}

	var jsonAny any

	if err = json.Unmarshal(eventJson, &jsonAny); err != nil {
		return fmt.Errorf("EventSimpleHashV3: failed to unmarshal events: %v", err)
	}

	bencodeEvent, err := bencode.EncodeBytes(jsonAny)
	if err != nil {
		return fmt.Errorf("EventSimpleHashV3: failed to bencode events: %v", err)
	}

	hasher.Write(bencodeEvent)

	return nil
}

type HasherV3 struct {
	Hasher
}

func NewHasherV3() HasherV3 {

	h := HasherV3{
		Hasher: NewHasher(),
	}
	return h
}

// V3FromEventJSON unmarshals rest api formated json into the event struct
func V3FromEventJSON(eventJson []byte) (V3Event, error) {
	var err error

	eventShashV3 := V3Event{}
	err = json.Unmarshal(eventJson, &eventShashV3)
	if err != nil {
		return V3Event{}, err
	}

	// change all instances of public identities to permissioned identities
	// we only use permissioned identities as part of the v3 hash schema
	eventShashV3.Identity = v2assets.PermissionedIdentityFromPublic(eventShashV3.Identity)

	return eventShashV3, nil
}

// V3FromEventResponse transforms a single event in grpc proto format (message bus
// compatible) to the canonical, publicly verifiable, api format.
func V3FromEventResponse(marshaler *simpleoneof.Marshaler, event *v2assets.EventResponse) (V3Event, error) {
	eventJson, err := marshaler.Marshal(event)
	if err != nil {
		return V3Event{}, err
	}
	return V3FromEventJSON(eventJson)
}

// HashEvent hashes a single event according to the canonical simple hash event
// format available to api consumers. The source event is in the grpc proto buf
// format. GRPC endpoints are not presently exposed by the platform.
//
// Options:
//   - WithIDCommitted prefix the data to hash with the bigendian encoding of
//     idtimestamp before hashing.
//   - WithPrefix is used to provide domain separation, the provided bytes are
//     pre-pended to the data to be hashed.  Eg H(prefix || data)
//     This option can be used multiple times, the prefix bytes are appended to
//     any previously supplied.
//   - WithAccumulate callers wishing to implement batched hashing of multiple
//     events in series should set this. They should call Reset() at their batch
//     boundaries.
//   - WithPublicFromPermissioned should be set if the event is the
//     permissioned (owner) counter part of a public attestation.
//     NOTE: should not be used for valid v3 schema
func (h *HasherV3) HashEvent(event *v2assets.EventResponse, opts ...HashOption) error {

	o := HashOptions{}
	for _, opt := range opts {
		opt(&o)
	}

	v3Event, err := V3FromEventResponse(h.marshaler, event)
	if err != nil {
		return err
	}

	h.applyEventOptions(o, &v3Event)

	h.applyHashingOptions(o)

	return V3HashEvent(h.hasher, v3Event)
}

// HashEventFromJson hashes a single event according to the canonical simple hash event
// format available to api consumers. The source event is in json format.
//
// Options:
//   - WithIDCommitted prefix the data to hash with the bigendian encoding of
//     idtimestamp before hashing.
//   - WithPrefix is used to provide domain separation, the provided bytes are
//     pre-pended to the data to be hashed.  Eg H(prefix || data)
//     This option can be used multiple times, the prefix bytes are appended to
//     any previously supplied.
//   - WithAccumulate callers wishing to implement batched hashing of multiple
//     events in series should set this. They should call Reset() at their batch
//     boundaries.
//   - WithPublicFromPermissioned should be set if the event is the
//     permissioned (owner) counter part of a public attestation.
//     NOTE: should not be used for valid v3 schema
func (h *HasherV3) HashEventFromJSON(eventJson []byte, opts ...HashOption) error {

	o := HashOptions{}
	for _, opt := range opts {
		opt(&o)
	}

	v3Event, err := V3FromEventJSON(eventJson)
	if err != nil {
		return err
	}

	h.applyEventOptions(o, &v3Event)

	h.applyHashingOptions(o)

	return V3HashEvent(h.hasher, v3Event)
}

// HashEventFromV3 hashes a single event according to the canonical simple hash event
// format available to api consumers. The source event a pre decoded V3Event type
// Options: same as HashEventFromJSON
func (h *HasherV3) HashEventFromV3(v3Event V3Event, opts ...HashOption) error {

	o := HashOptions{}
	for _, opt := range opts {
		opt(&o)
	}

	h.applyEventOptions(o, &v3Event)

	h.applyHashingOptions(o)

	return V3HashEvent(h.hasher, v3Event)
}
