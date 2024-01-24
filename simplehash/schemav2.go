package simplehash

// Public go lang implementation of the simplehash DataTrails event encoding scheme

import (
	"encoding/json"
	"fmt"
	"hash"

	v2assets "github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/datatrails/go-datatrails-common-api-gen/marshalers/simpleoneof"
	"github.com/zeebo/bencode"
)

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

type HasherV2 struct {
	Hasher
}

func NewHasherV2() HasherV2 {

	h := HasherV2{
		Hasher: NewHasher(),
	}
	return h
}

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
//     be publicly verifiable.
func (h *HasherV2) HashEvent(event *v2assets.EventResponse, opts ...HashOption) error {
	o := HashOptions{}
	for _, opt := range opts {
		opt(&o)
	}

	h.Hasher.applyEventOptions(o, event)

	// Note that we _don't_ take any notice of confirmation status.

	v2Event, err := V2FromEventResponse(h.marshaler, event)
	if err != nil {
		return err
	}

	// Hash data accumulation starts here
	h.Hasher.applyHashingOptions(o)

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
	if o.publicFromPermissioned {
		// It is api response data, so the details of protected vs public should already have been dealt with.
		return ErrInvalidOption
	}

	v2Event, err := V2FromEventJSON(event)
	if err != nil {
		return err
	}

	h.Hasher.applyHashingOptions(o)

	return V2HashEvent(h.hasher, v2Event)
}

func (h *HasherV2) Sum() []byte {
	return h.hasher.Sum(nil)
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
