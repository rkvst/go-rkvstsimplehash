package simplehash

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	v2assets "github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	expectedHashAllV3 = "c52caf06bf525ae7e2fde8e08e2d2cac30ceb8b9f761503d7f671213b07fc576"
)

func TestHasherV3_HashEvent(t *testing.T) {
	type fields struct {
		Hasher Hasher
	}
	type args struct {
		events []*v2assets.EventResponse
		opts   []HashOption
	}
	tests := []struct {
		name         string
		fields       fields
		args         args
		wantErr      bool
		expectedHash string
	}{
		{
			"valid events [:1] (both together)",
			fields{
				Hasher: Hasher{
					sha256.New(),
					NewEventMarshaler(),
				},
			},
			args{
				validEventsV2,
				[]HashOption{WithAccumulate()},
			},
			false,
			expectedHashAllV3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &HasherV3{
				Hasher: tt.fields.Hasher,
			}
			for _, event := range tt.args.events {
				if err := h.HashEvent(event, tt.args.opts...); (err != nil) != tt.wantErr {
					t.Errorf("HasherV3.HashEvent() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
			if tt.expectedHash == "" {
				return
			}
			actualHash := hex.EncodeToString(h.Hasher.Sum(nil))
			assert.Equal(t, tt.expectedHash, actualHash)
		})
	}
}

// TestV3Event_SetTimestampCommitted tests:
//
// 1. setting the timestamp gives the correctly formatted timestamp in the v3event
func TestV3Event_SetTimestampCommitted(t *testing.T) {
	type args struct {
		timestamp *timestamppb.Timestamp
	}
	tests := []struct {
		name              string
		originalTimestamp string
		args              args
		expected          string
	}{
		{
			name:              "positive",
			originalTimestamp: "2023-02-23T10:11:08.761Z",
			args: args{
				timestamp: timestamppb.New(time.Unix(1706700559, 43000000)),
			},
			expected: "2024-01-31T11:29:19.043Z",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := &V3Event{
				TimestampCommitted: test.originalTimestamp,
			}

			e.SetTimestampCommitted(test.args.timestamp)

			assert.Equal(t, test.expected, e.TimestampCommitted)
		})
	}
}

// TestV3Event_ToPublicIdentity tests:
//
// 1. that identity convert correctly to the public identity.
func TestV3Event_ToPublicIdentity(t *testing.T) {
	type fields struct {
		Identity string
	}
	tests := []struct {
		name      string
		fields    fields
		eIdentity string
	}{
		{
			name: "positive",
			fields: fields{
				Identity: "assets/9ccdc19b-44a1-434c-afab-14f8eac3405c/events/e76a03d1-19a5-4f11-bcaf-383bb4f1dfd4",
			},
			eIdentity: "publicassets/9ccdc19b-44a1-434c-afab-14f8eac3405c/events/e76a03d1-19a5-4f11-bcaf-383bb4f1dfd4",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := &V2Event{
				Identity: test.fields.Identity,
			}
			e.ToPublicIdentity()

			assert.Equal(t, test.eIdentity, e.Identity)
		})
	}
}

// TestV3FromEventJSON tests:
//
// 1. permissioned event is correctly interpretted into a v3event.
// 2. public event is correctly interpretted into a v3event.
func TestV3FromEventJSON(t *testing.T) {
	type args struct {
		eventJson []byte
	}
	tests := []struct {
		name     string
		args     args
		expected V3Event
		err      error
	}{
		{
			name: "positive permissioned",
			args: args{
				eventJson: []byte(`{"identity":"assets/1234/events/5678"}`),
			},
			expected: V3Event{
				Identity: "assets/1234/events/5678",
			},
			err: nil,
		},
		{
			name: "positive public",
			args: args{
				eventJson: []byte(`{"identity":"publicassets/1234/events/5678"}`),
			},
			expected: V3Event{
				Identity: "assets/1234/events/5678",
			},
			err: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := V3FromEventJSON(test.args.eventJson)

			assert.Equal(t, test.err, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}

// TestV3FromEventResponse tests:
//
// 1. permissioned event is correctly interpretted into a v3event.
// 2. public event is correctly interpretted into a v3event.
func TestV3FromEventResponse(t *testing.T) {
	type args struct {
		event *v2assets.EventResponse
	}
	tests := []struct {
		name     string
		args     args
		expected V3Event
		err      error
	}{
		{
			name: "positive permissioned",
			args: args{
				event: &v2assets.EventResponse{Identity: "assets/1234/events/5678"},
			},
			expected: V3Event{
				Identity: "assets/1234/events/5678",
			},
			err: nil,
		},
		{
			name: "positive public",
			args: args{
				event: &v2assets.EventResponse{Identity: "publicassets/1234/events/5678"},
			},
			expected: V3Event{
				Identity: "assets/1234/events/5678",
			},
			err: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := V3FromEventResponse(NewEventMarshaler(), test.args.event)

			assert.Equal(t, test.err, err)
			assert.Equal(t, test.expected.Identity, actual.Identity)
		})
	}
}
