package simplehash

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"testing"
	"time"

	v2assets "github.com/datatrails/go-datatrails-api/assets/v2/assets"
	"github.com/datatrails/go-datatrails-api/attribute/v2/attribute"
	"github.com/datatrails/go-datatrails-api/marshalers/simpleoneof"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	// Note these events correspond to the VALID_EVENTS in
	// https://github.com/datatrails/datatrails-simplehash-python/blob/main/unittests/constants.py

	expectedHashAllV2 = "61211c916cd113a1cf424ac729924de46aa6259919825dbdf8ec78c5c14665e2"
	expectedHashesV2  = []string{
		"681458c64f5ca35717e69df83c392c5f671a71c18f7830ccae676edfdb7179f1",
		"19111226f169ee67b41265aa27dc3792bf10ca463bc873361cae27d7e1bd6786",
	}

	validEventsV2 = []*v2assets.EventResponse{
		// SimpleHashV2: "681458c64f5ca35717e69df83c392c5f671a71c18f7830ccae676edfdb7179f1"
		{
			Identity:      "assets/03c60f22-588c-4f12-b3c2-e98c7f2e98a0/events/409ae05a-183d-4e55-8aa6-889159edefd3",
			AssetIdentity: "assets/03c60f22-588c-4f12-b3c2-e98c7f2e98a0",
			EventAttributes: map[string]*attribute.Attribute{
				"foo": {
					Value: &attribute.Attribute_StrVal{
						StrVal: "bar",
					},
				},
			},
			AssetAttributes: map[string]*attribute.Attribute{
				"fab": {
					Value: &attribute.Attribute_StrVal{
						StrVal: "baz",
					},
				},
			},
			Operation:          "Record",
			Behaviour:          "RecordEvidence",
			TimestampDeclared:  &timestamp.Timestamp{Seconds: 1665926090},
			TimestampAccepted:  &timestamp.Timestamp{Seconds: 1665926095},
			TimestampCommitted: &timestamp.Timestamp{Seconds: 1665926099},
			PrincipalDeclared: &v2assets.Principal{
				Issuer:      "https://rkvt.com",
				Subject:     "117303158125148247777",
				DisplayName: "William Defoe",
				Email:       "WilliamDefoe@rkvst.com",
			},
			PrincipalAccepted: &v2assets.Principal{
				Issuer:      "https://rkvt.com",
				Subject:     "117303158125148247777",
				DisplayName: "William Defoe",
				Email:       "WilliamDefoe@rkvst.com",
			},
			ConfirmationStatus: v2assets.ConfirmationStatus_CONFIRMED,
			From:               "0xf8dfc073650503aeD429E414bE7e972f8F095e70",
			TenantIdentity:     "tenant/0684984b-654d-4301-ad10-a508126e187d",
			MerklelogEntry:     &v2assets.MerkleLogEntry{},
		},
		{
			Identity:      "assets/a987b910-f567-4cca-9869-bbbeb12aec20/events/936ba508-ee65-426d-8903-52c59cb4655b",
			AssetIdentity: "assets/a987b910-f567-4cca-9869-bbbeb12aec20",
			EventAttributes: map[string]*attribute.Attribute{
				"make": {
					Value: &attribute.Attribute_StrVal{
						StrVal: "volvo",
					},
				},
			},
			AssetAttributes: map[string]*attribute.Attribute{
				"vehicle": {
					Value: &attribute.Attribute_StrVal{
						StrVal: "car",
					},
				},
			},
			Operation:          "Record",
			Behaviour:          "RecordEvidence",
			TimestampDeclared:  &timestamp.Timestamp{Seconds: 1665126090},
			TimestampAccepted:  &timestamp.Timestamp{Seconds: 1665126095},
			TimestampCommitted: &timestamp.Timestamp{Seconds: 1665126099},
			PrincipalDeclared: &v2assets.Principal{
				Issuer:      "https://rkvt.com",
				Subject:     "227303158125148248888",
				DisplayName: "John Cena",
				Email:       "JohnCena@rkvst.com",
			},
			PrincipalAccepted: &v2assets.Principal{
				Issuer:      "https://rkvt.com",
				Subject:     "227303158125148248888",
				DisplayName: "John Cena",
				Email:       "JohnCena@rkvst.com",
			},
			ConfirmationStatus: v2assets.ConfirmationStatus_CONFIRMED,
			From:               "0xa453a973650503aeD429E414bE7e972f8F095f81",
			TenantIdentity:     "tenant/0684984b-654d-4301-ad10-a508126e187d",
		},
		// "19111226f169ee67b41265aa27dc3792bf10ca463bc873361cae27d7e1bd6786",
	}
)

// TestV2Event_SetTimestampCommitted tests:
//
// 1. setting the timestamp gives the correctly formatted timestamp in the v2event
func TestV2Event_SetTimestampCommitted(t *testing.T) {
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
			e := &V2Event{
				TimestampCommitted: test.originalTimestamp,
			}

			e.SetTimestampCommitted(test.args.timestamp)

			assert.Equal(t, test.expected, e.TimestampCommitted)
		})
	}
}

func TestEventSimpleHashV2(t *testing.T) {
	type args struct {
		hasher    hash.Hash
		marshaler *simpleoneof.Marshaler
		event     *v2assets.EventResponse
	}
	tests := []struct {
		name       string
		args       args
		wantErr    bool
		expectHash string
	}{
		// Note these events correspond to the VALID_EVENTS in
		// https://github.com/datatrails/datatrails-simplehash-python/blob/main/unittests/constants.py
		// @39ec71e744cf0cff44d2e60142308e0669687901
		{
			"VALID_EVENTS[0]",
			args{
				sha256.New(),
				NewEventMarshaler(),
				validEventsV2[0],
			},
			false,
			expectedHashesV2[0],
		},
		{
			"VALID_EVENTS[1]",
			args{
				sha256.New(),
				NewEventMarshaler(),
				validEventsV2[1],
			},
			false,
			expectedHashesV2[1],
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := EventSimpleHashV2(tt.args.hasher, tt.args.marshaler, tt.args.event); (err != nil) != tt.wantErr {
				t.Errorf("EventSimpleHashV2() error = %v, wantErr %v", err, tt.wantErr)
			}

			actualHash := hex.EncodeToString(tt.args.hasher.Sum(nil))
			assert.Equal(t, tt.expectHash, actualHash)
		})
	}
}

func TestHasherV2_HashEvent(t *testing.T) {
	type fields struct {
		hasher    hash.Hash
		marshaler *simpleoneof.Marshaler
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
		// Test the accumulate case
		{
			"valid events [:1] (both together)",
			fields{
				sha256.New(),
				NewEventMarshaler(),
			},
			args{
				validEventsV2,
				[]HashOption{WithAccumulate()},
			},
			false,
			expectedHashAllV2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &HasherV2{
				Hasher: Hasher{
					hasher:    tt.fields.hasher,
					marshaler: tt.fields.marshaler,
				},
			}
			for _, event := range tt.args.events {
				if err := h.HashEvent(event, tt.args.opts...); (err != nil) != tt.wantErr {
					t.Errorf("HasherV2.HashEvent() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
			actualHash := hex.EncodeToString(h.Sum())
			assert.Equal(t, tt.expectedHash, actualHash)
		})
	}
}

func TestHasherV2_HashEventJSON(t *testing.T) {
	type fields struct {
		hasher    hash.Hash
		marshaler *simpleoneof.Marshaler
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
		// Test the accumulate case
		{
			"valid events [:1] (both together)",
			fields{
				sha256.New(),
				NewEventMarshaler(),
			},
			args{
				validEventsV2,
				[]HashOption{WithAccumulate()},
			},
			false,
			expectedHashAllV2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error

			h := &HasherV2{
				Hasher: Hasher{
					hasher:    tt.fields.hasher,
					marshaler: tt.fields.marshaler,
				},
			}
			for _, event := range tt.args.events {
				var eventJson []byte
				if eventJson, err = tt.fields.marshaler.Marshal(event); (err != nil) != tt.wantErr {
					t.Errorf("mashaling event for test error = %v, wantErr %v", err, tt.wantErr)
				}

				if err = h.HashEventJSON(eventJson, tt.args.opts...); (err != nil) != tt.wantErr {
					t.Errorf("HasherV2.HashEvent() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
			actualHash := hex.EncodeToString(h.Sum())
			assert.Equal(t, tt.expectedHash, actualHash)
		})
	}
}

// TestV2Event_ToPublicIdentity tests:
//
// 1. that both identity and asset identity convert correctly to the public identity.
func TestV2Event_ToPublicIdentity(t *testing.T) {
	type fields struct {
		Identity      string
		AssetIdentity string
	}
	tests := []struct {
		name           string
		fields         fields
		eIdentity      string
		eAssetIdentity string
	}{
		{
			name: "positive",
			fields: fields{
				Identity:      "assets/9ccdc19b-44a1-434c-afab-14f8eac3405c/events/e76a03d1-19a5-4f11-bcaf-383bb4f1dfd4",
				AssetIdentity: "assets/9ccdc19b-44a1-434c-afab-14f8eac3405c",
			},
			eIdentity:      "publicassets/9ccdc19b-44a1-434c-afab-14f8eac3405c/events/e76a03d1-19a5-4f11-bcaf-383bb4f1dfd4",
			eAssetIdentity: "publicassets/9ccdc19b-44a1-434c-afab-14f8eac3405c",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := &V2Event{
				Identity:      test.fields.Identity,
				AssetIdentity: test.fields.AssetIdentity,
			}
			e.ToPublicIdentity()

			assert.Equal(t, test.eIdentity, e.Identity)
			assert.Equal(t, test.eAssetIdentity, e.AssetIdentity)
		})
	}
}
