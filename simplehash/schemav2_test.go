package simplehash

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"testing"

	v2assets "github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/datatrails/go-datatrails-common-api-gen/attribute/v2/attribute"
	"github.com/datatrails/go-datatrails-common-api-gen/marshalers/simpleoneof"
	"github.com/golang/protobuf/ptypes/timestamp"
	"gotest.tools/v3/assert"
)

var (
	// Note these events correspond to the VALID_EVENTS in
	// https://github.com/datatrails/datatrails-simplehash-python/blob/main/unittests/constants.py
	// @39ec71e744cf0cff44d2e60142308e0669687901

	expectedHashAll = "61211c916cd113a1cf424ac729924de46aa6259919825dbdf8ec78c5c14665e2"
	expectedHashes  = []string{
		"681458c64f5ca35717e69df83c392c5f671a71c18f7830ccae676edfdb7179f1",
		"19111226f169ee67b41265aa27dc3792bf10ca463bc873361cae27d7e1bd6786",
	}

	validEvents = []*v2assets.EventResponse{
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
		// https://github.com/rkvst/rkvst-simplehash-python/blob/main/unittests/constants.py
		// @39ec71e744cf0cff44d2e60142308e0669687901
		{
			"VALID_EVENTS[0]",
			args{
				sha256.New(),
				NewEventMarshaler(),
				validEvents[0],
			},
			false,
			expectedHashes[0],
		},
		{
			"VALID_EVENTS[1]",
			args{
				sha256.New(),
				NewEventMarshaler(),
				validEvents[1],
			},
			false,
			expectedHashes[1],
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
				validEvents,
				[]HashOption{WithAccumulate()},
			},
			false,
			expectedHashAll,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &HasherV2{
				hasher:    tt.fields.hasher,
				marshaler: tt.fields.marshaler,
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
				validEvents,
				[]HashOption{WithAccumulate()},
			},
			false,
			expectedHashAll,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error

			h := &HasherV2{
				hasher:    tt.fields.hasher,
				marshaler: tt.fields.marshaler,
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
