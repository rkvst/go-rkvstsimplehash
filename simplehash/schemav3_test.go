package simplehash

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	v2assets "github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"gotest.tools/v3/assert"
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
