// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package kmip

import (
	"bytes"
	"testing"
	"time"

	kmip "github.com/gemalto/kmip-go"
	"github.com/gemalto/kmip-go/kmip14"
	"github.com/gemalto/kmip-go/ttlv"
)

// stripCorrelation must turn a response the gemalto handler emits (with the
// Client/Server CorrelationValue header fields) into exactly the bytes the same
// response would have without them — proving the lengths are fixed correctly and
// nothing else is touched. Strict clients (PyKMIP) then parse it.
func TestStripCorrelation(t *testing.T) {
	ts := time.Unix(1_700_000_000, 0).UTC()
	mk := func() kmip.ResponseMessage {
		return kmip.ResponseMessage{
			ResponseHeader: kmip.ResponseHeader{
				ProtocolVersion: kmip.ProtocolVersion{ProtocolVersionMajor: 1, ProtocolVersionMinor: 4},
				TimeStamp:       ts,
				BatchCount:      1,
			},
			BatchItem: []kmip.ResponseBatchItem{{
				Operation:    kmip14.OperationCreate,
				ResultStatus: kmip14.ResultStatusSuccess,
				ResponsePayload: &kmip.CreateResponsePayload{
					ObjectType:       kmip14.ObjectTypeSymmetricKey,
					UniqueIdentifier: "my-key-name",
				},
			}},
		}
	}

	withCorr := mk()
	withCorr.ResponseHeader.ClientCorrelationValue = "client-correlation-uuid-1234"
	withCorr.ResponseHeader.ServerCorrelationValue = "server-correlation-uuid-5678"
	in, err := ttlv.Marshal(withCorr)
	if err != nil {
		t.Fatalf("marshal with correlation: %v", err)
	}
	want, err := ttlv.Marshal(mk()) // omitempty drops the two fields
	if err != nil {
		t.Fatalf("marshal without correlation: %v", err)
	}

	out := stripCorrelation(in)

	if !bytes.Equal(out, want) {
		t.Fatalf("stripped output (%d bytes) != message without correlation (%d bytes)", len(out), len(want))
	}
	// And it must re-parse cleanly with the fields cleared.
	var rm kmip.ResponseMessage
	if err := ttlv.Unmarshal(out, &rm); err != nil {
		t.Fatalf("re-parse stripped: %v", err)
	}
	if rm.ResponseHeader.ServerCorrelationValue != "" || rm.ResponseHeader.ClientCorrelationValue != "" {
		t.Errorf("correlation values not cleared: %+v", rm.ResponseHeader)
	}
	if rm.ResponseHeader.BatchCount != 1 || len(rm.BatchItem) != 1 {
		t.Errorf("message structure altered: batchCount=%d items=%d", rm.ResponseHeader.BatchCount, len(rm.BatchItem))
	}

	// Idempotent + safe on a message that has nothing to strip.
	if again := stripCorrelation(out); !bytes.Equal(again, out) {
		t.Errorf("stripCorrelation not idempotent")
	}
}
