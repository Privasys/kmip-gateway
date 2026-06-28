// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package kmip

import (
	kmip "github.com/gemalto/kmip-go"
	"github.com/gemalto/kmip-go/kmip14"
	"github.com/gemalto/kmip-go/ttlv"
	"github.com/google/uuid"

	vsdk "github.com/Privasys/enclave-vaults-client/go/vault"
)

// keyTypeFor maps a KMIP Create request to a vault key type ("aes" | "p256").
// ObjectType is preferred (it is a typed field); the CryptographicAlgorithm
// attribute is a fallback.
func keyTypeFor(p *kmip.CreateRequestPayload) (string, error) {
	switch p.ObjectType {
	case kmip14.ObjectTypeSymmetricKey:
		return "aes", nil
	case kmip14.ObjectTypePrivateKey, kmip14.ObjectTypePublicKey:
		return "p256", nil
	}
	if a := p.TemplateAttribute.GetTag(kmip14.TagCryptographicAlgorithm); a != nil {
		if alg, ok := coerceAlgorithm(a.AttributeValue); ok {
			switch alg {
			case kmip14.CryptographicAlgorithmAES:
				return "aes", nil
			case kmip14.CryptographicAlgorithmECDSA:
				return "p256", nil
			}
		}
	}
	return "", fail(kmip14.ResultReasonInvalidField, "create: unsupported object type/algorithm")
}

// coerceAlgorithm reads a decoded CryptographicAlgorithm attribute value (an
// enumeration may arrive as the typed enum or its underlying integer).
func coerceAlgorithm(v interface{}) (kmip14.CryptographicAlgorithm, bool) {
	switch t := v.(type) {
	case kmip14.CryptographicAlgorithm:
		return t, true
	case uint32:
		return kmip14.CryptographicAlgorithm(t), true
	case int32:
		return kmip14.CryptographicAlgorithm(t), true
	case int:
		return kmip14.CryptographicAlgorithm(t), true
	}
	return 0, false
}

// requestedName extracts a client-supplied Name from a template attribute.
func requestedName(ta *kmip.TemplateAttribute) string {
	return nameValue(ta.GetTag(kmip14.TagName))
}

// nameFromAttributes extracts a Name value from a flat attribute list (Locate).
func nameFromAttributes(attrs []kmip.Attribute) string {
	for i := range attrs {
		if attrs[i].AttributeName == kmip14.TagName.CanonicalName() {
			return nameValue(&attrs[i])
		}
	}
	return ""
}

// nameValue coerces a decoded Name attribute (a structure) to its NameValue.
func nameValue(attr *kmip.Attribute) string {
	if attr == nil {
		return ""
	}
	switch v := attr.AttributeValue.(type) {
	case string:
		return v
	case kmip.Name:
		return v.NameValue
	case ttlv.TTLV:
		var n kmip.Name
		if err := ttlv.Unmarshal(v, &n); err == nil {
			return n.NameValue
		}
	}
	return ""
}

// generateName mints a stable, unique key name when the client supplies none.
func generateName(keyType string) string {
	return "kmip-" + keyType + "-" + uuid.NewString()
}

// kmipTypeFor maps a vault key type to a KMIP ObjectType + CryptographicAlgorithm.
func kmipTypeFor(kt vsdk.KeyType) (kmip14.ObjectType, kmip14.CryptographicAlgorithm) {
	switch kt {
	case vsdk.Aes256GcmKey:
		return kmip14.ObjectTypeSymmetricKey, kmip14.CryptographicAlgorithmAES
	case vsdk.P256SigningKey:
		return kmip14.ObjectTypePrivateKey, kmip14.CryptographicAlgorithmECDSA
	case vsdk.HmacSha256Key:
		return kmip14.ObjectTypeSymmetricKey, kmip14.CryptographicAlgorithmHMAC_SHA256
	}
	return 0, 0
}

// filterAttributes returns only the named attributes (all when names is empty).
func filterAttributes(attrs []kmip.Attribute, names []string) []kmip.Attribute {
	if len(names) == 0 {
		return attrs
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var out []kmip.Attribute
	for _, a := range attrs {
		if want[a.AttributeName] {
			out = append(out, a)
		}
	}
	return out
}
