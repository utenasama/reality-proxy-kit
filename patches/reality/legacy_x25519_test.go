// SPDX-License-Identifier: MPL-2.0
package reality

import (
	"crypto/mlkem"
	"testing"
)

func TestLegacyX25519KeyShare(t *testing.T) {
	x := keyShare{group: X25519, data: make([]byte, 32)}
	pq := keyShare{group: X25519MLKEM768, data: make([]byte, mlkem.EncapsulationKeySize768+32)}
	grease := keyShare{group: CurveID(0x0a0a), data: []byte{0}}
	cases := []struct {
		name string
		shares []keyShare
		want bool
	}{
		{"empty", nil, false},
		{"grease only", []keyShare{grease}, false},
		{"legacy", []keyShare{x}, true},
		{"legacy with grease", []keyShare{grease, x}, true},
		{"legacy with other curve", []keyShare{x, {group: CurveP256, data: make([]byte, 65)}}, true},
		{"short key", []keyShare{{group: X25519, data: make([]byte, 31)}}, false},
		{"long key", []keyShare{{group: X25519, data: make([]byte, 33)}}, false},
		{"duplicate", []keyShare{x, x}, false},
		{"duplicate after grease", []keyShare{x, grease, x}, false},
		{"malformed duplicate", []keyShare{x, {group: X25519, data: nil}}, false},
		{"modern only uses upstream gate", []keyShare{pq}, false},
		{"modern pair uses upstream gate", []keyShare{pq, x}, false},
		{"modern wrong order", []keyShare{x, pq}, false},
		{"malformed modern", []keyShare{{group: X25519MLKEM768, data: nil}, x}, false},
		{"duplicate modern", []keyShare{pq, pq, x}, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := legacyX25519KeyShare(tt.shares); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
