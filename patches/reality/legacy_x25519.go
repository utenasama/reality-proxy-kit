// SPDX-License-Identifier: MPL-2.0
package reality

import "os"

// Opt-in compatibility for TLS 1.3 clients that predate ML-KEM profiles.
// This only relaxes the ClientHello shape check; REALITY authentication,
// server-name/short-ID/time/version checks and VLESS authorization still run.
var allowLegacyX25519 = os.Getenv("UTENASAMA_REALITY_LEGACY_X25519") == "1"

func legacyX25519KeyShare(shares []keyShare) bool {
	seen := false
	for _, share := range shares {
		switch share.group {
		case X25519MLKEM768:
			// Never use the legacy exception to bypass the modern profile's
			// ordering, length or duplicate checks.
			return false
		case X25519:
			if seen || len(share.data) != 32 {
				return false
			}
			seen = true
		}
	}
	return seen
}
