// SPDX-License-Identifier: MPL-2.0
package session

import (
    "testing"

    "github.com/xtls/xray-core/common/protocol"
    "github.com/xtls/xray-core/common/uuid"
    "github.com/xtls/xray-core/proxy/vless"
)

func TestRPKRoutingIdentity(t *testing.T) {
    id, _ := uuid.ParseString("00112233-4455-4677-8899-aabbccddeeff")
    user := &protocol.MemoryUser{Email: "alice", Account: &vless.MemoryAccount{ID: protocol.NewID(id)}}
    t.Setenv("RPK_VLESS_IDENTITY_ROUTING", "0")
    if rpkRoutingUser(user) != "alice" { t.Fatal("upstream behavior changed while disabled") }
    t.Setenv("RPK_VLESS_IDENTITY_ROUTING", "1")
    expected := "vless-id:00112233-4455-0000-8899-aabbccddeeff"
    if rpkRoutingUser(user) != expected { t.Fatal("identity normalization differs from VLESS authentication") }
    user.Email = "renamed"
    if rpkRoutingUser(user) != expected { t.Fatal("rename changed authorization identity") }
    other, _ := uuid.ParseString("10112233-4455-4677-8899-aabbccddeeff")
    user.Account = &vless.MemoryAccount{ID: protocol.NewID(other)}
    if rpkRoutingUser(user) == expected { t.Fatal("same name inherited an old identity") }
    user.Account = nil
    if rpkRoutingUser(user) != "renamed" { t.Fatal("non-VLESS behavior changed") }
}
