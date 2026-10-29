// SPDX-License-Identifier: MPL-2.0
package vless

import (
    "testing"
    "github.com/xtls/xray-core/common/protocol"
    "github.com/xtls/xray-core/common/uuid"
)

func TestRPKIdentityCollision(t *testing.T) {
    t.Setenv("RPK_VLESS_IDENTITY_ROUTING", "1")
    makeUser := func(email, value string) *protocol.MemoryUser {
        id, err := uuid.ParseString(value)
        if err != nil { t.Fatal(err) }
        return &protocol.MemoryUser{Email: email, Account: &MemoryAccount{ID: protocol.NewID(id)}}
    }
    alice := makeUser("alice", "00112233-4455-4677-8899-aabbccddeeff")
    bob := makeUser("bob", "00112233-4455-0001-8899-aabbccddeeff")
    validator := &MemoryValidator{}
    if err := validator.Add(alice); err != nil { t.Fatal(err) }
    if err := validator.Add(bob); err == nil { t.Fatal("normalized collision accepted") }
    if validator.Get(bob.Account.(*MemoryAccount).ID.UUID()) != alice { t.Fatal("existing identity was overwritten") }
    if validator.GetByEmail("bob") != nil { t.Fatal("failed insert left an email entry") }
    if err := validator.Del("alice"); err != nil { t.Fatal(err) }
    if validator.GetCount() != 0 { t.Fatal("delete left an identity") }
    if err := validator.Add(alice); err != nil { t.Fatal("normal remove/add update failed", err) }
}
