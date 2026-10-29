// SPDX-License-Identifier: MPL-2.0
package vless

import (
    "os"
    "strings"
    "github.com/xtls/xray-core/common/errors"
    "github.com/xtls/xray-core/common/protocol"
)

func rpkIdentityRoutingEnabled() bool {
    return os.Getenv("RPK_VLESS_IDENTITY_ROUTING") == "1"
}

// Native panel writes must not bypass the controller's authentication identity
// collision check. Hold one lock across both indexes, including deletion.
func (v *MemoryValidator) addRPKUser(u *protocol.MemoryUser) error {
    v.rpkLock.Lock()
    defer v.rpkLock.Unlock()
    id := ProcessUUID(u.Account.(*MemoryAccount).ID.UUID())
    if _, exists := v.users.Load(id); exists {
        return errors.New("Duplicate VLESS authentication identity")
    }
    email := strings.ToLower(u.Email)
    if email != "" {
        if _, exists := v.email.Load(email); exists {
            return errors.New("Duplicate VLESS account name")
        }
        v.email.Store(email, u)
    }
    v.users.Store(id, u)
    return nil
}
