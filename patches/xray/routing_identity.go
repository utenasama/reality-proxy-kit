// SPDX-License-Identifier: MPL-2.0
// Copyright 2026 Reality Proxy Kit contributors.
package session

import (
    "os"

    "github.com/xtls/xray-core/common/protocol"
    "github.com/xtls/xray-core/proxy/vless"
)

// rpkRoutingUser separates authorization identity from a panel-editable label.
// Only the routing context changes; native accounting retains the original email.
// Authentication ignores UUID route bytes, so routing uses the same normalization.
func rpkRoutingUser(user *protocol.MemoryUser) string {
    if os.Getenv("RPK_VLESS_IDENTITY_ROUTING") == "1" {
        if account, ok := user.Account.(*vless.MemoryAccount); ok && account.ID != nil {
            id := account.ID.UUID()
            id[6], id[7] = 0, 0
            return "vless-id:" + id.String()
        }
    }
    return user.Email
}
