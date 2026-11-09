package smbsrv

import "github.com/tobychui/smbsrv/internal/auth"

// NTHash returns the NT hash of a password: MD4 over its UTF-16LE bytes. NTLM
// logins are checked against it, so a Backend has to be able to return it for
// every account (Backend.LookupHash).
//
// The NT hash is not salted and is enough to log in over NTLM on its own, so
// keep it as carefully as the password itself.
func NTHash(password string) []byte {
	return auth.NTHash(password)
}
