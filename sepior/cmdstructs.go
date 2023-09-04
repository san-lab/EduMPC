//go:build sepior
// +build sepior

package sepior

type KeyGenMsg struct {
	KeyType   string
	SessionID string
	KeyID     string
	Error     string
}
