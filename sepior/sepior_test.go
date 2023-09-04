package sepior

import (
	"testing"

	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
)

func TestAdmin(t *testing.T) {
	aC := tsm.NewAdminClient(tsmC)
	aC.HealthInformation(0)
}
