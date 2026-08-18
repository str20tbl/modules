package gormdb

import (
	"path/filepath"
	"testing"
)

// InitDBWithParameters is given every connection parameter explicitly, so it
// must work outside a running Revel application - which is exactly how the
// casbin adapter uses it. OpenDB used to read revel.Config unconditionally and
// dereference nil when no Revel app had loaded a configuration.
func TestInitDBWithParametersWithoutRevelConfig(t *testing.T) {
	params := DbInfo{
		DbDriver: "sqlite3",
		DbHost:   filepath.Join(t.TempDir(), "probe.db"),
	}

	InitDBWithParameters(params)

	if DB == nil {
		t.Fatal("expected DB to be initialised")
	}
}
