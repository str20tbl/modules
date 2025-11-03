package app

import (
	"github.com/str20tbl/revel"
)

func init() {
	revel.OnAppStart(func() {
		revel.AppLog.Info("Go to /@tests to run the tests.")
	})
}
