package jobs

import (
	"github.com/str20tbl/revel"
)

var jobLog = revel.AppLog

func init() {
	revel.RegisterModuleInit(func(m *revel.Module) {
		jobLog = m.Log
	})
}
