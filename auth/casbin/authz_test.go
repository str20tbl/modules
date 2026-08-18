package casbinauthz

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/casbin/casbin"
	_ "github.com/go-sql-driver/mysql"
	gormdb "github.com/str20tbl/modules/orm/gorm/app"
	"github.com/str20tbl/revel"
)

var (
	adapter      *Adapter
	enforcer     *casbin.Enforcer
	casbinModule *CasbinModule
	testFilters  []revel.Filter
)

// DefaultDbParams returns the MySQL connection these tests run against. Every
// field can be overridden from the environment so CI can point the suite at a
// service container.
func DefaultDbParams() gormdb.DbInfo {
	params := gormdb.DbInfo{}
	params.DbDriver = "mysql"
	params.DbHost = envOr("CASBIN_DB_HOST", "localhost")
	params.DbPort = envIntOr("CASBIN_DB_PORT", 3306)
	params.DbUser = envOr("CASBIN_DB_USER", "root")
	params.DbPassword = os.Getenv("CASBIN_DB_PASSWORD")
	params.DbName = envOr("CASBIN_DB_NAME", "casbin")

	return params
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}

func envIntOr(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}

	return fallback
}

// TestMain builds the fixture only after a MySQL server has answered. The
// adapter, enforcer and module used to be built in package-level var
// initialisers, which meant an unreachable database took the whole test binary
// down through revel's fatal logger before any test could skip.
func TestMain(m *testing.M) {
	params := DefaultDbParams()
	addr := net.JoinHostPort(params.DbHost, strconv.Itoa(params.DbPort))

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		fmt.Printf("skipping casbin tests: no MySQL server reachable at %s: %v\n", addr, err)
		os.Exit(0)
	}
	conn.Close()

	adapter = NewAdapter(params)
	enforcer = casbin.NewEnforcer("authz_model.conf", adapter)
	casbinModule = NewCasbinModule(enforcer)
	testFilters = []revel.Filter{
		casbinModule.AuthzFilter,
		func(c *revel.Controller, fc []revel.Filter) {
			c.RenderHTML("OK.")
		},
	}

	os.Exit(m.Run())
}

func testRequest(t *testing.T, user string, path string, method string, code int) {
	r, _ := http.NewRequest(method, path, nil)
	r.SetBasicAuth(user, "123")
	w := httptest.NewRecorder()
	context := revel.NewGoContext(nil)
	context.Request.SetRequest(r)
	context.Response.SetResponse(w)
	c := revel.NewController(context)

	testFilters[0](c, testFilters)

	if c.Response.Status != code {
		t.Errorf("%s, %s, %s: %d, supposed to be %d", user, path, method, c.Response.Status, code)
	}
}

func initPolicy(t *testing.T) {
	t.Helper()
	// Because the DB is empty at first,
	// so we need to load the policy from the file adapter (.CSV) first.
	e := casbin.NewEnforcer("authz_model.conf", "authz_policy.csv")

	a := NewAdapter(DefaultDbParams())
	// This is a trick to save the current policy to the DB.
	// We can't call e.SavePolicy() because the adapter in the enforcer is still the file adapter.
	// The current policy means the policy in the Casbin enforcer (aka in memory).
	err := a.SavePolicy(e.GetModel())
	if err != nil {
		panic(err)
	}
}

func TestBasic(t *testing.T) {
	// Initialize some policy in DB.
	initPolicy(t)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.

	testRequest(t, "alice", "/dataset1/resource1", "GET", 200)
	testRequest(t, "alice", "/dataset1/resource1", "POST", 200)
	testRequest(t, "alice", "/dataset1/resource2", "GET", 200)
	testRequest(t, "alice", "/dataset1/resource2", "POST", 403)
}

func TestPathWildcard(t *testing.T) {
	// Initialize some policy in DB.
	initPolicy(t)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.

	testRequest(t, "bob", "/dataset2/resource1", "GET", 200)
	testRequest(t, "bob", "/dataset2/resource1", "POST", 200)
	testRequest(t, "bob", "/dataset2/resource1", "DELETE", 200)
	testRequest(t, "bob", "/dataset2/resource2", "GET", 200)
	testRequest(t, "bob", "/dataset2/resource2", "POST", 403)
	testRequest(t, "bob", "/dataset2/resource2", "DELETE", 403)

	testRequest(t, "bob", "/dataset2/folder1/item1", "GET", 403)
	testRequest(t, "bob", "/dataset2/folder1/item1", "POST", 200)
	testRequest(t, "bob", "/dataset2/folder1/item1", "DELETE", 403)
	testRequest(t, "bob", "/dataset2/folder1/item2", "GET", 403)
	testRequest(t, "bob", "/dataset2/folder1/item2", "POST", 200)
	testRequest(t, "bob", "/dataset2/folder1/item2", "DELETE", 403)
}

func TestRBAC(t *testing.T) {
	// Initialize some policy in DB.
	initPolicy(t)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.

	// cathy can access all /dataset1/* resources via all methods because it has the dataset1_admin role.
	testRequest(t, "cathy", "/dataset1/item", "GET", 200)
	testRequest(t, "cathy", "/dataset1/item", "POST", 200)
	testRequest(t, "cathy", "/dataset1/item", "DELETE", 200)
	testRequest(t, "cathy", "/dataset2/item", "GET", 403)
	testRequest(t, "cathy", "/dataset2/item", "POST", 403)
	testRequest(t, "cathy", "/dataset2/item", "DELETE", 403)
}
