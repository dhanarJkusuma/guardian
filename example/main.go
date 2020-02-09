package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-redis/redis"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"

	"github.com/dhanarJkusuma/guardian"
	"github.com/dhanarJkusuma/guardian/auth"
	"github.com/dhanarJkusuma/guardian/migration"
	"github.com/dhanarJkusuma/guardian/schema"
)

const schemaGuardCfg = `
{
	"user": {
		"username": {
			"min": 6,
			"max": 20,
			"regex_validation": {
				"regex": "^[a-zA-Z0-9_]*$",
				"regex_err_msg": "your custom message"
			}
		},
		"password": {
			"min": 6,
			"max": 12,
			"regex_validation": {
				"regex": "^[a-zA-Z0-9_]*$",
				"regex_err_msg": "your custom message"
			}
		}
	},
	"rule": {
		"min": 3,
		"max": 10
	},
	"role": {
		"min": 3,
		"max": 10		
	},
	"permission": {
		"min": 3,
		"max": 10
	}
}
`

func main() {
	// open db connection
	dbConn := fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true&multiStatements=true", "root", "", "127.0.0.1", "guard_example_2")
	db, err := sql.Open("mysql", dbConn)
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	// init redis
	cacheClient := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
	})

	// init guardian
	guard := guardian.NewGuardian(&guardian.Options{
		DbConnection: db,
		SchemaName:   "guard_example_2",
		Session: guardian.SessionOptions{
			CacheClient:      cacheClient,
			LoginMethod:      auth.LoginEmail,
			ExpiredInSeconds: int64(24 * time.Hour),
			SessionName:      "_Guardian_Session_",
		}}).
		SetSchemaValidation(schemaGuardCfg).
		Build()

	// init db migration
	err = guard.Migration.Initialize()
	if err != nil {
		panic(err.Error())
	}

	// run migration for admin initiation
	err = guard.Migration.Run("init_admin", InitAdminMigration)
	if err != nil && err != migration.ErrMigrationAlreadyExist {
		panic(err)
	}

	// run migration for user registration
	err = guard.Migration.Run("some_user", func(g *migration.GuardTx) error {
		// inject guardTx with user schema
		user := g.User(&schema.User{
			Username: "someuser",
			Email:    "someuser@guardian.com",
			Password: "onlysecret",
		})
		// create another user without role
		return g.Auth.Register(user)
	})
	if err != nil && err != migration.ErrMigrationAlreadyExist {
		panic(err)
	}

	// run migration for create dashboard route and rule
	err = guard.Migration.Run("dashboard_rule", func(g *migration.GuardTx) error {
		var errMig error

		// create permission
		dashboardPermission := &schema.Permission{
			Name:   "dashboard_owner",
			Method: http.MethodGet,
			Route:  "/dashboard",
		}
		errMig = g.Permission(dashboardPermission).Save()
		if errMig != nil {
			return errMig
		}

		// create rule
		dashboardRule := &schema.Rule{
			RuleType: schema.EnumRuleTypes.PermissionRuleType,
			ParentID: dashboardPermission.ID,
			Name:     "rule_dashboard_owner",
		}
		errMig = g.Rule(dashboardRule).Save()
		if errMig != nil {
			return errMig
		}
		return nil
	})

	// register the rule
	guard.Auth.RegisterRule(&DashboardRule{})

	// run migration for create some user
	err = guard.Migration.Run("add_angel", func(g *migration.GuardTx) error {
		var errMig error

		// inject user with guard tx
		user := g.User(&schema.User{
			Username: "lala",
			Email:    "lala@jkt48.com",
			Password: "lalakawaii",
		})
		errMig = g.Auth.Register(user)
		if errMig != nil {
			return errMig
		}
		return nil
	})

	// create handler
	handler := HttpHandler{
		guard: guard,
	}

	r := mux.NewRouter()
	r.HandleFunc("/login", handler.LoginHandler).Methods(http.MethodPost)
	r.HandleFunc("/rahasia", guard.Auth.AuthenticateRBACHandlerFunc(handler.PrivateHandler)).Methods(http.MethodGet)
	r.HandleFunc("/dashboard", guard.Auth.AuthenticateHandlerFunc(handler.DashboardHandler)).Methods(http.MethodGet)

	log.Fatal(http.ListenAndServe(":8000", r))
}
