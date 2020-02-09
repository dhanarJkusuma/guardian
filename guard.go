package guardian

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/dhanarJkusuma/guardian/auth"
	"github.com/dhanarJkusuma/guardian/auth/password"
	"github.com/dhanarJkusuma/guardian/auth/token"
	"github.com/dhanarJkusuma/guardian/migration"
	"github.com/dhanarJkusuma/guardian/schema"
	"github.com/go-redis/redis"
)

// Guardian wrap all needed function for authentication in the guardian library
type Guardian struct {
	Migration *migration.Migration
	Auth      *auth.Auth

	guardSchema *schema.Schema
}

type SessionOptions struct {
	CacheClient      *redis.Client
	LoginMethod      auth.LoginMethod
	SessionName      string
	ExpiredInSeconds int64
}

type Options struct {
	DbConnection *sql.DB
	SchemaName   string
	Session      SessionOptions
}

type guardianBuilder struct {
	guardOpts        *Options
	tokenStrategy    token.TokenGenerator
	passwordStrategy password.PasswordGenerator
	validation       string
}

// NewGuardian will set required parameters and return guardianBuilder
// This function is called when you want to create Guardian instance using builder pattern
func NewGuardian(opts *Options) *guardianBuilder {
	rbacBuilder := &guardianBuilder{
		guardOpts: opts,
	}
	defaultTokenGen := &token.DefaultTokenGenerator{}
	defaultPasswordStrategy := &password.DefaultBcryptPassword{}
	rbacBuilder.tokenStrategy = defaultTokenGen
	rbacBuilder.passwordStrategy = defaultPasswordStrategy
	return rbacBuilder
}

// SetTokenGenerator will set token strategy in the guardian library
func (p *guardianBuilder) SetTokenGenerator(generator token.TokenGenerator) *guardianBuilder {
	p.tokenStrategy = generator
	return p
}

// SetPasswordGenerator will set password strategy in the guardian library
func (p *guardianBuilder) SetPasswordGenerator(generator password.PasswordGenerator) *guardianBuilder {
	p.passwordStrategy = generator
	return p
}

func (p *guardianBuilder) SetSchemaValidation(config string) *guardianBuilder {
	p.validation = config
	return p
}

// Build() will set all required parameters
func (p *guardianBuilder) Build() *Guardian {
	var validator *schema.Validator

	// check schema validation
	if len(p.validation) > 0 {
		err := json.Unmarshal([]byte(p.validation), &validator)
		if err != nil {
			panic(errors.New("error occur while parsing validator config"))
		}
	} else {
		validator = &schema.Validator{}
	}

	validator.Initialize()
	rbac := &Guardian{
		guardSchema: &schema.Schema{
			DbConnection: p.guardOpts.DbConnection,
			Validator:    validator,
		},
	}

	// initialize auth module
	authModule := auth.NewAuth(auth.Options{
		SessionName: p.guardOpts.Session.SessionName,
		GuardSchema: rbac.guardSchema,

		CacheClient:  p.guardOpts.Session.CacheClient,
		LoginMethod:  p.guardOpts.Session.LoginMethod,
		ExpiredInSec: p.guardOpts.Session.ExpiredInSeconds,

		TokenStrategy:    p.tokenStrategy,
		PasswordStrategy: p.passwordStrategy,
	})

	// initialize migration module
	migrationModule, err := migration.NewMigration(migration.MigrationOptions{
		Schema:      p.guardOpts.SchemaName,
		GuardSchema: rbac.guardSchema,
		Auth:        authModule,
	})
	if err != nil {
		panic(err)
	}

	// set migration and auth module
	rbac.Migration = migrationModule
	rbac.Auth = authModule
	return rbac
}

// GetSchema will return guardian schema that used for do some database operation using guardian library
func (p *Guardian) GetSchema() *schema.Schema {
	return p.guardSchema
}
