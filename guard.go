package guardian

import (
	"database/sql"
	"github.com/dhanarJkusuma/guardian/auth"
	"github.com/dhanarJkusuma/guardian/auth/password"
	"github.com/dhanarJkusuma/guardian/auth/token"
	"github.com/dhanarJkusuma/guardian/migration"
	"github.com/dhanarJkusuma/guardian/schema"
	"github.com/go-redis/redis"
	"log"
)

type AuthManager interface {
	GenerateToken()
}

// Constants for Error Messaging
const ()

// Guardian wrap all needed function for authentication in the guardian library
type Guardian struct {
	Migration *migration.Migration
	Auth      *auth.Auth

	guardSchema *schema.Schema
}

type SessionOptions struct {
	LoginMethod      auth.LoginMethod
	SessionName      string
	Origin           string
	ExpiredInSeconds int64
}

type Options struct {
	DbConnection *sql.DB
	CacheClient  *redis.Client
	SchemaName   string
	Session      SessionOptions
}

type guardianBuilder struct {
	guardOpts        *Options
	tokenStrategy    token.TokenGenerator
	passwordStrategy password.PasswordGenerator
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

// Build will set all required parameters
func (p *guardianBuilder) Build() *Guardian {
	rbac := &Guardian{
		guardSchema: &schema.Schema{DbConnection: p.guardOpts.DbConnection},
	}

	// initialize auth module
	authModule := auth.NewAuth(auth.Options{
		SessionName:  p.guardOpts.Session.SessionName,
		GuardSchema:  rbac.guardSchema,
		CacheClient:  p.guardOpts.CacheClient,
		LoginMethod:  p.guardOpts.Session.LoginMethod,
		ExpiredInSec: p.guardOpts.Session.ExpiredInSeconds,

		TokenStrategy:    p.tokenStrategy,
		PasswordStrategy: p.passwordStrategy,
	})

	// initialize migration module
	migrator, err := migration.NewMigration(migration.MigrationOptions{
		Schema:       p.guardOpts.SchemaName,
		DBConnection: p.guardOpts.DbConnection,
	})
	if err != nil {
		log.Fatal(err)
	}

	// set migration and auth module
	rbac.Migration = migrator
	rbac.Auth = authModule
	return rbac
}

// GetSchema will return guardian schema that used for do some database operation using guardian library
func (p *Guardian) GetSchema() *schema.Schema {
	return p.guardSchema
}
