package migration

import (
	"database/sql"
	"github.com/dhanarJkusuma/guardian/auth"
	"github.com/dhanarJkusuma/guardian/schema"
)

// GuardTx is used for custom schema migration
type GuardTx struct {
	dbTx *sql.Tx
	Auth *auth.Auth
}

// User will inject the databaseTx in the `User` schema
func (gtx *GuardTx) User(user *schema.User) *schema.User {
	if user == nil {
		return &schema.User{
			Entity: schema.Entity{DBContract: gtx.dbTx},
		}
	}
	user.DBContract = gtx.dbTx
	return user
}

// Role will inject the databaseTx in the `Role` schema
func (gtx *GuardTx) Role(role *schema.Role) *schema.Role {
	if role == nil {
		return &schema.Role{
			Entity: schema.Entity{DBContract: gtx.dbTx},
		}
	}
	role.DBContract = gtx.dbTx
	return role
}

// Permission will inject the databaseTx in the `Permission` schema
func (gtx *GuardTx) Permission(permission *schema.Permission) *schema.Permission {
	if permission == nil {
		return &schema.Permission{
			Entity: schema.Entity{DBContract: gtx.dbTx},
		}
	}
	permission.DBContract = gtx.dbTx
	return permission
}

// Rule will inject the databaseTx in the `Rule` schema
func (gtx *GuardTx) Rule(rule *schema.Rule) *schema.Rule {
	if rule == nil {
		return &schema.Rule{
			Entity: schema.Entity{DBContract: gtx.dbTx},
		}
	}
	rule.DBContract = gtx.dbTx
	return rule
}

// GetTx function will return specific database transaction
func (gtx *GuardTx) GetTx() *sql.Tx {
	return gtx.dbTx
}
