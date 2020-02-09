package migration

import (
	"database/sql"
	"github.com/dhanarJkusuma/guardian/auth"
	"github.com/dhanarJkusuma/guardian/schema"
)

// GuardTx is used for custom schema migration
type GuardTx struct {
	dbTx      *sql.Tx
	Auth      *auth.Auth
	validator *schema.Validator
}

// User will inject the databaseTx in the `User` schema
func (gtx *GuardTx) User(user *schema.User) *schema.User {
	if user == nil {
		user = &schema.User{
			Entity: schema.Entity{DBContract: gtx.dbTx},
		}
	} else {
		user.DBContract = gtx.dbTx
	}
	user.SetValidator(gtx.validator.User)
	return user
}

// Role will inject the databaseTx in the `Role` schema
func (gtx *GuardTx) Role(role *schema.Role) *schema.Role {
	if role == nil {
		role = &schema.Role{
			Entity: schema.Entity{DBContract: gtx.dbTx},
		}
	} else {
		role.DBContract = gtx.dbTx
	}
	role.SetValidator(gtx.validator.Role)
	return role
}

// Permission will inject the databaseTx in the `Permission` schema
func (gtx *GuardTx) Permission(permission *schema.Permission) *schema.Permission {
	if permission == nil {
		return &schema.Permission{
			Entity: schema.Entity{DBContract: gtx.dbTx},
		}
	} else {
		permission.DBContract = gtx.dbTx
	}
	permission.SetValidator(gtx.validator.Permission)
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
	rule.SetValidator(gtx.validator.Rule)
	return rule
}

// GetTx function will return specific database transaction
func (gtx *GuardTx) GetTx() *sql.Tx {
	return gtx.dbTx
}
