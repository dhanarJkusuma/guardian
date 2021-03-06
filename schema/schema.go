package schema

import (
	"context"
	"database/sql"
	"errors"
)

type Schema struct {
	DbConnection *sql.DB
	Validator    *Validator
}

type Entity struct {
	DBContract DbContract `json:"-"`
}

type existRecord struct {
	IsExist bool `db:"is_exist"`
}

var (
	ErrInvalidID     = errors.New("invalid id")
	ErrNoSchema      = errors.New("no schema provided")
	ErrInvalidParams = errors.New("invalid params")
)

// DbContract interface will provide database behaviour if you want to using dbTx function
type DbContract interface {
	Prepare(query string) (*sql.Stmt, error)
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	Exec(query string, args ...interface{}) (sql.Result, error)
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

// User function will inject schema in the userModel
// This function will inject the database connection to userModel
func (s *Schema) User(userModel *User) *User {
	if userModel == nil {
		return &User{
			Entity:    Entity{DBContract: s.DbConnection},
			validator: s.Validator.User,
		}
	}

	userModel.DBContract = s.DbConnection
	userModel.validator = s.Validator.User
	return userModel
}

// Permission function will inject schema in the permissionModel
// This function will inject the database connection to permissionModel
func (s *Schema) Permission(permissionModel *Permission) *Permission {
	if permissionModel == nil {
		return &Permission{
			Entity:    Entity{DBContract: s.DbConnection},
			validator: s.Validator.Permission,
		}
	}
	permissionModel.DBContract = s.DbConnection
	permissionModel.validator = s.Validator.Permission
	return permissionModel
}

// Role function will inject schema in the roleModel
// This function will inject the database connection to roleModel
func (s *Schema) Role(roleModel *Role) *Role {
	if roleModel == nil {
		return &Role{
			Entity:    Entity{DBContract: s.DbConnection},
			validator: s.Validator.Role,
		}
	}
	roleModel.DBContract = s.DbConnection
	roleModel.validator = s.Validator.Role
	return roleModel
}

// Rule function will inject schema in the ruleModel
// This function will inject the database connection to ruleModel
func (s *Schema) Rule(ruleModel *Rule) *Rule {
	if ruleModel == nil {
		return &Rule{
			Entity:    Entity{DBContract: s.DbConnection},
			validator: s.Validator.Rule,
		}
	}
	ruleModel.DBContract = s.DbConnection
	ruleModel.validator = s.Validator.Rule
	return ruleModel
}
