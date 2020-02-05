package schema

import (
	"context"
	"database/sql"
	"github.com/dhanarJkusuma/guardian"
	"strings"
	"time"
)

type RuleType int
type RuleTypes struct {
	RoleRuleType       RuleType
	PermissionRuleType RuleType
}

var EnumRuleTypes = RuleTypes{
	RoleRuleType:       13,
	PermissionRuleType: 9,
}

// Role represents `rbac_rule` table in the database
type Rule struct {
	Entity

	ID       int64    `db:"id" json:"id"`
	RuleType RuleType `db:"rule_type" json:"rule_type"`
	ParentID int64    `db:"parent_id" json:"parent_id"`
	Name     string   `db:"name" json:"name"`

	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// RuleExecutor represent rule behaviour which acts as additional constraint to roles and permission
type RuleExecutor interface {
	Name() string
	Execute(user *User) bool
}

const insertRuleQuery = `
	INSERT INTO rbac_role (
		rule_type,
		parent_id,
		name
	) VALUES (?,?,?)
`

// CreateRule function will create a new record of rule entity
func (r *Rule) CreateRule() error {
	if r.DBContract == nil {
		return guardian.ErrNoSchema
	}
	result, err := r.DBContract.Exec(
		insertRuleQuery,
		r.RuleType,
		r.ParentID,
		r.Name,
	)
	if err != nil {
		return err
	}

	r.ID, _ = result.LastInsertId()
	return nil
}

// CreateRuleContext function will create a new record of rule entity with specific context
func (r *Rule) CreateRuleContext(ctx context.Context) error {
	if r.DBContract == nil {
		return guardian.ErrNoSchema
	}
	result, err := r.DBContract.ExecContext(
		ctx,
		insertRuleQuery,
		r.RuleType,
		r.ParentID,
		r.Name,
	)
	if err != nil {
		return err
	}

	r.ID, _ = result.LastInsertId()
	return nil
}

const saveRuleQuery = `
	INSERT INTO rbac_role (
		rule_type,
		parent_id,
		name
	) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE rule_type = ?, parent_id = ?, name = ?
`

// Save function will save updated rule entity
// if rule record already exist in the database, it will be updated
// otherwise it will create a new one
func (r *Rule) Save() error {
	if r.DBContract == nil {
		return guardian.ErrNoSchema
	}

	result, err := r.DBContract.Exec(
		saveRuleQuery,
		r.RuleType,
		r.ParentID,
		r.Name,
	)
	if err != nil {
		return err
	}

	r.ID, _ = result.LastInsertId()
	return nil
}

// SaveContext function will save updated rule entity with specific context
// if rule record already exist in the database, it will be updated
// otherwise it will create a new one
func (r *Rule) SaveContext(ctx context.Context) error {
	if r.DBContract == nil {
		return guardian.ErrNoSchema
	}

	result, err := r.DBContract.ExecContext(
		ctx,
		saveRuleQuery,
		r.RuleType,
		r.ParentID,
		r.Name,
	)
	if err != nil {
		return err
	}

	r.ID, _ = result.LastInsertId()
	return nil
}

const deleteRuleQuery = `DELETE FROM rbac_rule WHERE id = ?`

// Delete function will delete rule entity with specific ID
// if rule has no ID, than error will be returned
func (r *Rule) Delete() error {
	if r.DBContract == nil {
		return guardian.ErrNoSchema
	}

	if r.ID <= 0 {
		return ErrInvalidID
	}
	_, err := r.DBContract.Exec(
		deleteRuleQuery,
		r.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

// DeleteContext function will delete rule entity with specific ID and context
// if rule has no ID, than error will be returned
func (r *Rule) DeleteContext(ctx context.Context) error {
	if r.DBContract == nil {
		return guardian.ErrNoSchema
	}
	if r.ID <= 0 {
		return ErrInvalidID
	}
	_, err := r.DBContract.ExecContext(
		ctx,
		deleteRuleQuery,
		r.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

const fetchRuleQuery = `
	SELECT
		id,
		rule_type,
		parent_id,
		name,
		created_at,	
		updated_at
	FROM rbac_rule WHERE name = ?
`

// GetRule function will get the rule entity by name
// This function will fetch the data from database and search by name
func (r *Rule) GetRule(name string) (*Rule, error) {
	if r.DBContract == nil {
		return nil, guardian.ErrNoSchema
	}

	var rule = new(Rule)
	result := r.DBContract.QueryRow(fetchRuleQuery, name)
	err := result.Scan(
		&rule.ID,
		&rule.RuleType,
		&rule.ParentID,
		&rule.Name,
		&rule.CreatedAt,
		&rule.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return rule, nil
}

// GetRuleContext function will get the rule entity by name with specific context
// This function will fetch the data from database and search by name
func (r *Rule) GetRuleContext(ctx context.Context, name string) (*Rule, error) {
	if r.DBContract == nil {
		return nil, guardian.ErrNoSchema
	}

	var rule = new(Rule)
	result := r.DBContract.QueryRowContext(ctx, fetchRuleQuery, name)
	err := result.Scan(
		&rule.ID,
		&rule.RuleType,
		&rule.ParentID,
		&rule.Name,
		&rule.CreatedAt,
		&rule.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return rule, nil
}

const fetchRuleByRuleTypeAndParentIDs = `
	SELECT
		id,
		rule_type,
		parent_id,
		name,
		created_at,	
		updated_at
	FROM rbac_rule 
	WHERE rule_type = ? AND parent_id in (?) 
`

// GetRolesRule function will return a collection of rule entity by specific roles
func (r *Rule) GetRolesRule(roles []Role) ([]Rule, error) {
	if r.DBContract == nil {
		return nil, guardian.ErrNoSchema
	}

	args := make([]interface{}, len(roles))
	args[0] = EnumRuleTypes.RoleRuleType
	for i := range roles {
		args = append(args, roles[i].ID)
	}
	inStmt := `(?` + strings.Repeat(",?", len(args)-1) + `)`
	query := strings.Replace(fetchRuleByRuleTypeAndParentIDs, `(?)`, inStmt, -1)

	var rule Rule
	rule.DBContract = r.DBContract
	rules := make([]Rule, 0)
	result, err := r.DBContract.Query(query, args...)
	if err != nil {
		if err == sql.ErrNoRows {
			return rules, nil
		}
		return nil, err
	}

	for result.Next() {
		err := result.Scan(
			&rule.ID,
			&rule.RuleType,
			&rule.ParentID,
			&rule.Name,
			&rule.CreatedAt,
			&rule.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// GetRolesRuleContext function will return a collection of rule entity by specific roles
func (r *Rule) GetRolesRuleContext(ctx context.Context, roles []Role) ([]Rule, error) {
	if r.DBContract == nil {
		return nil, guardian.ErrNoSchema
	}

	args := make([]interface{}, len(roles))
	args[0] = EnumRuleTypes.RoleRuleType
	for i := range roles {
		args = append(args, roles[i].ID)
	}
	inStmt := `(?` + strings.Repeat(",?", len(args)-1) + `)`
	query := strings.Replace(fetchRuleByRuleTypeAndParentIDs, `(?)`, inStmt, -1)

	var rule Rule
	rule.DBContract = r.DBContract
	rules := make([]Rule, 0)
	result, err := r.DBContract.QueryContext(ctx, query, args...)
	if err != nil {
		if err == sql.ErrNoRows {
			return rules, nil
		}
		return nil, err
	}

	for result.Next() {
		err := result.Scan(
			&rule.ID,
			&rule.RuleType,
			&rule.ParentID,
			&rule.Name,
			&rule.CreatedAt,
			&rule.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

const fetchRuleByRuleTypeAndParentID = `
	SELECT
		id,
		rule_type,
		parent_id,
		name,
		created_at,	
		updated_at
	FROM rbac_rule 
	WHERE rule_type = ? AND parent_id = ?
`

// GetPermissionRule function will return a collection of rule entity by specific permissions
func (r *Rule) GetPermissionRule(permission Permission) ([]Rule, error) {
	if r.DBContract == nil {
		return nil, guardian.ErrNoSchema
	}
	if permission.ID <= 0 {
		return nil, ErrInvalidID
	}

	var rule Rule
	rule.DBContract = r.DBContract
	rules := make([]Rule, 0)
	result, err := r.DBContract.Query(fetchRuleByRuleTypeAndParentID, EnumRuleTypes.PermissionRuleType, permission.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return rules, nil
		}
		return nil, err
	}

	for result.Next() {
		err := result.Scan(
			&rule.ID,
			&rule.RuleType,
			&rule.ParentID,
			&rule.Name,
			&rule.CreatedAt,
			&rule.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// GetPermissionRule function will return a collection of rule entity by specific permissions
func (r *Rule) GetPermissionRuleContext(ctx context.Context, permission Permission) ([]Rule, error) {
	if r.DBContract == nil {
		return nil, guardian.ErrNoSchema
	}
	if permission.ID <= 0 {
		return nil, ErrInvalidID
	}

	var rule Rule
	rule.DBContract = r.DBContract
	rules := make([]Rule, 0)
	result, err := r.DBContract.QueryContext(ctx, fetchRuleByRuleTypeAndParentID, EnumRuleTypes.PermissionRuleType, permission.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return rules, nil
		}
		return nil, err
	}

	for result.Next() {
		err := result.Scan(
			&rule.ID,
			&rule.RuleType,
			&rule.ParentID,
			&rule.Name,
			&rule.CreatedAt,
			&rule.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}
