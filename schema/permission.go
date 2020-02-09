package schema

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	PermissionNotFound = errors.New("permission is not exist")
)

// Permission represents `guard_permission` table in the database
type Permission struct {
	Entity

	ID          int64  `db:"id" json:"id"`
	Name        string `db:"name" json:"name"`
	Method      string `db:"method" json:"method"`
	Route       string `db:"route" json:"route"`
	Description string `db:"description" json:"description"`

	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`

	exist     bool                 `json:"-"`
	validator *PermissionValidator `json:"-"`
}

// SetValidator is setter function to set validator in permission entity
func (p *Permission) SetValidator(validator *PermissionValidator) {
	p.validator = validator
}

// Validate will validate all value in permission entity
func (p *Permission) validate() error {
	// validate name
	return p.validator.Name.validateLen("name", p.Name)
}

const insertPermissionQuery = `
	INSERT INTO guard_permission (
		name, 
		method,
		route,
		description
	) VALUES (?,?,?,?)
`

// CreatePermission function will create a new record of permission entity
func (p *Permission) CreatePermission() error {
	if p.DBContract == nil {
		return ErrNoSchema
	}

	// validate
	err := p.validate()
	if err != nil {
		return err
	}

	result, err := p.DBContract.Exec(
		insertPermissionQuery,
		p.Name,
		p.Method,
		p.Route,
		p.Description,
	)
	if err != nil {
		return err
	}
	p.ID, _ = result.LastInsertId()
	p.exist = true
	return nil
}

// CreatePermissionContext function will create a new record of permission entity with specific context
func (p *Permission) CreatePermissionContext(ctx context.Context) error {
	if p.DBContract == nil {
		return ErrNoSchema
	}

	// validate
	err := p.validate()
	if err != nil {
		return err
	}

	result, err := p.DBContract.ExecContext(
		ctx,
		insertPermissionQuery,
		p.Name,
		p.Method,
		p.Route,
		p.Description,
	)
	if err != nil {
		return err
	}

	p.ID, _ = result.LastInsertId()
	p.exist = true
	return nil
}

const savePermissionQuery = `
	INSERT INTO guard_permission (
		name,
		method,
		route,
		description
	) VALUES (?, ?, ?, ?) ON DUPLICATE KEY 
	UPDATE name = ?, method = ?, route = ?, description = ?
`

// Save function will save updated permission entity
// if permission record already exist in the database, it will be updated
// otherwise it will create a new one
func (p *Permission) Save() error {
	if p.DBContract == nil {
		return ErrNoSchema
	}

	// validate
	err := p.validate()
	if err != nil {
		return err
	}

	result, err := p.DBContract.Exec(
		savePermissionQuery,
		p.Name,
		p.Method,
		p.Route,
		p.Description,
		p.Name,
		p.Method,
		p.Route,
		p.Description,
	)
	if err != nil {
		return err
	}

	p.ID, _ = result.LastInsertId()
	p.exist = true
	return nil
}

// Save function will save updated user permission with specific context
// if user permission already exist in the database, it will be updated
// otherwise it will create a new one
func (p *Permission) SaveContext(ctx context.Context) error {
	if p.DBContract == nil {
		return ErrNoSchema
	}

	// validate
	err := p.validate()
	if err != nil {
		return err
	}

	result, err := p.DBContract.ExecContext(
		ctx,
		savePermissionQuery,
		p.Name,
		p.Method,
		p.Route,
		p.Description,
		p.Name,
		p.Method,
		p.Route,
		p.Description,
	)
	if err != nil {
		return err
	}

	p.ID, _ = result.LastInsertId()
	p.exist = true
	return nil
}

const deletePermissionQuery = `DELETE FROM guard_permission WHERE id = ?`

// Delete function will delete permission entity with specific ID
// if permission has no ID, than error will be returned
func (p *Permission) Delete() error {
	if p.DBContract == nil {
		return ErrNoSchema
	}

	if !p.exist {
		return PermissionNotFound
	}

	if p.ID <= 0 {
		return ErrInvalidID
	}

	_, err := p.DBContract.Exec(
		deletePermissionQuery,
		p.ID,
	)
	if err != nil {
		return err
	}
	p.exist = false
	return nil
}

// Delete function will delete permission entity with specific ID and context
// if permission has no ID, than error will be returned
func (p *Permission) DeleteContext(ctx context.Context) error {
	if p.DBContract == nil {
		return ErrNoSchema
	}

	if !p.exist {
		return PermissionNotFound
	}

	if p.ID <= 0 {
		return ErrInvalidID
	}

	_, err := p.DBContract.ExecContext(
		ctx,
		deletePermissionQuery,
		p.ID,
	)
	if err != nil {
		return err
	}
	p.exist = false
	return nil
}

const fetchPermissionQuery = `
	SELECT
		id,
		name,
		method,
		route,
		description,
		created_at,
		updated_at
	FROM guard_permission WHERE name = ? LIMIT 1
`

// GetPermission function will get the permission entity by name
// This function will fetch the data from database and search by this name
func (p *Permission) GetPermission(name string) (*Permission, error) {
	if p.DBContract == nil {
		return nil, ErrNoSchema
	}

	var permission = new(Permission)
	result := p.DBContract.QueryRow(fetchPermissionQuery, name)
	err := result.Scan(
		&permission.ID,
		&permission.Name,
		&permission.Method,
		&permission.Route,
		&permission.Description,
		&permission.CreatedAt,
		&permission.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	permission.DBContract = p.DBContract
	permission.exist = true
	return permission, nil
}

// GetPermission function will get the permission entity by name with specific context
// This function will fetch the data from database and search by this name
func (p *Permission) GetPermissionContext(ctx context.Context, name string) (*Permission, error) {
	if p.DBContract == nil {
		return nil, ErrNoSchema
	}

	var permission = new(Permission)
	result := p.DBContract.QueryRowContext(ctx, fetchPermissionQuery, name)
	err := result.Scan(
		&permission.ID,
		&permission.Name,
		&permission.Method,
		&permission.Route,
		&permission.Description,
		&permission.CreatedAt,
		&permission.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	permission.DBContract = p.DBContract
	permission.exist = true
	return permission, nil
}

const fetchPermissionByResourceQuery = `
	SELECT
		id,
		name,
		method,
		route,
		description,
		created_at,
		updated_at
	FROM guard_permission WHERE method = ? AND route = ?
`

// GetPermissionByResource function will get the permission entity by resource
// This function will fetch the data from database and search by method and path
func (p *Permission) GetPermissionByResource(method, path string) (*Permission, error) {
	if p.DBContract == nil {
		return nil, ErrNoSchema
	}

	var permission = new(Permission)
	result := p.DBContract.QueryRow(fetchPermissionByResourceQuery, method, path)
	err := result.Scan(
		&permission.ID,
		&permission.Name,
		&permission.Method,
		&permission.Route,
		&permission.Description,
		&permission.CreatedAt,
		&permission.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	permission.DBContract = p.DBContract
	permission.exist = true
	return permission, nil
}

// GetPermissionByResourceContext function will get the permission entity by resource with specific context
// This function will fetch the data from database and search by method and path
func (p *Permission) GetPermissionByResourceContext(ctx context.Context, method, path string) (*Permission, error) {
	if p.DBContract == nil {
		return nil, ErrNoSchema
	}

	var permission = new(Permission)
	result := p.DBContract.QueryRowContext(ctx, fetchPermissionByResourceQuery, method, path)
	err := result.Scan(
		&permission.ID,
		&permission.Name,
		&permission.Method,
		&permission.Route,
		&permission.Description,
		&permission.CreatedAt,
		&permission.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	permission.DBContract = p.DBContract
	permission.exist = true
	return permission, nil
}
