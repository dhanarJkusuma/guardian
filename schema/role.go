package schema

import (
	"context"
	"database/sql"
	"time"
)

// Role represents `guard_role` table in the database
type Role struct {
	Entity

	ID          int64  `db:"id" json:"id"`
	Name        string `db:"name" json:"name"`
	Description string `db:"description" json:"description"`

	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

const insertRoleQuery = `
	INSERT INTO guard_role (
		name, 
		description
	) VALUES (?,?)
`

// CreateRole function will create a new record of role entity
func (r *Role) CreateRole() error {
	if r.DBContract == nil {
		return ErrNoSchema
	}
	result, err := r.DBContract.Exec(
		insertRoleQuery,
		r.Name,
		r.Description,
	)
	if err != nil {
		return err
	}

	r.ID, _ = result.LastInsertId()
	return nil
}

// CreateRoleContext function will create a new record of role entity with specific context
func (r *Role) CreateRoleContext(ctx context.Context) error {
	if r.DBContract == nil {
		return ErrNoSchema
	}
	result, err := r.DBContract.ExecContext(
		ctx,
		insertRoleQuery,
		r.Name,
		r.Description,
	)
	if err != nil {
		return err
	}

	r.ID, _ = result.LastInsertId()
	return nil
}

const saveRoleQuery = `
	INSERT INTO guard_role (
		name,
		description
	) VALUES (?, ?) ON DUPLICATE KEY UPDATE name = ?, description = ?
`

// Save function will save updated role entity
// if role record already exist in the database, it will be updated
// otherwise it will create a new one
func (r *Role) Save() error {
	if r.DBContract == nil {
		return ErrNoSchema
	}

	result, err := r.DBContract.Exec(
		saveRoleQuery,
		r.Name,
		r.Description,
	)
	if err != nil {
		return err
	}

	r.ID, _ = result.LastInsertId()
	return nil
}

// Save function will save updated role entity with specific context
// if role record already exist in the database, it will be updated
// otherwise it will create a new one
func (r *Role) SaveContext(ctx context.Context) error {
	if r.DBContract == nil {
		return ErrNoSchema
	}

	result, err := r.DBContract.ExecContext(
		ctx,
		saveRoleQuery,
		r.Name,
		r.Description,
	)
	if err != nil {
		return err
	}

	r.ID, _ = result.LastInsertId()
	return nil
}

const deleteRoleQuery = `DELETE FROM guard_role WHERE id = ?`

// Delete function will delete role entity with specific ID
// if role has no ID, than error will be returned
func (r *Role) Delete() error {
	if r.DBContract == nil {
		return ErrNoSchema
	}

	if r.ID <= 0 {
		return ErrInvalidID
	}
	_, err := r.DBContract.Exec(
		deleteRoleQuery,
		r.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

// Delete function will delete role entity with specific ID and context
// if role has no ID, than error will be returned
func (r *Role) DeleteContext(ctx context.Context) error {
	if r.DBContract == nil {
		return ErrNoSchema
	}
	if r.ID <= 0 {
		return ErrInvalidID
	}
	_, err := r.DBContract.ExecContext(
		ctx,
		deleteRoleQuery,
		r.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

const assignRoleQuery = `
	INSERT INTO guard_user_role (
		role_id, 
		user_id
	) VALUES (?,?)
`

// Assign function will assign the role to the specific user
// This function will create a new record in the database to create relation between user and role
func (r *Role) Assign(u *User) error {
	if r.DBContract == nil {
		return ErrNoSchema
	}
	if r.ID <= 0 || u.ID <= 0 {
		return ErrInvalidID
	}

	_, err := r.DBContract.Exec(
		assignRoleQuery,
		r.ID,
		u.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

// AssignContext function will assign the role to the specific user and specific context
// This function will create a new record in the database to create relation between user and role
func (r *Role) AssignContext(ctx context.Context, u *User) error {
	if r.DBContract == nil {
		return ErrNoSchema
	}
	if r.ID <= 0 || u.ID <= 0 {
		return ErrInvalidID
	}

	_, err := r.DBContract.ExecContext(
		ctx,
		assignRoleQuery,
		r.ID,
		u.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

const revokeRoleQuery = `DELETE FROM guard_user_role WHERE role_id = ? AND user_id = ?`

// Revoke function will revoke user's role by specific userID
// This function will delete the relation between user and role
func (r *Role) Revoke(u *User) error {
	if r.DBContract == nil {
		return ErrNoSchema
	}
	if r.ID <= 0 || u.ID <= 0 {
		return ErrInvalidID
	}

	_, err := r.DBContract.Exec(
		revokeRoleQuery,
		r.ID,
		u.ID,
	)
	if err != nil {
		return err
	}

	return nil
}

// RevokeContext function will revoke user's role by specific userID and specific context
// This function will delete the relation between user and role
func (r *Role) RevokeContext(ctx context.Context, u *User) error {
	if r.DBContract == nil {
		return ErrNoSchema
	}
	if r.ID <= 0 || u.ID <= 0 {
		return ErrInvalidID
	}

	_, err := r.DBContract.ExecContext(
		ctx,
		revokeRoleQuery,
		r.ID,
		u.ID,
	)
	if err != nil {
		return err
	}

	return nil
}

const addPermissionQuery = `
	INSERT INTO guard_role_permission (
		role_id, 
		permission_id
	) VALUES (?,?)
`

// AddPermission function will create a new relation between role with specific permission
// This function will create a new record in the table relation between role and permission
func (r *Role) AddPermission(p *Permission) error {
	if r.DBContract == nil {
		return ErrNoSchema
	}
	if r.ID <= 0 || p.ID <= 0 {
		return ErrInvalidID
	}

	_, err := r.DBContract.Exec(
		addPermissionQuery,
		r.ID,
		p.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

// AddPermissionContext function will create a new relation between role with specific permission and specific context
// This function will create a new record in the table relation between role and permission
func (r *Role) AddPermissionContext(ctx context.Context, p *Permission) error {
	if r.DBContract == nil {
		return ErrNoSchema
	}
	_, err := r.DBContract.ExecContext(
		ctx,
		addPermissionQuery,
		r.ID,
		p.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

const removePermissionQuery = `DELETE FROM guard_role_permission WHERE role_id = ? AND permission_id = ?`

// RemovePermission function will delete relation between role with specific permission
// This function will delete relation data record in the table relation between role and permission
func (r *Role) RemovePermission(p *Permission) error {
	if r.DBContract == nil {
		return ErrNoSchema
	}
	if r.ID <= 0 || p.ID <= 0 {
		return ErrInvalidID
	}

	_, err := r.DBContract.Exec(
		removePermissionQuery,
		r.ID,
		p.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

// RemovePermissionContext function will delete relation between role with specific permission and specific context
// This function will delete relation data record in the table relation between role and permission
func (r *Role) RemovePermissionContext(ctx context.Context, p *Permission) error {
	if r.DBContract == nil {
		return ErrNoSchema
	}
	if r.ID <= 0 || p.ID <= 0 {
		return ErrInvalidID
	}

	_, err := r.DBContract.ExecContext(
		ctx,
		removePermissionQuery,
		r.ID,
		p.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

const getPermissionQuery = `
	SELECT
		p.id,
		p.name,
		p.method,
		p.route,
		p.description,
		p.created_at,
		p.updated_at
	FROM guard_permission p
	JOIN guard_role_permission rp ON rp.permission_id = p.id   
	WHERE rp.role_id = ?
`

// GetPermissions function will return the permission collection by specific role
func (r *Role) GetPermissions() ([]Permission, error) {
	if r.DBContract == nil {
		return nil, ErrNoSchema
	}

	permissions := make([]Permission, 0)
	result, err := r.DBContract.Query(getPermissionQuery, r.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return permissions, nil
		}
		return nil, err
	}

	var permission Permission
	permission.DBContract = r.DBContract

	for result.Next() {
		err = result.Scan(
			&permission.ID,
			&permission.Name,
			&permission.Method,
			&permission.Route,
			&permission.Description,
			&permission.CreatedAt,
			&permission.UpdatedAt,
		)
		if err == nil {
			permissions = append(permissions, permission)
		}
	}
	return permissions, nil
}

// GetPermissions function will return the permission collection by specific role and context
func (r *Role) GetPermissionsContext(ctx context.Context) ([]Permission, error) {
	if r.DBContract == nil {
		return nil, ErrNoSchema
	}

	permissions := make([]Permission, 0)
	result, err := r.DBContract.QueryContext(ctx, getPermissionQuery, r.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return permissions, nil
		}
		return nil, err
	}

	var permission Permission
	for result.Next() {
		err = result.Scan(
			&permission.ID,
			&permission.Name,
			&permission.Method,
			&permission.Route,
			&permission.Description,
			&permission.CreatedAt,
			&permission.UpdatedAt,
		)
		if err == nil {
			permissions = append(permissions, permission)
		}
	}
	return permissions, nil
}

const fetchRoleQuery = `
	SELECT
		id,
		name,
		description,
		created_at,	
		updated_at
	FROM guard_role WHERE name = ?
`

// GetRole function will get the role entity by name
// This function will fetch the data from database and search by name
func (r *Role) GetRole(name string) (*Role, error) {
	if r.DBContract == nil {
		return nil, ErrNoSchema
	}

	var role = new(Role)
	result := r.DBContract.QueryRow(fetchRoleQuery, name)
	err := result.Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&role.CreatedAt,
		&role.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return role, nil
}

// GetRole function will get the role entity by name with specific context
// This function will fetch the data from database and search by name
func (r *Role) GetRoleContext(ctx context.Context, name string) (*Role, error) {
	if r.DBContract == nil {
		return nil, ErrNoSchema
	}

	var role = new(Role)
	result := r.DBContract.QueryRowContext(ctx, fetchRoleQuery, name)
	err := result.Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&role.CreatedAt,
		&role.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return role, nil
}

const fetchRolesResourceQuery = `
	SELECT 
		r.id,
		r.name,
		r.description,
		r.created_at,
		r.updated_at
	FROM guard_role r
	JOIN guard_role_permission rp ON rp.role_id = r.id
	JOIN guard_permission p ON p.id = rp.permission_id
	JOIN guard_user_role ur ON ur.role_id = r.id
	WHERE ur.user_id = ? AND p.method = ?  AND p.route = ?
`

// GetRolesResource function will return a collection of roles that associated with user, method, and route
// This function will fetch the data from database and search by user_id, method, and route
func (r *Role) GetRolesResource(user *User, method, route string) ([]Role, error) {
	if r.DBContract == nil {
		return nil, ErrNoSchema
	}

	if user == nil || user.ID <= 0 {
		return nil, ErrInvalidID
	}

	var role Role
	role.DBContract = r.DBContract
	roles := make([]Role, 0)
	result, err := r.DBContract.Query(fetchRolesResourceQuery, user.ID, method, route)
	if err != nil {
		if err == sql.ErrNoRows {
			return roles, nil
		}
		return nil, err
	}
	for result.Next() {
		err := result.Scan(
			&role.ID,
			&role.Name,
			&role.Description,
			&role.CreatedAt,
			&role.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, nil
}

// GetRolesResource function will return a collection of roles that associated with user, method, and route
// This function will fetch the data from database and search by user_id, method, and route
func (r *Role) GetRolesResourceContext(ctx context.Context, user *User, method, route string) ([]Role, error) {
	if r.DBContract == nil {
		return nil, ErrNoSchema
	}

	if user == nil || user.ID <= 0 {
		return nil, ErrInvalidID
	}

	var role Role
	role.DBContract = r.DBContract
	roles := make([]Role, 0)
	result, err := r.DBContract.QueryContext(
		ctx,
		fetchRolesResourceQuery,
		user.ID,
		method,
		route,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return roles, nil
		}
		return nil, err
	}
	for result.Next() {
		err := result.Scan(
			&role.ID,
			&role.Name,
			&role.Description,
			&role.CreatedAt,
			&role.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, nil
}
