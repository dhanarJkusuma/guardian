package schema

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	UserNotFound = errors.New("user is not exist")
)

// User represents `guard_user` table in the database
type User struct {
	Entity

	ID       int64  `db:"id" json:"id"`
	Username string `db:"username" json:"username"`
	Email    string `db:"email" json:"email"`
	Password string `db:"password" json:"-"`
	Active   bool   `db:"active" json:"active"`

	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`

	exist             bool           `json:"-"`
	passwordEncrypted bool           `json:"-"`
	validator         *UserValidator `json:"-"`
}

// setDefaultTimeStamp is helper func to set current time for attribute `created_at` and `updated_at`
func (u *User) setDefaultTimeStamp() {
	now := time.Now()
	u.UpdatedAt = now
	if !u.exist {
		u.CreatedAt = now
	}
}

// SetValidator is setter function to set validator in user entity
func (u *User) SetValidator(validator *UserValidator) {
	u.validator = validator
}

// SetEncryptedPassword will set passwordEncrypted password and updating flag as passwordEncrypted
func (u *User) SetEncryptedPassword(encrypted string) {
	u.Password = encrypted
	u.passwordEncrypted = true
}

// Validate will validate all value in user entity
func (u *User) Validate() error {
	// username length
	err := u.validator.Username.validateLen("username", u.Username)
	if err != nil {
		return err
	}

	// username regex
	err = u.validator.Username.validateLen("username", u.Username)
	if err != nil {
		return err
	}

	// email regex
	err = u.validator.Email.validateRegex("email", u.Email)
	if err != nil {
		return err
	}

	// password length
	if !u.passwordEncrypted {
		err = u.validator.Password.StringValidator.validateLen("password", u.Password)
		if err != nil {
			return err
		}

		err = u.validator.Password.Regex.validateRegex("password", u.Password)
		if err != nil {
			return err
		}
	}

	return nil
}

const insertUserQuery = `
	INSERT INTO guard_user (
		email,
		username,
		password,
		created_at,
		updated_at
	) VALUES (?,?,?,?,?)
`

// CreateUser function will create a new record of user entity
func (u *User) CreateUser() error {
	if u.DBContract == nil {
		return ErrNoSchema
	}
	err := u.Validate()
	if err != nil {
		return err
	}

	u.setDefaultTimeStamp()

	result, err := u.DBContract.Exec(
		insertUserQuery,
		u.Email,
		u.Username,
		u.Password,
		u.CreatedAt,
		u.UpdatedAt,
	)
	if err != nil {
		return err
	}

	u.ID, err = result.LastInsertId()
	u.Active = true
	u.exist = true
	return nil
}

// CreateUserWithContext function will create a new record of user entity with specific context
func (u *User) CreateUserContext(ctx context.Context) error {
	if u.DBContract == nil {
		return ErrNoSchema
	}
	err := u.Validate()
	if err != nil {
		return err
	}

	u.setDefaultTimeStamp()

	result, err := u.DBContract.ExecContext(
		ctx,
		insertUserQuery,
		u.Email,
		u.Username,
		u.Password,
		u.CreatedAt,
		u.UpdatedAt,
	)
	if err != nil {
		return err
	}

	u.ID, err = result.LastInsertId()
	u.Active = true
	u.exist = true
	return nil
}

const saveUserQuery = `
	INSERT INTO guard_user (
		email,
		username,
		password,
		active,
		created_at,
		updated_at
	) VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE email = ?, username = ?, password = ?, active = ?, updated_at = ?
`

// Save function will save updated user entity
// if user record already exist in the database, it will be updated
// otherwise it will create a new one
func (u *User) Save() error {
	if u.DBContract == nil {
		return ErrNoSchema
	}

	// validate
	err := u.Validate()
	if err != nil {
		return err
	}

	// set the timestamp is user is not exist
	u.setDefaultTimeStamp()

	result, err := u.DBContract.Exec(
		saveUserQuery,
		u.Email,
		u.Username,
		u.Password,
		u.Active,
		u.CreatedAt,
		u.UpdatedAt,
		u.Email,
		u.Username,
		u.Password,
		u.Active,
		u.UpdatedAt,
	)
	if err != nil {
		return err
	}

	u.ID, _ = result.LastInsertId()
	u.exist = true
	return nil
}

// Save function will save updated user entity with specific context
// if user record already exist in the database, it will be updated
// otherwise it will create a new one
func (u *User) SaveContext(ctx context.Context) error {
	if u.DBContract == nil {
		return ErrNoSchema
	}

	// validate
	err := u.Validate()
	if err != nil {
		return err
	}

	// set the timestamp is user is not exist
	u.setDefaultTimeStamp()

	result, err := u.DBContract.ExecContext(
		ctx,
		saveUserQuery,
		u.Email,
		u.Username,
		u.Password,
		u.Active,
		u.CreatedAt,
		u.UpdatedAt,
		u.Email,
		u.Username,
		u.Password,
		u.Active,
		u.UpdatedAt,
	)
	if err != nil {
		return err
	}

	u.ID, _ = result.LastInsertId()
	u.exist = true
	return nil
}

const deleteUserQuery = `DELETE FROM guard_user WHERE id = ?`

// Delete function will save delete user entity with specific ID
// if user has no ID, than error will be returned
func (u *User) Delete() error {
	if u.DBContract == nil {
		return ErrNoSchema
	}

	if !u.exist {
		return UserNotFound
	}

	if u.ID <= 0 {
		return ErrInvalidID
	}

	_, err := u.DBContract.Exec(
		deleteUserQuery,
		u.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

// Delete function will delete user entity with specific ID and context
// if user has no ID, than error will be returned
func (u *User) DeleteContext(ctx context.Context) error {
	if u.DBContract == nil {
		return ErrNoSchema
	}

	if !u.exist {
		return UserNotFound
	}

	if u.ID <= 0 {
		return ErrInvalidID
	}

	_, err := u.DBContract.ExecContext(
		ctx,
		deleteUserQuery,
		u.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

const getAccessQuery = `
 	SELECT EXISTS(
		SELECT 
			*
		FROM guard_user_role ur 
		JOIN guard_role_permission rp ON ur.role_id = rp.role_id
		JOIN guard_permission p ON p.id = rp. permission_id 
		WHERE ur.user_id = ? AND p.method = ? AND p.route = ?
	) AS is_exist
`

// CanAccess function will return bool that represent this user is eligible to access the resource path or not
// This function will check the user permission record
func (u *User) CanAccess(method, path string) (bool, error) {
	if u.DBContract == nil {
		return false, ErrNoSchema
	}

	if !u.exist {
		return false, UserNotFound
	}

	var accessRecord existRecord
	result := u.DBContract.QueryRow(getAccessQuery, u.ID, method, path)
	err := result.Scan(&accessRecord.IsExist)
	if err != nil {
		return false, err
	}
	return accessRecord.IsExist, nil
}

// CanAccessContext function will return bool that represent this user is eligible to access the resource path or not
// This function will check the user permission record with specific context
func (u *User) CanAccessContext(ctx context.Context, method, path string) (bool, error) {
	if u.DBContract == nil {
		return false, ErrNoSchema
	}

	if !u.exist {
		return false, UserNotFound
	}

	var accessRecord existRecord
	result := u.DBContract.QueryRowContext(ctx, getAccessQuery, u.ID, method, path)
	err := result.Scan(&accessRecord.IsExist)
	if err != nil {
		return false, err
	}

	return accessRecord.IsExist, nil
}

const getUserPermissionQuery = `
	SELECT EXISTS(
		SELECT 
			*
		FROM guard_user_role ur 
		JOIN guard_role_permission rp ON ur.role_id = rp.role_id
		JOIN guard_permission p ON p.id = rp. permission_id 
		WHERE ur.user_id = ? AND p.name = ?
	) AS is_exist
`

// HasPermission function will return bool that represent this user has permission or not
// This function will check the user permission record by user and permissionName
func (u *User) HasPermission(permissionName string) (bool, error) {
	if u.DBContract == nil {
		return false, ErrNoSchema
	}

	if !u.exist {
		return false, UserNotFound
	}

	var permissionRecord existRecord
	result := u.DBContract.QueryRow(getUserPermissionQuery, u.ID, permissionName)
	err := result.Scan(&permissionRecord.IsExist)
	if err != nil {
		return false, err
	}
	return permissionRecord.IsExist, nil
}

// HasPermissionContext function will return bool that represent this user has specific permission or not
// This function will check the user permission record by user, permissionName and context
func (u *User) HasPermissionContext(ctx context.Context, permissionName string) (bool, error) {
	if u.DBContract == nil {
		return false, ErrNoSchema
	}

	if !u.exist {
		return false, UserNotFound
	}

	var permissionRecord existRecord
	result := u.DBContract.QueryRowContext(ctx, getUserPermissionQuery, u.ID, permissionName)
	err := result.Scan(&permissionRecord.IsExist)
	if err != nil {
		return false, err
	}
	return permissionRecord.IsExist, nil
}

const getUserRoleQuery = `
	SELECT EXISTS(
		SELECT 
			*
		FROM guard_user_role ur 
		JOIN guard_role r ON ur.role_id = r.id 
		WHERE ur.user_id = ? AND r.name = ? 
	) AS is_exist
`

// HasRole function will return bool that represent this user has specific roleName or not
// This function will check the user role record by user and roleName
func (u *User) HasRole(roleName string) (bool, error) {
	if u.DBContract == nil {
		return false, ErrNoSchema
	}

	if !u.exist {
		return false, UserNotFound
	}

	var roleRecord existRecord
	result := u.DBContract.QueryRow(getUserRoleQuery, u.ID, roleName)
	err := result.Scan(&roleRecord.IsExist)
	if err != nil {
		return false, err
	}
	return roleRecord.IsExist, nil
}

// HasRoleContext function wi	ll return bool that represent this user has specific roleName or not
// This function will check the user role record by user, roleName and context
func (u *User) HasRoleContext(ctx context.Context, roleName string) (bool, error) {
	if u.DBContract == nil {
		return false, ErrNoSchema
	}

	if !u.exist {
		return false, UserNotFound
	}

	var roleRecord existRecord
	result := u.DBContract.QueryRowContext(ctx, getUserRoleQuery, u.ID, roleName)
	err := result.Scan(&roleRecord.IsExist)
	if err != nil {
		return false, err
	}
	return roleRecord.IsExist, nil
}

const getUserRolesQuery = `
	SELECT
		r.id,
		r.name,
		r.description,
		r.created_at,
		r.updated_at
	FROM guard_role r
	JOIN guard_user_role ur ON ur.role_id = r.id 
	WHERE ur.user_id = ?
`

// GetRoles function will return roles by this user ID
// This function will check the user role record by this specific userID
func (u *User) GetRoles() ([]Role, error) {
	if u.DBContract == nil {
		return nil, ErrNoSchema
	}

	if !u.exist {
		return nil, UserNotFound
	}

	var roles []Role

	roles = make([]Role, 0)
	result, err := u.DBContract.Query(getUserRolesQuery, u.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return roles, nil
		}
		return nil, err
	}

	var role Role
	role.DBContract = u.DBContract
	for result.Next() {
		err = result.Scan(
			&role.ID,
			&role.Name,
			&role.Description,
			&role.Description,
			&role.CreatedAt,
			&role.UpdatedAt,
		)
		if err == nil {
			role.exist = true
			roles = append(roles, role)
		}
		return nil, err
	}
	return roles, nil
}

// GetRolesContext function will return roles by this user ID and context
// This function will check the user role record by this specific userID and context
func (u *User) GetRolesContext(ctx context.Context) ([]Role, error) {
	if u.DBContract == nil {
		return nil, ErrNoSchema
	}

	if !u.exist {
		return nil, UserNotFound
	}

	var roles []Role

	roles = make([]Role, 0)
	result, err := u.DBContract.QueryContext(ctx, getUserRolesQuery, u.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return roles, nil
		}
		return nil, err
	}

	var role Role
	for result.Next() {
		err = result.Scan(&role)
		if err == nil {
			role.exist = true
			roles = append(roles, role)
		}
	}
	return roles, nil
}

const getUserPermissionsQuery = `
	SELECT
		p.id,
		p.name,
		p.method,
		p.route,
		p.description,
		p.created_at,
		p.updated_at
	FROM guard_permission p 
	JOIN guard_role_permission pr ON pr.permission_id = p.id
	JOIN guard_user_role ru ON ru.role_id = pr.role_id
	WHERE ru.user_id = ?
`

// GetPermissions function will return permissions by this user ID
// This function will check the user permission record by specific userID
func (u *User) GetPermissions() ([]Permission, error) {
	if u.DBContract == nil {
		return nil, ErrNoSchema
	}

	if !u.exist {
		return nil, UserNotFound
	}

	permissions := make([]Permission, 0)
	result, err := u.DBContract.Query(getUserPermissionsQuery, u.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return permissions, nil
		}
		return nil, err
	}

	var permission Permission
	permission.DBContract = u.DBContract
	for result.Next() {
		err = result.Scan(
			&permission.ID,
			&permission.Name,
			&permission.Method,
			&permission.Route,
			&permission.Description,
			&permission.Description,
			&permission.CreatedAt,
			&permission.UpdatedAt,
		)
		if err == nil {
			permission.exist = true
			permissions = append(permissions, permission)
		}
		return nil, err
	}
	return permissions, nil
}

// GetPermissionsContext function will return permissions by this user ID and specific context
// This function will check the user permission record by this specific userID
func (u *User) GetPermissionsContext(ctx context.Context) ([]Permission, error) {
	if u.DBContract == nil {
		return nil, ErrNoSchema
	}

	if !u.exist {
		return nil, UserNotFound
	}

	permissions := make([]Permission, 0)
	result, err := u.DBContract.QueryContext(ctx, getUserPermissionsQuery, u.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return permissions, nil
		}
		return nil, err
	}

	var permission Permission
	permission.DBContract = u.DBContract
	for result.Next() {
		err = result.Scan(
			&permission.ID,
			&permission.Name,
			&permission.Method,
			&permission.Route,
			&permission.Description,
			&permission.Description,
			&permission.CreatedAt,
			&permission.UpdatedAt,
		)
		if err == nil {
			permission.exist = true
			permissions = append(permissions, permission)
		}
		return nil, err
	}
	return permissions, nil
}

/* Fetcher */

const fetchUserByUsernameOrEmail = `
	SELECT 
		id, 
		email, 
		username, 
		password, 
		active,
		created_at,
		updated_at
	FROM guard_user WHERE email = ? OR username = ? LIMIT 1
`

// FindUserByUsernameOrEmail function will return existing user record by username or email
// This function will select data from user record by username or email column
func (u *User) FindUserByUsernameOrEmail(params string) (*User, error) {
	if u.DBContract == nil {
		return nil, ErrNoSchema
	}

	var user = new(User)
	result := u.DBContract.QueryRow(fetchUserByUsernameOrEmail, params, params)
	err := result.Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.Password,
		&user.Active,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	user.DBContract = u.DBContract
	user.exist = true
	return user, nil
}

// FindUserByUsernameOrEmail function will return existing user record by username or email with specific context
// This function will select data from user record by username or email column with specific context
func (u *User) FindUserByUsernameOrEmailContext(ctx context.Context, params string) (*User, error) {
	if u.DBContract == nil {
		return nil, ErrNoSchema
	}

	var user = new(User)
	result := u.DBContract.QueryRowContext(ctx, fetchUserByUsernameOrEmail, params, params)
	err := result.Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.Password,
		&user.Active,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	user.DBContract = u.DBContract
	user.exist = true
	return user, nil
}

const fetchDynamicUserParams = `
		SELECT 
			id, 
			email, 
			username, 
			password, 
			active,
			created_at,
			updated_at
		FROM guard_user WHERE 
`

// FindUser function will return existing user record by given parameters
// This function will select data from user record by given parameters
func (u *User) FindUser(params map[string]interface{}) (*User, error) {
	if u.DBContract == nil {
		return nil, ErrNoSchema
	}

	var user = new(User)
	var result *sql.Row
	paramsLength := len(params)
	if paramsLength == 0 {
		return nil, ErrInvalidParams
	}

	query := fetchDynamicUserParams
	values := make([]interface{}, 0)
	index := 0
	for k := range params {
		query += fmt.Sprintf("%s = ?", k)
		if index < paramsLength-1 {
			query += ` AND `
		}
		values = append(values, params[k])
	}

	query += " LIMIT 1"
	result = u.DBContract.QueryRow(query, values...)
	err := result.Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.Password,
		&user.Active,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	user.DBContract = u.DBContract
	user.exist = true
	return user, nil
}

// FindUser function will return existing user record by given parameters and specific context
// This function will select data from user record by given parameters with specific context
func (u *User) FindUserContext(ctx context.Context, params map[string]interface{}) (*User, error) {
	if u.DBContract == nil {
		return nil, ErrNoSchema
	}

	var user = new(User)
	var result *sql.Row
	paramsLength := len(params)
	if paramsLength == 0 {
		return nil, ErrInvalidParams
	}

	query := fetchDynamicUserParams
	values := make([]interface{}, 0)
	index := 0
	for k := range params {
		query += fmt.Sprintf("%s = ?", k)
		if index < paramsLength-1 {
			query += ` AND `
		}
		values = append(values, params[k])
	}

	query += " LIMIT 1"
	result = u.DBContract.QueryRowContext(ctx, query, values...)
	err := result.Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.Password,
		&user.Active,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	user.DBContract = u.DBContract
	user.exist = true
	return user, nil
}
