package schema

import (
	"database/sql"
)

// MigrationSchema represents `rbac_migration` table in the database
type MigrationSchema struct {
	Entity
}

const fetchMigrationQuery = `
	SELECT EXISTS (
		SELECT migration_key FROM rbac_migration WHERE migration_key = ? LIMIT 1
	) AS is_exist
`

// CheckExistingMigration will check existing migration data by key
func (m *MigrationSchema) CheckExistingMigration(key string) (bool, error) {
	if m.DBContract == nil {
		return false, ErrNoSchema
	}

	var migrationRecord existRecord
	result := m.DBContract.QueryRow(fetchMigrationQuery, key)
	err := result.Scan(&migrationRecord.IsExist)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return migrationRecord.IsExist, nil
}

const insertMigrationQuery = `
	INSERT INTO rbac_migration(
		migration_key
	) VALUES (?)
`

// WriteMigration will create migration record with specific key
func (m *MigrationSchema) WriteMigration(key string) error {
	if m.DBContract == nil {
		return ErrNoSchema
	}

	_, err := m.DBContract.Exec(
		insertMigrationQuery,
		key,
	)
	return err
}
