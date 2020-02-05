package migration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"

	"github.com/dhanarJkusuma/guardian/schema"
)

var (
	ErrMigration = "error while migrating rbac-database, reason = %s"

	ErrMigrationAlreadyExist = errors.New("error while running migration, migration already exist")
	ErrMigrationHistory      = errors.New("error while record migration history")
)

const migrationUp = "mysql_migration.up.sql"
const migrationIndexUp = "mysql_migration_index.up.sql"
const migrationDown = "mysql_migration.down.sql"

type indexSchema struct {
	IndexName string `db:"index_name"`
}

// requiredIndexes is used for check existing required indexes in the database
var requiredIndexes = map[string]bool{
	"rbac_user_email_idx":                      false,
	"rbac_user_username_idx":                   false,
	"rbac_permission_route_method_idx":         false,
	"rbac_permission_name_idx":                 false,
	"rbac_role_name_idx":                       false,
	"rbac_user_role_role_user_idx":             false,
	"rbac_role_permission_role_permission_idx": false,
	"rbac_role_rbac_rule_idx":                  false,
	"rbac_role_rbac_rule_checker_idx":          false,
}

// Migration represent entity that has responsibility for schema migration
type Migration struct {
	dbConnection *sql.DB
	schemaName   string
}

type MigrationOptions struct {
	DBConnection *sql.DB
	Schema       string
}

// NewMigration acts as constructor with required params
func NewMigration(opts MigrationOptions) (*Migration, error) {
	m := &Migration{
		schemaName:   opts.Schema,
		dbConnection: opts.DBConnection,
	}
	return m, nil
}

// getCurrentPath is unexported helper function to return current path
func getCurrentPath() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}

	return path.Dir(filename)
}

// openSource is unexported helper function to open file and return the content as string
func openSource(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	b, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// scanSource is helper function to scan specific path and do some task per each file scanned
func (m *Migration) scanSource(rootPath string, callback func(currentPath string)) error {
	return filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		ext := filepath.Ext(path)
		if info.IsDir() || ext != ".sql" {
			return nil
		}
		callback(path)
		return nil
	})
}

// migrate is helper function to execute migration by name
func (m *Migration) migrate(filename string) error {
	migrationPath := fmt.Sprintf("%s/sql/%s", getCurrentPath(), filename)
	query, err := openSource(migrationPath)
	if err != nil {
		return err
	}
	// run migration version
	ctx := context.Background()
	_, err = m.dbConnection.ExecContext(ctx, query)
	return err
}

// Initialize function will create migration for RBAC auth
func (m *Migration) Initialize() error {
	var err error
	fmt.Println("Migration :: Migrating Schema")
	err = m.migrate(migrationUp)
	if err != nil {
		m.Down()
		return err
	}

	err = m.validateIndexes()
	if err != nil {
		fmt.Println("Migration :: Migrating indexes")
		err = m.migrate(migrationIndexUp)
		if err != nil {
			m.Down()
			return err
		}
		return nil
	}

	return err
}

// Down function is helper function to clear all databases schema that used by guardian schema
func (m *Migration) Down() {
	fmt.Println("Migration :: Down")
	err := m.migrate(migrationDown)
	if err != nil {
		fmt.Println("Err occur while clean up the migration")
	}
}

// Run function will run custom migration
func (m *Migration) Run(name string, executor func(ptx *GuardTx) error) error {
	var err error
	ptx := &GuardTx{}

	// init begin transaction db
	err = ptx.BeginTx(m.dbConnection)
	if err != nil {
		return err
	}
	defer ptx.FinishTx(err)

	// init migration schema
	migrationSchema := &schema.MigrationSchema{schema.Entity{DBContract: ptx.GetTx()}}

	// check existing migration
	alreadyRun, err := migrationSchema.CheckExistingMigration(name)
	if err != nil {
		return err
	}
	if alreadyRun {
		err = ErrMigrationAlreadyExist
		return ErrMigrationAlreadyExist
	}

	// run migration
	err = executor(ptx)
	if err == nil {
		errRecordMigration := migrationSchema.WriteMigration(name)
		if errRecordMigration != nil {
			log.Printf("%s : %s", ErrMigrationHistory.Error(), errRecordMigration)
			return ErrMigrationHistory
		}
	}
	return err
}

// validateIndexes will check all required indexes in the database
// It will select all indexes from the database and compare it with requiredIndexes variable.
// If the value of requiredIndexes with index_name is false, then it'll return error invalid index Schema.
func (m *Migration) validateIndexes() error {
	querySchema := `SELECT DISTINCT 
		INDEX_NAME AS index_name 
	FROM INFORMATION_SCHEMA.STATISTICS 
	WHERE TABLE_SCHEMA = ? 
	AND INDEX_NAME <> ?`

	rows, err := m.dbConnection.Query(querySchema, m.schemaName, "PRIMARY")
	if err != nil {
		log.Println(err)
		return errors.New(fmt.Sprintf(ErrMigration, "error while checking the tables"))
	}

	var index indexSchema
	for rows.Next() {
		err = rows.Scan(&index.IndexName)
		if err != nil {
			log.Println(err)
			return errors.New(fmt.Sprintf(ErrMigration, "error while checking the indexes"))
		}

		if _, ok := requiredIndexes[index.IndexName]; ok {
			requiredIndexes[index.IndexName] = true
		}
	}

	for _, v := range requiredIndexes {
		if !v {
			return errors.New("invalid RBAC index Schema")
		}
	}
	return nil
}
