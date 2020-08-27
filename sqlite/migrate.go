package sqlite

import (
	"database/sql"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite3"
	bindata "github.com/golang-migrate/migrate/v4/source/go_bindata"
)

// Migrate database using provided resources.
func Migrate(db *sql.DB, resources *bindata.AssetSource) error {
	source, err := bindata.WithInstance(resources)
	if err != nil {
		return err
	}

	driver, err := sqlite3.WithInstance(db, &sqlite3.Config{
		MigrationsTable: "status_go_" + sqlite3.DefaultMigrationsTable,
	})
	if err != nil {
		return err
	}

	m, err := migrate.NewWithInstance(
		"go-bindata",
		source,
		"sqlite3",
		driver)
	if err != nil {
		return err
	}

	if err = m.Up(); err != migrate.ErrNoChange {
		return err
	}
	return nil
}
