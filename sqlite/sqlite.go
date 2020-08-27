package sqlite

import (
	"database/sql"
	"fmt"
)

const (
	// The reduced number of kdf iterations (for performance reasons) which is
	// currently used for derivation of the database key
	// https://github.com/status-im/status-go/pull/1343
	// https://notes.status.im/i8Y_l7ccTiOYq09HVgoFwA
	kdfIterationsNumber = 3200
	// WALMode for sqlite.
	WALMode = "wal"
)

func openDB(path, key string) (*sql.DB, error) {
	return OpenUnecryptedDB(path)
}

// OpenDB opens not-encrypted database.
func OpenDB(path, key string) (*sql.DB, error) {
	return openDB(path, key)
}

// OpenUnecryptedDB opens database with setting PRAGMA key.
func OpenUnecryptedDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	// Disable concurrent access as not supported by the driver
	db.SetMaxOpenConns(1)

	if _, err = db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		return nil, err
	}
	// readers do not block writers and faster i/o operations
	// https://www.sqlite.org/draft/wal.html
	// must be set after db is encrypted
	var mode string
	err = db.QueryRow("PRAGMA journal_mode=WAL").Scan(&mode)
	if err != nil {
		return nil, err
	}
	if mode != WALMode {
		return nil, fmt.Errorf("unable to set journal_mode to WAL. actual mode %s", mode)
	}

	return db, nil
}
