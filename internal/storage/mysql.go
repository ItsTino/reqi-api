package storage

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"sort"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

type Config struct {
    Host     string
    Port     string
    User     string
    Password string
    DBName   string
}

func NewDB(config Config) (*sql.DB, error) {
    dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&multiStatements=true",
        config.User,
        config.Password,
        config.Host,
        config.Port,
        config.DBName,
    )

    db, err := sql.Open("mysql", dsn)
    if err != nil {
        return nil, fmt.Errorf("error opening database: %v", err)
    }

    if err := db.Ping(); err != nil {
        return nil, fmt.Errorf("error connecting to the database: %v", err)
    }

    return db, nil
}

func RunMigrations(db *sql.DB, migrationsPath string) error {
    // Drop existing migrations table if exists
    _, err := db.Exec(`DROP TABLE IF EXISTS schema_migrations`)
    if err != nil {
        return fmt.Errorf("error dropping migrations table: %v", err)
    }

    // Create migrations table
    _, err = db.Exec(`
        CREATE TABLE schema_migrations (
            version INT PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            dirty BOOLEAN NOT NULL DEFAULT FALSE
        )
    `)
    if err != nil {
        return fmt.Errorf("error creating migrations table: %v", err)
    }

    // Get list of migration files
    files, err := ioutil.ReadDir(migrationsPath)
    if err != nil {
        return fmt.Errorf("error reading migrations directory: %v", err)
    }

    // Filter and sort migration files
    var migrations []string
    for _, file := range files {
        if strings.HasSuffix(file.Name(), ".up.sql") {
            migrations = append(migrations, file.Name())
        }
    }
    sort.Strings(migrations)

    // Apply migrations
    for _, migration := range migrations {
        // Extract version number from filename
        var version int
        fmt.Sscanf(migration, "%d", &version)

        // Read migration file
        content, err := ioutil.ReadFile(filepath.Join(migrationsPath, migration))
        if err != nil {
            return fmt.Errorf("error reading migration file %s: %v", migration, err)
        }

        // Execute migration
        tx, err := db.Begin()
        if err != nil {
            return fmt.Errorf("error starting transaction: %v", err)
        }

        // Mark migration as dirty before executing
        if _, err := tx.Exec("INSERT INTO schema_migrations (version, dirty) VALUES (?, true)", version); err != nil {
            tx.Rollback()
            return fmt.Errorf("error marking migration as dirty %s: %v", migration, err)
        }

        // Execute the migration
        if _, err := tx.Exec(string(content)); err != nil {
            tx.Rollback()
            return fmt.Errorf("error executing migration %s: %v", migration, err)
        }

        // Mark migration as clean after successful execution
        if _, err := tx.Exec("UPDATE schema_migrations SET dirty = false WHERE version = ?", version); err != nil {
            tx.Rollback()
            return fmt.Errorf("error marking migration as clean %s: %v", migration, err)
        }

        if err := tx.Commit(); err != nil {
            return fmt.Errorf("error committing migration %s: %v", migration, err)
        }

        log.Printf("Applied migration: %s", migration)
    }

    return nil
}