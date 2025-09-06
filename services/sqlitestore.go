// services/sqlitestore.go
package services

import (
	"database/sql"
	"fmt"
	"os"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

// SQLiteKeyStore implements a persistent key store using SQLite.
type SQLiteKeyStore struct {
	db *sql.DB
	mu sync.RWMutex
}

// NewSQLiteKeyStore initializes and returns a new SQLiteKeyStore.
func NewSQLiteKeyStore(dbPath string) (*SQLiteKeyStore, error) {
	// 确保数据库文件所在的目录存在
	dir := "data"
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.Mkdir(dir, 0755)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// 创建一个表来存储用户ID和加密的私钥
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS private_keys (
		student_id TEXT PRIMARY KEY,
		private_key_pem BLOB NOT NULL
	);`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		return nil, fmt.Errorf("failed to create table: %w", err)
	}

	return &SQLiteKeyStore{db: db}, nil
}

// SavePrivateKey saves a PEM-encoded private key to the database.
func (ks *SQLiteKeyStore) SavePrivateKey(studentID string, privateKeyPEM []byte) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	stmt, err := ks.db.Prepare("INSERT INTO private_keys(student_id, private_key_pem) VALUES(?, ?)")
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(studentID, privateKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	return nil
}

// GetPrivateKey retrieves a PEM-encoded private key from the database.
func (ks *SQLiteKeyStore) GetPrivateKey(studentID string) ([]byte, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	var privateKeyPEM []byte
	row := ks.db.QueryRow("SELECT private_key_pem FROM private_keys WHERE student_id = ?", studentID)
	if err := row.Scan(&privateKeyPEM); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("private key not found for student ID: %s", studentID)
		}
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}
	return privateKeyPEM, nil
}

// Close closes the database connection.
func (ks *SQLiteKeyStore) Close() error {
	return ks.db.Close()
}
