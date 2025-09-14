// services/sqlitestore.go
package services

import (
	"database/sql"
	"fmt"
	"os"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

// UserData represents user data stored in the database.
type UserData struct {
	StudentID      string
	Username       string
	HashedPassword string
}

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

	// 移除了 private_keys 表的创建逻辑

	// 创建一个表来存储用户账户信息
	createUserTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		student_id TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		password_hash TEXT NOT NULL
	);`

	_, err = db.Exec(createUserTableSQL)
	if err != nil {
		return nil, fmt.Errorf("failed to create user table: %w", err)
	}

	return &SQLiteKeyStore{db: db}, nil
}

// SavePrivateKey 方法已被移除
// GetPrivateKey 方法已被移除

// SaveUser saves a user's account information to the database.
func (ks *SQLiteKeyStore) SaveUser(studentID, username, hashedPassword string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	stmt, err := ks.db.Prepare("INSERT INTO users(student_id, username, password_hash) VALUES(?, ?, ?)")
	if err != nil {
		return fmt.Errorf("failed to prepare user statement: %w", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(studentID, username, hashedPassword)
	if err != nil {
		return fmt.Errorf("failed to save user: %w", err)
	}

	return nil
}

// GetUser retrieves a user's account information from the database.
func (ks *SQLiteKeyStore) GetUser(studentID string) (*UserData, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	var user UserData
	row := ks.db.QueryRow("SELECT student_id, username, password_hash FROM users WHERE student_id = ?", studentID)
	if err := row.Scan(&user.StudentID, &user.Username, &user.HashedPassword); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found for student ID: %s", studentID)
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

// Close closes the database connection.
func (ks *SQLiteKeyStore) Close() error {
	return ks.db.Close()
}
