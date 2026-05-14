package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type UserInfo struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	Enabled   bool   `json:"enabled"`
	CreatedAt int64  `json:"created_at"`
}

func ensureUsersTable() {
	if deps.ConfigDB == nil {
		return
	}
	deps.ConfigDB.Exec(`CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'admin',
		enabled INTEGER DEFAULT 1,
		created_at INTEGER
	)`)
}

func ValidateUserCredentials(username, password string) bool {
	ensureUsersTable()

	if deps.ConfigDB != nil {
		var hash string
		var enabled int
		err := deps.ConfigDB.QueryRow("SELECT password_hash, enabled FROM users WHERE username = ?", username).Scan(&hash, &enabled)
		if err == nil {
			if enabled != 1 {
				return false
			}
			return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
		}
	}

	cfgMu.RLock()
	defer cfgMu.RUnlock()
	if deps.Config.Admin.PasswordHash != "" {
		if username == deps.Config.Admin.Username && checkPassword(password, deps.Config.Admin.PasswordHash) {
			return true
		}
	}
	return false
}

func GetUserRole(username string) string {
	if deps.ConfigDB != nil {
		var role string
		err := deps.ConfigDB.QueryRow("SELECT role FROM users WHERE username = ?", username).Scan(&role)
		if err == nil {
			return role
		}
	}
	if username == deps.Config.Admin.Username {
		return "admin"
	}
	return ""
}

func APIUserList(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ensureUsersTable()
	if deps.ConfigDB == nil {
		jsonError(w, "数据库未初始化", http.StatusInternalServerError)
		return
	}
	rows, err := deps.ConfigDB.Query("SELECT id, username, role, enabled, created_at FROM users ORDER BY created_at DESC")
	if err != nil {
		jsonError(w, "查询失败", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var users []UserInfo
	for rows.Next() {
		var u UserInfo
		var enabled int
		if rows.Scan(&u.ID, &u.Username, &u.Role, &enabled, &u.CreatedAt) == nil {
			u.Enabled = enabled == 1
			users = append(users, u)
		}
	}
	jsonSuccess(w, users)
}

func APIUserAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ensureUsersTable()
	if deps.ConfigDB == nil {
		jsonError(w, "数据库未初始化", http.StatusInternalServerError)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "解析请求失败", http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.Password == "" {
		jsonError(w, "用户名和密码不能为空", http.StatusBadRequest)
		return
	}
	if len(req.Username) > 64 || len(req.Password) > 128 {
		jsonError(w, "用户名或密码过长", http.StatusBadRequest)
		return
	}
	if req.Role != "admin" && req.Role != "readonly" {
		req.Role = "readonly"
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, "密码加密失败", http.StatusInternalServerError)
		return
	}
	id := "usr_" + time.Now().Format("20060102150405")
	now := time.Now().Unix()
	if _, err := deps.ConfigDB.Exec("INSERT INTO users (id, username, password_hash, role, enabled, created_at) VALUES (?,?,?,?,1,?)", id, req.Username, string(hash), req.Role, now); err != nil {
		jsonError(w, "创建用户失败（可能已存在）", http.StatusBadRequest)
		return
	}
	jsonSuccess(w, map[string]string{"id": id, "message": "用户创建成功"})
}

func APIUserDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if deps.ConfigDB == nil {
		jsonError(w, "数据库未初始化", http.StatusInternalServerError)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "解析请求失败", http.StatusBadRequest)
		return
	}
	deps.ConfigDB.Exec("DELETE FROM users WHERE id=?", req.ID)
	jsonSuccess(w, nil)
}

func APIUserToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if deps.ConfigDB == nil {
		jsonError(w, "数据库未初始化", http.StatusInternalServerError)
		return
	}
	var req struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "解析请求失败", http.StatusBadRequest)
		return
	}
	e := 0
	if req.Enabled {
		e = 1
	}
	deps.ConfigDB.Exec("UPDATE users SET enabled=? WHERE id=?", e, req.ID)
	jsonSuccess(w, nil)
}

func APIPasswordChangeForUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if deps.ConfigDB == nil {
		jsonError(w, "数据库未初始化", http.StatusInternalServerError)
		return
	}
	var req struct {
		ID          string `json:"id"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "解析请求失败", http.StatusBadRequest)
		return
	}
	if len(req.NewPassword) < 8 || len(req.NewPassword) > 128 {
		jsonError(w, "密码长度应在8-128之间", http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, "密码加密失败", http.StatusInternalServerError)
		return
	}
	deps.ConfigDB.Exec("UPDATE users SET password_hash=? WHERE id=?", string(hash), req.ID)
	jsonSuccess(w, nil)
}
