package handler

import (
	"encoding/json"
	"net/http"

	"gowaf-demo/internal/backend"
	"gowaf-demo/internal/web/templates"
)

func BackendPage(w http.ResponseWriter, r *http.Request) {
	// 使用模板渲染
	data := map[string]interface{}{
		"Active": "backend",
	}
	templates.BackendTmpl.ExecuteTemplate(w, "backend", data)
}

// APIBackendList 获取后端列表
func APIBackendList(w http.ResponseWriter, r *http.Request) {
	backends := BackendManager.GetBackends()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(backends)
}

// APIBackendAdd 添加后端
func APIBackendAdd(w http.ResponseWriter, r *http.Request) {
	var req backend.Backend
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "无效的请求数据"})
		return
	}

	if err := BackendManager.AddBackend(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		// 优化错误提示
		errMsg := err.Error()
		if errMsg == "constraint failed: UNIQUE constraint failed: backends.address (2067)" {
			errMsg = "该后端地址已存在，请使用不同的地址"
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": errMsg})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// APIBackendUpdate 更新后端
func APIBackendUpdate(w http.ResponseWriter, r *http.Request) {
	var req backend.Backend
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "无效的请求数据"})
		return
	}

	if err := BackendManager.UpdateBackend(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		// 优化错误提示
		errMsg := err.Error()
		if errMsg == "constraint failed: UNIQUE constraint failed: backends.address (2067)" {
			errMsg = "该后端地址已被其他服务使用，请使用不同的地址"
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": errMsg})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// APIBackendDelete 删除后端
func APIBackendDelete(w http.ResponseWriter, r *http.Request) {
	// 从URL参数获取ID
	id := r.URL.Query().Get("id")
	if id == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "缺少ID参数"})
		return
	}

	if err := BackendManager.RemoveBackend(id); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}
