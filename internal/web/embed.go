package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
)

//go:embed static/* templates/*
var StaticFS embed.FS

// GetStaticFS 返回带有MIME类型支持的静态文件系统
func GetStaticFS() http.FileSystem {
	// 获取static子目录
	staticFS, _ := fs.Sub(StaticFS, "static")
	return http.FS(staticFS)
}

// FileServerWithMIME 返回支持MIME类型的文件服务器
func FileServerWithMIME(root http.FileSystem) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 打开文件
		f, err := root.Open(r.URL.Path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()

		// 获取文件信息
		stat, err := f.Stat()
		if err != nil {
			http.NotFound(w, r)
			return
		}

		// 如果是目录，尝试打开index.html
		if stat.IsDir() {
			r.URL.Path += "index.html"
			f, err = root.Open(r.URL.Path)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			defer f.Close()
			stat, err = f.Stat()
			if err != nil {
				http.NotFound(w, r)
				return
			}
		}

		// 设置Content-Type
		ext := strings.ToLower(filepath.Ext(r.URL.Path))
		switch ext {
		case ".css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=86400")
		case ".js":
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=86400")
		case ".html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache")
		case ".json":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
		case ".svg":
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Header().Set("Cache-Control", "public, max-age=604800")
		case ".png":
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Cache-Control", "public, max-age=604800")
		case ".jpg", ".jpeg":
			w.Header().Set("Content-Type", "image/jpeg")
			w.Header().Set("Cache-Control", "public, max-age=604800")
		case ".gif":
			w.Header().Set("Content-Type", "image/gif")
			w.Header().Set("Cache-Control", "public, max-age=604800")
		case ".ico":
			w.Header().Set("Content-Type", "image/x-icon")
			w.Header().Set("Cache-Control", "public, max-age=604800")
		case ".woff", ".woff2":
			w.Header().Set("Content-Type", "font/woff2")
			w.Header().Set("Cache-Control", "public, max-age=31536000")
		case ".ttf":
			w.Header().Set("Content-Type", "font/ttf")
			w.Header().Set("Cache-Control", "public, max-age=31536000")
		case ".eot":
			w.Header().Set("Content-Type", "application/vnd.ms-fontobject")
			w.Header().Set("Cache-Control", "public, max-age=31536000")
		}

		// 使用http.ServeContent处理文件
		http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
	})
}
