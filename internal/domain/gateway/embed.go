package gateway

import (
	"compress/gzip"
	"embed"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
)

//go:embed static/** templates/*
var StaticFS embed.FS

// GetStaticFS 返回带有MIME类型支持的静态文件系统
func GetStaticFS() http.FileSystem {
	staticFS, _ := fs.Sub(StaticFS, "static")
	return http.FS(staticFS)
}

// FileServerWithMIME 返回支持MIME类型的文件服务器
func FileServerWithMIME(root http.FileSystem) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, err := root.Open(r.URL.Path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()

		stat, err := f.Stat()
		if err != nil {
			http.NotFound(w, r)
			return
		}

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

		ext := strings.ToLower(filepath.Ext(r.URL.Path))
		compressible := false
		switch ext {
		case ".css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=86400")
			compressible = true
		case ".js":
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=86400")
			compressible = true
		case ".html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache")
			compressible = true
		case ".json":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			compressible = true
		case ".svg":
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Header().Set("Cache-Control", "public, max-age=604800")
			compressible = true
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
		case ".woff":
			w.Header().Set("Content-Type", "font/woff")
			w.Header().Set("Cache-Control", "public, max-age=31536000")
		case ".woff2":
			w.Header().Set("Content-Type", "font/woff2")
			w.Header().Set("Cache-Control", "public, max-age=31536000")
		case ".ttf":
			w.Header().Set("Content-Type", "font/ttf")
			w.Header().Set("Cache-Control", "public, max-age=31536000")
		case ".eot":
			w.Header().Set("Content-Type", "application/vnd.ms-fontobject")
			w.Header().Set("Cache-Control", "public, max-age=31536000")
		}

		hasRange := r.Header.Get("Range") != ""
		if compressible && !hasRange && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Vary", "Accept-Encoding")
			gz := gzip.NewWriter(w)
			defer gz.Close()
			http.ServeContent(gzResponseWriter{ResponseWriter: w, gw: gz}, r, stat.Name(), stat.ModTime(), f)
		} else {
			http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
		}
	})
}

type gzResponseWriter struct {
	http.ResponseWriter
	gw *gzip.Writer
}

func (w gzResponseWriter) Write(b []byte) (int, error) {
	return w.gw.Write(b)
}
