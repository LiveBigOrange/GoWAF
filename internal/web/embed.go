package web

import "embed"

//go:embed static/* templates/*
var StaticFS embed.FS
