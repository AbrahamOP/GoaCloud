// Package assets embeds the application templates and static files for production use.
package assets

import "embed"

//go:embed templates/*
var TemplatesFS embed.FS

//go:embed static
var StaticFS embed.FS
