// Package assets embeds the application templates for production use.
package assets

import "embed"

//go:embed templates/*
var TemplatesFS embed.FS
