// Package frpcelplugin holds root-level embedded assets.
package frpcelplugin

import _ "embed"

// ConfigSchema is the JSON Schema (draft 2020-12) for the YAML config file.
//
//go:embed config.schema.json
var ConfigSchema []byte
