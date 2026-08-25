module goacore

go 1.25.0

// Épingle le toolchain au patch qui corrige les vulnérabilités de la bibliothèque
// standard remontées par govulncheck (et que le builder du Dockerfile embarque).
toolchain go1.25.13

require (
	github.com/bwmarrin/discordgo v0.29.0
	github.com/go-chi/chi/v5 v5.3.1
	github.com/go-sql-driver/mysql v1.10.0
	github.com/gorilla/sessions v1.4.0
	github.com/gorilla/websocket v1.5.3
	github.com/pquerna/otp v1.5.0
	golang.org/x/crypto v0.54.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/boombuler/barcode v1.0.1 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
