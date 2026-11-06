module github.com/xtls/reality

go 1.27

require (
	github.com/juju/ratelimit v1.0.2
	github.com/pires/go-proxyproto v0.15.0
	github.com/refraction-networking/utls v1.8.2
	golang.org/x/crypto v0.57.0
	golang.org/x/sys v0.48.0
)

require (
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/molecule-man/go-brrr v1.2.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)

replace github.com/refraction-networking/utls => github.com/xtls/utls v0.0.0-20261106014349-570772d34ef8
