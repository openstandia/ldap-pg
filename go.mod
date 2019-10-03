module github.com/openstandia/ldap-postgresql

go 1.13

require (
	github.com/comail/colog v0.0.0-20160416085026-fba8e7b1f46c
	github.com/cpuguy83/go-md2man/v2 v2.0.0 // indirect
	github.com/google/uuid v1.1.1
	github.com/hamano/lb v0.0.0-20190806052113-b9f12e445cf4 // indirect
	github.com/jmoiron/sqlx v1.2.0
	github.com/jsimonetti/pwscheme v0.0.0-20160922125227-76804708ecad
	github.com/lib/pq v1.2.0
	github.com/openstandia/goldap/message v0.0.0-20191003154542-b76848166a0d
	github.com/openstandia/ldapserver v0.0.0-20190930164349-8581cc1a444f
	github.com/pkg/errors v0.8.1
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/urfave/cli v1.22.1 // indirect
	google.golang.org/appengine v1.6.4 // indirect
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/ldap.v3 v3.0.3
)

// replace (
// 	github.com/openstandia/goldap/message => ../goldap/message
// 	github.com/openstandia/ldapserver => ../ldapserver
// )
