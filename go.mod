module github.com/openstandia/ldap-pg

go 1.13

require (
	github.com/comail/colog v0.0.0-20160416085026-fba8e7b1f46c
	github.com/google/uuid v1.1.1
	github.com/jmoiron/sqlx v1.2.0
	github.com/jsimonetti/pwscheme v0.0.0-20160922125227-76804708ecad
	github.com/lib/pq v1.2.0
	github.com/openstandia/goldap/message v0.0.0-20191023020826-0fe515582e2f
	github.com/openstandia/ldapserver v0.0.0-20190930164349-8581cc1a444f
	github.com/pkg/errors v0.8.1
	golang.org/x/xerrors v0.0.0-20191011141410-1b5146add898
	google.golang.org/appengine v1.6.5 // indirect
	gopkg.in/ldap.v3 v3.1.0
)

// replace (
//     github.com/openstandia/goldap/message => ../goldap/message
//     github.com/openstandia/ldapserver => ../ldapserver
// )
