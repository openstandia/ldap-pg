package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/openstandia/goldap/message"
)

var maxRetry = 10

// For generic filter
type StmtCache struct {
	sm sync.Map
}

func (m *StmtCache) Get(key string) (*sqlx.NamedStmt, bool) {
	val, ok := m.sm.Load(key)
	if !ok {
		return nil, false
	}
	return val.(*sqlx.NamedStmt), true
}

func (m *StmtCache) Put(key string, value *sqlx.NamedStmt) {
	m.sm.Store(key, value)
}

type DBRepository struct {
	server *Server
	db     *sqlx.DB
}

func NewRepository(server *Server) (Repository, error) {
	// Init DB Connection
	db, err := sqlx.Connect("postgres", fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=disable search_path=%s",
		server.config.DBHostName, server.config.DBPort, server.config.DBUser, server.config.DBName,
		server.config.DBPassword, server.config.DBSchema))
	if err != nil {
		log.Fatalf("alert: Connect error. host=%s, port=%d, user=%s, dbname=%s, error=%s",
			server.config.DBHostName, server.config.DBPort, server.config.DBUser, server.config.DBName, err)
	}
	db.SetMaxOpenConns(server.config.DBMaxOpenConns)
	db.SetMaxIdleConns(server.config.DBMaxIdleConns)
	// db.SetConnMaxLifetime(time.Hour)

	// TODO: Enable to switch another implementation
	repo := &HybridRepository{
		DBRepository: &DBRepository{
			server: server,
			db:     db,
		},
		translator: &HybridDBFilterTranslator{},
	}

	err = repo.Init()
	if err != nil {
		return nil, err
	}

	return repo, nil
}

type Repository interface {
	// Init is called when initializing repository implementation.
	Init() error

	// Bind fetches the current bind entry by specified DN. Then execute callback with the entry.
	// The callback is expected checking the credential, account lock status and so on.
	// This is used for BIND operation.
	Bind(ctx context.Context, dn *DN, callback func(current *FetchedCredential) error) error

	// FindPPolicyByDN returns the password policy entry by specified DN.
	// This is used for password policy process.
	FindPPolicyByDN(ctx context.Context, dn *DN) (*PPolicy, error)

	// Search handles search request by filter.
	// This is used for SEARCH operation.
	Search(ctx context.Context, baseDN *DN, option *SearchOption, handler func(entry *SearchEntry) error) (int32, int32, error)

	// Update modifies the entry by specified change data.
	// This is used for MOD operation.
	Update(ctx context.Context, dn *DN, callback func(current *ModifyEntry) error) error

	// UpdateDN modifies the entry DN by specified change data.
	// This is used for MODRDN operation.
	UpdateDN(ctx context.Context, oldDN, newDN *DN, oldRDN *RelativeDN) error

	// Insert creates the entry by specified entry data.
	Insert(ctx context.Context, entry *AddEntry) (int64, error)

	// DeleteByDN deletes the entry by specified DN.
	DeleteByDN(ctx context.Context, dn *DN) error
}

type SearchOption struct {
	Scope                      int
	Filter                     message.Filter
	PageSize                   int32
	Offset                     int32
	RequestedAssocation        []string
	IsMemberOfRequested        bool
	IsHasSubordinatesRequested bool
}

type FetchedDNOrig struct {
	ID     int64  `db:"id"`
	DNOrig string `db:"dn_orig"`
}

type FetchedCredential struct {
	ID int64
	// Credential
	Credential []string
	// DN of the MemberOf
	MemberOf []*DN
	// PPolicy related to this entry
	PPolicy              *PPolicy
	PwdAccountLockedTime *time.Time
	LastPwdFailureTime   *time.Time
	PwdFailureCount      int
}
