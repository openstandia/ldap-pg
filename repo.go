package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/jmoiron/sqlx"
	"github.com/openstandia/goldap/message"
)

var (
	// repo_create

	// repo_read
	findDNByIDStmt                 *sqlx.NamedStmt
	findRDNByIDStmt                *sqlx.NamedStmt
	findRDNsByIDsStmt              *sqlx.NamedStmt
	findContainerByPathStmt        *sqlx.NamedStmt
	findIDByParentIDAndRDNNormStmt *sqlx.NamedStmt

	filterStmtMap StmtCache
	treeStmtCache StmtCache

	// repo_update
	updateAttrsByIdStmt *sqlx.NamedStmt
	updateDNByIdStmt    *sqlx.NamedStmt
	updateRDNByIdStmt   *sqlx.NamedStmt

	// repo_delete
	deleteTreeByIDStmt         *sqlx.NamedStmt
	deleteByIDStmt             *sqlx.NamedStmt
	hasSubStmt                 *sqlx.NamedStmt
	removeMemberByIDStmt       *sqlx.NamedStmt
	removeUniqueMemberByIDStmt *sqlx.NamedStmt
)

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

func (r *DBRepository) BeginTx() *sqlx.Tx {
	return r.db.MustBegin()
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
	// repo := &SimpleRepository{}
	repo := &HybridRepository{
		DBRepository: &DBRepository{
			server: server,
			db:     db,
		},
	}
	// repo.server = server
	// repo.db = db

	err = repo.Init()
	if err != nil {
		return nil, err
	}

	return repo, nil
}

type Repository interface {
	// Init is called when initializing repository implementation.
	Init() error

	// FindCredByDN returns the credential by specified DN.
	// This is used for BIND operation.
	FindCredByDN(dn *DN) ([]string, error)

	// Search handles search request by filter.
	// This is used for SEARCH operation.
	Search(baseDN *DN, scope int, q message.Filter,
		pageSize, offset int32,
		reqMemberAttrs []string,
		reqMemberOf, isHasSubordinatesRequested bool, handler func(entry *SearchEntry) error) (int32, int32, error)

	// Update modifies the entry by specified change data.
	// This is used for MOD operation.
	Update(dn *DN, callback func(current *ModifyEntry) error) error

	// UpdateDN modifies the entry DN by specified change data.
	// This is used for MODRDN operation.
	UpdateDN(oldDN, newDN *DN, oldRDN *RelativeDN) error

	// Insert creates the entry by specified entry data.
	Insert(entry *AddEntry) (int64, error)

	// DeleteByDN deletes the entry by specified DN.
	DeleteByDN(dn *DN) error
}

type FetchedDNOrig struct {
	ID     int64  `db:"id"`
	DNOrig string `db:"dn_orig"`
}
