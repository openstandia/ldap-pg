package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/jmoiron/sqlx"
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
	repo := &SimpleRepository{}
	repo.server = server
	repo.db = db

	err = repo.Init()
	if err != nil {
		return nil, err
	}

	return repo, nil
}

type Repository interface {
	// Init is called when initializing repository implementation.
	Init() error

	BeginTx() *sqlx.Tx

	// FindCredByDN returns the credential by specified DN.
	// This is used for BIND operation.
	FindCredByDN(dn *DN) ([]string, error)

	FindRDNsByIDs(tx *sqlx.Tx, id []int64, lock bool) ([]*FetchedRDNOrig, error)
	FindDNByID(tx *sqlx.Tx, id int64, lock bool) (*FetchedDNOrig, error)
	// FindDNByDNWithLock returns FetchedDN object from database by DN search.
	FindDNByDNWithLock(tx *sqlx.Tx, dn *DN, lock bool) (*FetchedDN, error)
	FindIDsByParentIDAndRDNNorms(tx *sqlx.Tx, parentID int64, rdnNorms []string) ([]int64, error)
	Search(baseDN *DN, scope int, q *Query, reqMemberAttrs []string,
		reqMemberOf, isHasSubordinatesRequested bool, handler func(entry *SearchEntry) error) (int32, int32, error)
	FindDNsByIDs(tx *sqlx.Tx, id []int64, lock bool) ([]*FetchedDNOrig, error)

	// Update modifies the entry by specified change data.
	Update(tx *sqlx.Tx, oldEntry, newEntry *ModifyEntry) error
	// FindEntryByDN returns FetchedDBEntry object from database by DN search.
	FindEntryByDN(tx *sqlx.Tx, dn *DN, lock bool) (*ModifyEntry, error)

	// UpdateDN modifies the entry DN by specified change data.
	UpdateDN(oldDN, newDN *DN, oldRDN *RelativeDN) error

	// Insert creates the entry by specified entry data.
	Insert(entry *AddEntry) (int64, error)

	// DeleteByDN deletes the entry by specified DN.
	DeleteByDN(dn *DN) error
}
