package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
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
	db *sqlx.DB
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
	repo.db = db

	err = repo.InitTables(db)
	if err != nil {
		return nil, err
	}

	err = repo.InitStmt(db)
	if err != nil {
		return nil, err
	}

	return repo, nil
}

type Repository interface {
	InitTables(db *sqlx.DB) error
	InitStmt(db *sqlx.DB) error

	BeginTx() *sqlx.Tx

	FindCredByDN(dn *DN) ([]string, error)
	FindRDNsByIDs(tx *sqlx.Tx, id []int64, lock bool) ([]*FetchedRDNOrig, error)
	FindDNByID(tx *sqlx.Tx, id int64, lock bool) (*FetchedDNOrig, error)
	// FindDNByDNWithLock returns FetchedDN object from database by DN search.
	FindDNByDNWithLock(tx *sqlx.Tx, dn *DN, lock bool) (*FetchedDN, error)
	FindIDsByParentIDAndRDNNorms(tx *sqlx.Tx, parentID int64, rdnNorms []string) ([]int64, error)
	Search(baseDN *DN, scope int, q *Query, reqMemberAttrs []string,
		reqMemberOf, isHasSubordinatesRequested bool, handler func(entry *SearchEntry) error) (int32, int32, error)
	FindDNsByIDs(tx *sqlx.Tx, id []int64, lock bool) ([]*FetchedDNOrig, error)

	Update(tx *sqlx.Tx, oldEntry, newEntry *ModifyEntry) error
	// FindEntryByDN returns FetchedDBEntry object from database by DN search.
	FindEntryByDN(tx *sqlx.Tx, dn *DN, lock bool) (*ModifyEntry, error)

	UpdateDN(oldDN, newDN *DN, oldRDN *RelativeDN) error

	Insert(entry *AddEntry) (int64, error)

	DeleteByDN(dn *DN) error
}

type DBEntry struct {
	ID        int64          `db:"id"`
	DNNorm    string         `db:"dn_norm"`
	DNOrig    string         `db:"dn_orig"`
	EntryUUID string         `db:"uuid"`
	Created   time.Time      `db:"created"`
	Updated   time.Time      `db:"updated"`
	AttrsNorm types.JSONText `db:"attrs_norm"`
	AttrsOrig types.JSONText `db:"attrs_orig"`
	Count     int32          `db:"count"`    // No real column in the table
	MemberOf  types.JSONText `db:"memberof"` // No real column in the table
}

type FetchedDBEntry struct {
	ID              int64          `db:"id"`
	ParentID        int64          `db:"parent_id"`
	RDNOrig         string         `db:"rdn_orig"`
	RawAttrsOrig    types.JSONText `db:"attrs_orig"`
	RawMember       types.JSONText `db:"member"`          // No real column in the table
	RawUniqueMember types.JSONText `db:"uniquemember"`    // No real column in the table
	RawMemberOf     types.JSONText `db:"member_of"`       // No real column in the table
	HasSubordinates string         `db:"hassubordinates"` // No real column in the table
	DNOrig          string         `db:"dn_orig"`         // No real clumn in t he table
	Count           int32          `db:"count"`           // No real column in the table
	ParentDNOrig    string         // No real column in the table
}
