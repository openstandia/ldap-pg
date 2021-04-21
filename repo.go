package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
	"golang.org/x/xerrors"
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

type Repository struct {
	db *sqlx.DB
}

func NewRepository(server *Server) (RepositoryHandler, error) {
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

	var repo RepositoryHandler = &Repository{
		// server: server,
		db: db,
	}

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

type RepositoryHandler interface {
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

	Update(tx *sqlx.Tx, oldEntry, newEntry *ModifyEntry) error
	// FindEntryByDN returns FetchedDBEntry object from database by DN search.
	FindEntryByDN(tx *sqlx.Tx, dn *DN, lock bool) (*ModifyEntry, error)

	UpdateDN(oldDN, newDN *DN, oldRDN *RelativeDN) error

	Insert(entry *AddEntry) (int64, error)

	DeleteByDN(dn *DN) error
}

func (r *Repository) InitTables(db *sqlx.DB) error {
	_, err := db.Exec(`
	CREATE EXTENSION IF NOT EXISTS pgcrypto;
	CREATE EXTENSION IF NOT EXISTS ltree;
	
	CREATE TABLE IF NOT EXISTS ldap_tree (
		id BIGINT PRIMARY KEY,
		path ltree NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_ldap_tree_path ON ldap_tree USING GIST (path);
	
	CREATE TABLE IF NOT EXISTS ldap_entry (
		id BIGSERIAL PRIMARY KEY,
		parent_id BIGINT,
		rdn_norm VARCHAR(255) NOT NULL,
		rdn_orig VARCHAR(255) NOT NULL,
		attrs_norm JSONB NOT NULL,
		attrs_orig JSONB NOT NULL
	);
	
	-- basic index
	CREATE UNIQUE INDEX IF NOT EXISTS idx_ldap_entry_rdn_norm ON ldap_entry (parent_id, rdn_norm);
	
	-- all json index
	CREATE INDEX IF NOT EXISTS idx_ldap_entry_attrs ON ldap_entry USING gin (attrs_norm jsonb_path_ops);
	`)
	return err
}

func (r *Repository) InitStmt(db *sqlx.DB) error {
	var err error

	// Can't find root by this query
	findDNByIDStmt, err = db.PrepareNamed(`SELECT
		e.id, e.rdn_orig || ',' || string_agg(pe.rdn_orig, ',' ORDER BY dn.ord DESC) AS dn_orig
		FROM
			ldap_entry e
			INNER JOIN ldap_tree t ON t.id = e.parent_id
			JOIN regexp_split_to_table(t.path::::text, '[.]') WITH ORDINALITY dn(id, ord) ON true
			JOIN ldap_entry pe ON pe.id = dn.id::::bigint
		WHERE
			e.id = :id
		GROUP BY e.id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	findRDNByIDStmt, err = db.PrepareNamed(`SELECT
		e.rdn_orig, e.parent_id
		FROM
			ldap_entry e
		WHERE
			e.id = :id
		`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	findRDNsByIDsStmt, err = db.PrepareNamed(`SELECT
		e.rdn_orig, e.parent_id
		FROM
			ldap_entry e
		WHERE
			e.id in (:id)
		`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	findContainerByPathStmt, err = db.PrepareNamed(`SELECT
		t.id, string_agg(e.rdn_orig, ',' ORDER BY dn.ord DESC) AS dn_orig
		FROM
			ldap_tree t
			JOIN regexp_split_to_table(t.path::::text, '[.]') WITH ORDINALITY dn(id, ord) ON true
			JOIN ldap_entry e ON e.id = dn.id::::bigint
		WHERE
			t.path ~ :path
		GROUP BY t.id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	findIDByParentIDAndRDNNormStmt, err = db.PrepareNamed(`SELECT
		e.id
		FROM
			ldap_entry e
		WHERE
			e.parent_id = :parent_id AND e.rdn_norm = :rdn_norm
	`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	updateAttrsByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET attrs_norm = :attrs_norm, attrs_orig = :attrs_orig
		WHERE id = :id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	updateDNByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET
		rdn_orig = :new_rdn_orig, rdn_norm = :new_rdn_norm,
		attrs_norm = :attrs_norm, attrs_orig = :attrs_orig,
		parent_id = :parent_id
		WHERE id = :id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	updateRDNByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET
		rdn_orig = :new_rdn_orig, rdn_norm = :new_rdn_norm,
		attrs_norm = :attrs_norm, attrs_orig = :attrs_orig
		WHERE id = :id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	deleteTreeByIDStmt, err = db.PrepareNamed(`DELETE FROM ldap_tree
		WHERE id = :id RETURNING id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	deleteByIDStmt, err = db.PrepareNamed(`DELETE FROM ldap_entry 
		WHERE id = :id RETURNING id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	hasSubStmt, err = db.PrepareNamed(`SELECT EXISTS (SELECT 1 FROM ldap_entry WHERE parent_id = :id)`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	// Don't need to update modifyTimestamp since it's overlay function
	removeMemberByIDStmt, err = db.PrepareNamed(`UPDATE ldap_entry
		SET attrs_norm =
			CASE WHEN (jsonb_array_length(attrs_norm->'member')) = 1
				THEN
					attrs_norm #- '{member}'
				ELSE
					attrs_norm || jsonb_build_object('member', jsonb_path_query_array(attrs_norm->'member', :cond_filter))
			END
		WHERE attrs_norm @@ :cond_where
		RETURNING id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	// Don't need to update modifyTimestamp since it's overlay function
	removeUniqueMemberByIDStmt, err = db.PrepareNamed(`UPDATE ldap_entry
		SET attrs_norm =
			CASE WHEN (jsonb_array_length(attrs_norm->'uniqueMember')) = 1
				THEN
					attrs_norm #- '{uniqueMember}'
				ELSE
					attrs_norm || jsonb_build_object('uniqueMember', jsonb_path_query_array(attrs_norm->'uniqueMember', :cond_filter))
			END
		WHERE attrs_norm @@ :cond_where
		RETURNING id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	return nil
}

func (r *Repository) BeginTx() *sqlx.Tx {
	return r.db.MustBegin()
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
