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
	insertTreeStmt    *sqlx.NamedStmt
	insertDCStmt      *sqlx.NamedStmt
	insertUnderDCStmt *sqlx.NamedStmt
	insertStmtCache   StmtCache

	// repo_read
	collectNodeOrigByParentIDStmt *sqlx.NamedStmt
	collectNodeNormByParentIDStmt *sqlx.NamedStmt
	getDCStmt                     *sqlx.NamedStmt
	getDCDNOrigStmt               *sqlx.NamedStmt
	filterStmtMap                 StmtCache
	treeStmtCache                 StmtCache
	findByDNStmtCache             StmtCache
	findCredByDNStmtCache         StmtCache

	// repo_update
	updateAttrsByIdStmt *sqlx.NamedStmt
	updateDNByIdStmt    *sqlx.NamedStmt

	// repo_delete
	deleteDCStmt           *sqlx.NamedStmt
	deleteTreeNodeByIDStmt *sqlx.NamedStmt
	deleteMemberByIDStmt   *sqlx.NamedStmt
	deleteByDNStmtCache    StmtCache

	ROOT_ID int64 = 0
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
	server *Server
	db     *sqlx.DB
}

func NewRepository(server *Server) (*Repository, error) {
	// Init DB Connection
	db, err := sqlx.Connect("postgres", fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=disable",
		server.config.DBHostName, server.config.DBPort, server.config.DBUser, server.config.DBName, server.config.DBPassword))
	if err != nil {
		log.Fatalf("fatal: Connect error. host=%s, port=%d, user=%s, dbname=%s, error=%s",
			server.config.DBHostName, server.config.DBPort, server.config.DBUser, server.config.DBName, err)
	}
	db.SetMaxOpenConns(server.config.DBMaxOpenConns)
	db.SetMaxIdleConns(server.config.DBMaxIdleConns)
	// db.SetConnMaxLifetime(time.Hour)

	repo := &Repository{
		server: server,
		db:     db,
	}
	err = repo.initStmt(db)
	if err != nil {
		return nil, err
	}

	return repo, nil
}

func (r *Repository) initStmt(db *sqlx.DB) error {
	var err error

	collectNodeOrigByParentIDStmt, err = db.PrepareNamed(`WITH RECURSIVE child (dn_orig, id, parent_id) AS
	(
		SELECT e.rdn_orig::::TEXT AS dn_orig, e.id, e.parent_id
			FROM ldap_tree e WHERE e.parent_id = :parent_id 
			UNION ALL
				SELECT
					e.rdn_orig || ',' || child.dn_orig,
					e.id,
					e.parent_id
				FROM ldap_tree e, child
				WHERE e.parent_id = child.id
	)
	SELECT id, dn_orig from child`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	collectNodeNormByParentIDStmt, err = db.PrepareNamed(`WITH RECURSIVE child (dn_norm, id, parent_id) AS
	(
		SELECT e.rdn_norm::::TEXT AS dn_norm, e.id, e.parent_id
			FROM ldap_tree e WHERE e.parent_id = :parent_id 
			UNION ALL
				SELECT
					e.rdn_norm || ',' || child.dn_norm,
					e.id,
					e.parent_id
				FROM ldap_tree e, child
				WHERE e.parent_id = child.id
	)
	SELECT id, dn_norm from child`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	getDCStmt, err = db.PrepareNamed(fmt.Sprintf(`SELECT id, parent_id, uuid, created, updated, rdn_orig, attrs_orig
		FROM ldap_entry
		WHERE parent_id = %d`, ROOT_ID))
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	getDCDNOrigStmt, err = db.PrepareNamed(fmt.Sprintf(`SELECT id, '' as dn_orig FROM ldap_tree
		WHERE parent_id = %d`, ROOT_ID))
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	insertTreeStmt, err = db.PrepareNamed(`INSERT INTO ldap_tree (id, parent_id, rdn_norm, rdn_orig)
		VALUES (:id, :parent_id, :rdn_norm, :rdn_orig)`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	insertDCStmt, err = db.PrepareNamed(fmt.Sprintf(`INSERT INTO ldap_entry (parent_id, rdn_norm, rdn_orig, uuid, created, updated, attrs_norm, attrs_orig)
		SELECT %d, :rdn_norm, :rdn_orig, :uuid, :created, :updated, :attrs_norm, :attrs_orig
			WHERE NOT EXISTS (SELECT id FROM ldap_entry WHERE parent_id = %d)
		RETURNING id`, ROOT_ID, ROOT_ID))
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	insertUnderDCStmt, err = db.PrepareNamed(fmt.Sprintf(`INSERT INTO ldap_entry (parent_id, rdn_norm, rdn_orig, uuid, created, updated, attrs_norm, attrs_orig)
		SELECT (SELECT id FROM ldap_tree WHERE parent_id = %d) as parent_id, :rdn_norm, :rdn_orig, :uuid, :created, :updated, :attrs_norm, :attrs_orig
			WHERE 
				NOT EXISTS (SELECT e.id FROM ldap_entry e, ldap_tree t WHERE e.parent_id = t.id AND t.parent_id = %d AND e.rdn_norm = :rdn_norm)
		RETURNING id, parent_id`, ROOT_ID, ROOT_ID))
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	updateAttrsByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET updated = :updated, attrs_norm = :attrs_norm, attrs_orig = :attrs_orig
		WHERE id = :id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	updateDNByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET updated = :updated,
		rdn_orig = :new_rdn_orig, rdn_norm = :new_rdn_norm,
		attrs_norm = :attrs_norm, attrs_orig = :attrs_orig,
		parent_id = :parent_id
		WHERE id = :id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	deleteDCStmt, err = db.PrepareNamed(fmt.Sprintf(`DELETE FROM ldap_entry
		WHERE parent_id = %d RETURNING id`, ROOT_ID))
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	deleteTreeNodeByIDStmt, err = db.PrepareNamed(`DELETE FROM ldap_tree
		WHERE id = :id RETURNING id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	deleteMemberByIDStmt, err = db.PrepareNamed(`DELETE FROM ldap_member
		WHERE member_id = :id OR member_of_id = :id RETURNING member_id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	return nil
}

type DBEntry struct {
	ID            int64          `db:"id"`
	DNNorm        string         `db:"dn_norm"`
	DNOrig        string         `db:"dn_orig"`
	EntryUUID     string         `db:"uuid"`
	Created       time.Time      `db:"created"`
	Updated       time.Time      `db:"updated"`
	AttrsNorm     types.JSONText `db:"attrs_norm"`
	AttrsOrig     types.JSONText `db:"attrs_orig"`
	Count         int32          `db:"count"`    // No real column in the table
	MemberOf      types.JSONText `db:"memberof"` // No real column in the table
	jsonAttrsNorm map[string]interface{}
	jsonAttrsOrig map[string][]string
}
