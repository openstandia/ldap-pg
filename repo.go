package main

import (
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
	"golang.org/x/xerrors"
)

var (
	addTreeStmt             *sqlx.NamedStmt
	addStmt                 *sqlx.NamedStmt
	addMemberOfByDNNormStmt *sqlx.NamedStmt

	findByDNStmt                             *sqlx.NamedStmt
	findByDNWithMemberOfStmt                 *sqlx.NamedStmt
	findByDNWithLockStmt                     *sqlx.NamedStmt
	findByParentIDAndRDNNormStmt             *sqlx.NamedStmt
	findByParentIDAndRDNNormStmtWithLockStmt *sqlx.NamedStmt
	findByIDWithLockStmt                     *sqlx.NamedStmt
	findCredByDNStmt                         *sqlx.NamedStmt
	findByMemberWithLockStmt                 *sqlx.NamedStmt
	findByMemberOfWithLockStmt               *sqlx.NamedStmt
	findChildrenByParentIDStmt               *sqlx.NamedStmt
	getDCStmt                                *sqlx.NamedStmt

	updateAttrsByIdStmt              *sqlx.NamedStmt
	updateAttrsWithNoUpdatedByIdStmt *sqlx.NamedStmt
	updateDNByIdStmt                 *sqlx.NamedStmt

	deleteByDNStmt *sqlx.NamedStmt

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

var filterStmtMap StmtCache
var treeStmtCache StmtCache

type Repository struct {
	server *Server
}

func NewRepository(server *Server) *Repository {
	return &Repository{
		server: server,
	}
}

func (r *Repository) initStmt(db *sqlx.DB) error {
	var err error

	findByParentIDAndRDNNormSQL := `SELECT id, uuid, created, updated, rdn_orig || ',' || :parent_dn_orig AS dn_orig, attrs_orig
		FROM ldap_entry
		WHERE parent_id = :parent_id AND rdn_norm = :rdn_norm`

	findByParentIDAndRDNNormStmt, err = db.PrepareNamed(findByParentIDAndRDNNormSQL)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	findByParentIDAndRDNNormStmtWithLockStmt, err = db.PrepareNamed(findByParentIDAndRDNNormSQL + " FOR UPDATE")
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	// findByDNSQL := "SELECT id, uuid, created, updated, dn_norm, attrs_orig FROM ldap_entry WHERE parent_id =rdn_norm = :dn_norm"
	// findByDNWithMemberOfSQL := "SELECT id, uuid, created, updated, dn_norm, attrs_orig, (select jsonb_agg(e2.dn_norm) AS memberOf FROM ldap_entry e2 WHERE e2.attrs_norm->'member' @> jsonb_build_array(e1.dn_norm)) AS memberOf FROM ldap_entry e1 WHERE dn_norm = :dnNorm"

	// findByDNStmt, err = db.PrepareNamed(findByDNSQL)
	// if err != nil {
	// 	return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	// }

	// findByDNWithMemberOfStmt, err = db.PrepareNamed(findByDNWithMemberOfSQL)
	// if err != nil {
	// 	return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	// }

	// findByDNWithLockStmt, err = db.PrepareNamed(findByDNSQL + " FOR UPDATE")
	// if err != nil {
	// 	return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	// }

	findByIDWithLockStmt, err = db.PrepareNamed(`SELECT id, uuid, created, updated, rdn_orig, attrs_orig
		FROM ldap_entry
		WHERE id = :id
		FOR UPDATE`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	findCredByDNStmt, err = db.PrepareNamed(`SELECT attrs_norm->>'userPassword'
		FROM ldap_entry
		WHERE parent_id = :parent_id AND rdn_norm = :rdn_norm`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	findByMemberWithLockStmt, err = db.PrepareNamed(`SELECT id, parent_id, rdn_norm, attrs_orig
		FROM ldap_entry
		WHERE parent_id = :parent_id AND attrs_norm->'member' @> jsonb_build_array(:dn_norm ::::text) FOR UPDATE`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	findByMemberOfWithLockStmt, err = db.PrepareNamed(`SELECT id, parent_id, rdn_norm, attrs_orig
		FROM ldap_entry
		WHERE parent_id = :parent_id AND attrs_norm->'memberOf' @> jsonb_build_array(:dn_norm ::::text) FOR UPDATE`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	findChildrenByParentIDStmt, err = db.PrepareNamed(`WITH RECURSIVE child (dn_orig, id, parent_id, rdn_orig) AS
	(
		SELECT e.rdn_orig::::TEXT AS dn_orig, e.id, e.parent_id, e.rdn_orig FROM
		ldap_tree e WHERE e.parent_id = :parent_id 
		UNION ALL
			SELECT
				e.rdn_orig || ',' || child.dn_orig,
				e.id,
				e.parent_id,
				e.rdn_orig
			FROM ldap_tree e, child
			WHERE e.parent_id = child.id
	)
	SELECT id, dn_orig from child`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	getDCStmt, err = db.PrepareNamed(`SELECT id, '' as dn_orig FROM ldap_tree
		WHERE parent_id = 0`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	addTreeStmt, err = db.PrepareNamed(`INSERT INTO ldap_tree (id, parent_id, rdn_norm, rdn_orig)
		VALUES (:id, :parent_id, :rdn_norm, :rdn_orig)`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	addStmt, err = db.PrepareNamed(`INSERT INTO ldap_entry (parent_id, rdn_norm, rdn_orig, uuid, created, updated, attrs_norm, attrs_orig)
		SELECT :parent_id, :rdn_norm, :rdn_orig, :uuid, :created, :updated, :attrs_norm, :attrs_orig
			WHERE NOT EXISTS (SELECT id FROM ldap_entry WHERE parent_id = :parent_id AND rdn_norm = :rdn_norm)
		RETURNING id`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	addMemberOfByDNNormStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET attrs_norm = jsonb_set(attrs_norm, array['memberOf'], coalesce(attrs_norm->'memberOf', '[]'::::jsonb) || jsonb_build_array(:memberOfDNNorm ::::text)), attrs_orig = jsonb_set(attrs_orig, array['memberOf'], coalesce(attrs_orig->'memberOf', '[]'::::jsonb) || jsonb_build_array(:memberOfDNOrig ::::text))
		WHERE parent_id = :parent_id AND rdn_norm = :rdn_norm`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	updateAttrsByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET updated = :updated, attrs_norm = :attrsNorm, attrs_orig = :attrsOrig
		WHERE id = :id`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	// When updating memberOf, don't update 'updated'
	updateAttrsWithNoUpdatedByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET attrs_norm = :attrsNorm, attrs_orig = :attrsOrig
		WHERE id = :id`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	updateDNByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET updated = :updated, rdn_norm = :new_rdn_norm, attrs_norm = :attrsNorm, attrs_orig = :attrsOrig
		WHERE id = :id`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	deleteByDNStmt, err = db.PrepareNamed(`DELETE FROM ldap_entry
		WHERE parent_id = :parent_id AND rdn_norm = :rdn_norm RETURNING id`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
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
