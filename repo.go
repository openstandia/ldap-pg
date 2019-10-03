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
	findByDNStmt     *sqlx.NamedStmt
	findCredByDNStmt *sqlx.NamedStmt
	baseSearchStmt   *sqlx.NamedStmt
)

// For generic filter
type FilterStmtMap struct {
	sm sync.Map
}

func (m *FilterStmtMap) Get(key string) (*sqlx.NamedStmt, bool) {
	val, ok := m.sm.Load(key)
	if !ok {
		return nil, false
	}
	return val.(*sqlx.NamedStmt), true
}

func (m *FilterStmtMap) Put(key string, value *sqlx.NamedStmt) {
	m.sm.Store(key, value)
}

var filterStmtMap FilterStmtMap

type Entry struct {
	Id        int            `db:"id"`
	Dn        string         `db:"dn"`
	Path      string         `db:"path"`
	EntryUUID string         `db:"uuid"`
	Created   time.Time      `db:"created"`
	Updated   time.Time      `db:"updated"`
	Attrs     types.JSONText `db:"attrs"`
	Count     int32          `db:"count"`
}

func initStmt(db *sqlx.DB) error {
	var err error

	findByDNStmt, err = db.PrepareNamed("SELECT id, attrs FROM ldap_entry WHERE LOWER(dn) = LOWER(:dn)")
	if err != nil {
		return err
	}

	findCredByDNStmt, err = db.PrepareNamed("SELECT attrs->>'userPassword' FROM ldap_entry WHERE LOWER(dn) = LOWER(:dn)")
	if err != nil {
		return err
	}

	baseSearchStmt, err = db.PrepareNamed("SELECT * FROM ldap_entry WHERE LOWER(dn) = LOWER(:baseDN)")
	if err != nil {
		return err
	}

	return nil
}

func findByDN(tx *sqlx.Tx, dn *DN) (*Entry, error) {
	entry := Entry{}
	err := tx.NamedStmt(findByDNStmt).Get(&entry, map[string]interface{}{
		"dn": dn.DN,
	})
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

func findCredByDN(dn *DN) (string, error) {
	var bindUserCred string
	err := findCredByDNStmt.Get(&bindUserCred, map[string]interface{}{
		"dn": dn.DN,
	})
	if err != nil {
		return "", err
	}
	return bindUserCred, nil
}

func getBaseSearch(baseDN *DN) (*Entry, error) {
	var entry Entry
	err := baseSearchStmt.Get(&entry, map[string]interface{}{
		"baseDN": baseDN.DN,
	})
	// including not found
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

func findByFilter(pathQuery string, q *Query) (*sqlx.Rows, error) {
	var query string
	if q.Query != "" {
		query = " AND " + q.Query
	}

	fetchQuery := fmt.Sprintf(`SELECT *, count(id) over() as count FROM ldap_entry WHERE %s %s LIMIT :pageSize OFFSET :offset`, pathQuery, query)

	log.Printf("Fetch Query: %s Params: %v", fetchQuery, q.Params)

	var fetchStmt *sqlx.NamedStmt
	var ok bool
	var err error
	if fetchStmt, ok = filterStmtMap.Get(fetchQuery); !ok {
		// cache
		fetchStmt, err = db.PrepareNamed(fetchQuery)
		if err != nil {
			return nil, err
		}
		filterStmtMap.Put(fetchQuery, fetchStmt)
	}

	var rows *sqlx.Rows
	rows, err = fetchStmt.Queryx(q.Params)
	if err != nil {
		return nil, err
	}

	return rows, nil
}

// func countOneByFilter(tx *sqlx.Tx, q *Query) (int, error) {
// 	var count int
// 	err := tx.NamedStmt(findByDNStmt).Get(&entry, map[string]interface{}{
// 		"dn": dn.DN,
// 	})
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &entry, nil
// }
