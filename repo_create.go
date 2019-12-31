package main

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/jmoiron/sqlx"
	"golang.org/x/xerrors"
)

func (r *Repository) Insert(entry *AddEntry) (int64, error) {
	tx := r.db.MustBegin()
	return r.insertWithTx(tx, entry)
}

func (r *Repository) insertWithTx(tx *sqlx.Tx, entry *AddEntry) (int64, error) {
	if !entry.IsDC() {
		has, err := r.hasParent(tx, entry.DN())
		if err != nil {
			tx.Rollback()
			return 0, err
		}
		if !has {
			tx.Rollback()
			// TODO
			// return 0, NewNoSuchObjectWithMatchedDN(entry.DN().DNNormStr())
			return 0, NewNoSuchObject()
		}
	}

	newID, parentID, err := r.insertEntry(tx, entry)
	if err != nil {
		tx.Rollback()
		return 0, err
	}

	err = insertTree(tx, newID, parentID, entry)
	if err != nil {
		tx.Rollback()
		return 0, err
	}

	err = r.insertMember(tx, newID, entry)
	if err != nil {
		tx.Rollback()
		return 0, err
	}

	tx.Commit()
	return newID, nil
}

func (r *Repository) hasParent(tx *sqlx.Tx, dn *DN) (bool, error) {
	_, err := r.FindByDN(tx, dn.ParentDN(), &FindOption{Lock: true})
	if err != nil {
		if isNoResult(err) {
			return false, nil
		}
		return false, xerrors.Errorf("Failed to find parent by DN: %s, err: %w", dn.DNNormStr(), err)
	}

	return true, nil
}

func (r *Repository) insertEntry(tx *sqlx.Tx, entry *AddEntry) (int64, int64, error) {
	if entry.IsDC() {
		return r.insertDCEntry(tx, entry)
	}

	if entry.ParentDN().IsDC() {
		return r.insertUnderDCEntry(tx, entry)
	}

	dbEntry, err := mapper.AddEntryToDBEntry(entry)
	if err != nil {
		return 0, 0, err
	}

	pq, params := r.CreateFindByDNQuery(entry.ParentDN(), &FindOption{Lock: false})

	q := fmt.Sprintf(`INSERT INTO ldap_entry (parent_id, rdn_norm, rdn_orig, uuid, created, updated, attrs_norm, attrs_orig)
		SELECT p.id AS parent_id, :rdn_norm, :rdn_orig, :uuid, :created, :updated, :attrs_norm, :attrs_orig
			FROM (%s) p
			WHERE NOT EXISTS (SELECT id FROM ldap_entry WHERE parent_id = p.id AND rdn_norm = :rdn_norm)
		RETURNING id, parent_id`, pq)

	log.Printf("insert query: %s, params: %v", q, params)

	stmt, err := r.db.PrepareNamed(q)
	if err != nil {
		return 0, 0, xerrors.Errorf("Failed to prepare query. query: %s, err: %w", err)
	}

	params["rdn_norm"] = entry.RDNNorm()
	params["rdn_orig"] = entry.RDNOrig()
	params["uuid"] = dbEntry.EntryUUID
	params["created"] = dbEntry.Created
	params["updated"] = dbEntry.Updated
	params["attrs_norm"] = dbEntry.AttrsNorm
	params["attrs_orig"] = dbEntry.AttrsOrig

	rows, err := tx.NamedStmt(stmt).Queryx(params)
	if err != nil {
		return 0, 0, xerrors.Errorf("Failed to insert entry record. entry: %v, err: %w", entry, err)
	}
	defer rows.Close()

	var id int64
	var parentID int64
	if rows.Next() {
		rows.Scan(&id, &parentID)
	} else {
		log.Printf("debug: Already exists. parentID: %d, rdn_norm: %s", parentID, entry.RDNNorm())
		return 0, 0, NewAlreadyExists()
	}

	return id, parentID, nil
}

func (r *Repository) insertDCEntry(tx *sqlx.Tx, entry *AddEntry) (int64, int64, error) {
	dbEntry, err := mapper.AddEntryToDBEntry(entry)
	if err != nil {
		return 0, 0, err
	}

	rows, err := tx.NamedStmt(insertDCStmt).Queryx(map[string]interface{}{
		"rdn_norm":   entry.RDNNorm(),
		"rdn_orig":   entry.RDNOrig(),
		"uuid":       dbEntry.EntryUUID,
		"created":    dbEntry.Created,
		"updated":    dbEntry.Updated,
		"attrs_norm": dbEntry.AttrsNorm,
		"attrs_orig": dbEntry.AttrsOrig,
	})
	if err != nil {
		return 0, 0, xerrors.Errorf("Failed to insert DC entry record. DC entry: %v, err: %w", entry, err)
	}
	defer rows.Close()

	var id int64
	if rows.Next() {
		err := rows.Scan(&id)
		if err != nil {
			return 0, 0, xerrors.Errorf("Failed to scan returning id. err: %w", err)
		}
	} else {
		log.Printf("warn: Already exists. parentID: %d, rdn_norm: %s", ROOT_ID, entry.RDNNorm())
		return 0, 0, NewAlreadyExists()
	}

	return id, ROOT_ID, nil
}

func (r *Repository) insertUnderDCEntry(tx *sqlx.Tx, entry *AddEntry) (int64, int64, error) {
	dbEntry, err := mapper.AddEntryToDBEntry(entry)
	if err != nil {
		return 0, 0, err
	}

	rows, err := tx.NamedStmt(insertUnderDCStmt).Queryx(map[string]interface{}{
		"rdn_norm":   entry.RDNNorm(),
		"rdn_orig":   entry.RDNOrig(),
		"uuid":       dbEntry.EntryUUID,
		"created":    dbEntry.Created,
		"updated":    dbEntry.Updated,
		"attrs_norm": dbEntry.AttrsNorm,
		"attrs_orig": dbEntry.AttrsOrig,
	})
	if err != nil {
		return 0, 0, xerrors.Errorf("Failed to insert entry record. entry: %v, err: %w", entry, err)
	}
	defer rows.Close()

	var id int64
	var parentID int64
	if rows.Next() {
		err := rows.Scan(&id, &parentID)
		if err != nil {
			return 0, 0, xerrors.Errorf("Failed to scan returning id. err: %w", err)
		}
	} else {
		log.Printf("warn: Already exists. dn: %s", entry.DN().DNOrigStr())
		return 0, 0, NewAlreadyExists()
	}

	return id, parentID, nil
}

func insertTree(tx *sqlx.Tx, id, parentID int64, entry *AddEntry) error {
	if entry.IsContainer() {
		_, err := tx.NamedStmt(insertTreeStmt).Exec(map[string]interface{}{
			"id":        id,
			"parent_id": parentID,
			"rdn_norm":  entry.dn.RDNNormStr(),
			"rdn_orig":  entry.dn.RDNOrigStr(),
		})
		if err != nil {
			return xerrors.Errorf("Failed to insert tree record. parent_id: %d, rdn_norm: %s err: %w",
				parentID, entry.RDNNorm(), err)
		}
	}
	return nil
}

func (r *Repository) insertMember(tx *sqlx.Tx, subjectID int64, entry *AddEntry) error {
	members := entry.Member()
	if len(members) == 0 {
		log.Printf("The new entry doesn't have member attributes. DN: %s", entry.DN().DNOrigStr())
		return nil
	}

	// Resolve IDs from memberOfDNs
	dns := make([]string, len(members))
	for i, m := range members {
		dns[i] = m.MemberOfDNNorm
	}

	// First, cache all parent IDs
	// TODO should optimize if ldap_tree tables is too big
	dc, err := getDCDNOrig(tx)
	if err != nil {
		return err
	}
	dnIDCache := map[string]int64{} // dn_orig => id cache map
	dnIDCache[dc.DNOrig] = dc.ID

	nodeNorms, err := collectNodeNormByParentID(dc.ID)
	if err != nil {
		return err
	}

	for _, node := range nodeNorms {
		dnIDCache[node.DNNorm] = node.ID
	}

	where := make([]string, len(members))
	params := make(map[string]interface{}, len(members))

	memberTypeCache := map[string]string{}

	for i, m := range members {
		dn, err := r.server.NormalizeDN(m.MemberOfDNNorm)
		if err != nil {
			log.Printf("info: Invalid member DN sintax. DN: %s, %s DN: %s", entry.DN().DNOrigStr(), m.AttrNameNorm, m.MemberOfDNNorm)
			return NewInvalidDNSyntax()
		}
		parent := dn.ParentDN()
		parentID, ok := dnIDCache[parent.DNNormStr()]
		if !ok {
			log.Printf("info: Not found member DN. DN: %s, %s DN: %s", entry.DN().DNOrigStr(), m.AttrNameNorm, m.MemberOfDNNorm)
			return NewInvalidDNSyntax()
		}
		where[i] = fmt.Sprintf("(parent_id = :parent_id_%d AND rdn_norm = :rdn_norm_%d)", i, i)
		params[fmt.Sprintf("parent_id_%d", i)] = parentID
		params[fmt.Sprintf("rdn_norm_%d", i)] = dn.RDNNormStr()

		// cache
		memberTypeCache[fmt.Sprintf("%d_%s", parentID, dn.RDNNormStr())] = m.AttrNameNorm
	}

	query := fmt.Sprintf("SELECT id, parent_id, rdn_norm FROM ldap_entry WHERE %s", strings.Join(where, " OR "))

	rows, err := tx.NamedQuery(query, params)
	if err != nil {
		return xerrors.Errorf("Failed to fetch member's id. err: %w", err)
	}

	defer rows.Close()

	values := make([]string, len(members))
	params = make(map[string]interface{}, len(members))
	count := 0

	for rows.Next() {
		var id int64
		var parentID int64
		var rdnNorm string
		err := rows.Scan(&id, &parentID, &rdnNorm)
		if err != nil {
			return xerrors.Errorf("Failed to scan member's id. err: %w", err)
		}
		memberType, ok := memberTypeCache[fmt.Sprintf("%d_%s", parentID, rdnNorm)]
		if !ok {
			return xerrors.Errorf("Failed to fetch member's id. err: %w", err)
		}
		k1 := "a_" + strconv.Itoa(count)
		k2 := "o_" + strconv.Itoa(count)
		values[count] = fmt.Sprintf("(%d, :%s, :%s)", subjectID, k1, k2)
		params[k1] = memberType
		params[k2] = id

		count++
	}

	// Not found the member DN
	if count != len(dns) {
		log.Printf("warn: Invalid member DN. member dn: %v, values: %v", dns, values)
		return NewInvalidDNSyntax()
	}

	// work around
	rows.Close()

	insert := fmt.Sprintf("INSERT INTO ldap_member VALUES %s", strings.Join(values, ", "))

	_, err = tx.NamedExec(insert, params)
	if err != nil {
		return xerrors.Errorf("Failed to bulk insert members. err: %w", err)
	}

	return nil
}

type nordNorm struct {
	ID     int64  `db:"id"`
	DNNorm string `db:"dn_norm"`
}

func collectNodeNormByParentID(parentID int64) ([]*nordNorm, error) {
	if parentID == ROOT_ID {
		return nil, xerrors.Errorf("Invalid parentID: %d", parentID)
	}

	rows, err := collectNodeNormByParentIDStmt.Queryx(map[string]interface{}{
		"parent_id": parentID,
	})
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch child ID by parentID: %s, err: %w", parentID, err)
	}
	defer rows.Close()

	list := []*nordNorm{}
	for rows.Next() {
		child := nordNorm{}
		rows.StructScan(&child)
		list = append(list, &child)
	}

	err = rows.Err()
	if err != nil {
		log.Printf("error: Search children error: %#v", err)
		return nil, err
	}

	return list, nil
}
