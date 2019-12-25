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

func (r *Repository) insertEntry(tx *sqlx.Tx, entry *AddEntry) (int64, int64, error) {
	// if *twowayEnabled {
	// 	hasMemberEntries, err := findByMemberDNWithLock(tx, entry.DN())
	// 	if err != nil {
	// 		return 0, err
	// 	}
	// 	memberOfDNsOrig := make([]string, len(hasMemberEntries))
	// 	for i, v := range hasMemberEntries {
	// 		memberOfDNsOrig[i] = v.GetDNOrig()
	// 	}
	// 	err = entry.Add("memberOf", memberOfDNsOrig)
	// 	if err != nil {
	// 		return 0, err
	// 	}
	// }

	dbEntry, err := mapper.AddEntryToDBEntry(entry)
	if err != nil {
		return 0, 0, err
	}

	var parentID int64
	if entry.IsDC() {
		parentID = ROOT_ID
	} else {
		// Detect parentID
		parent, err := r.findParentByDN(tx, entry.DN())
		if err != nil {
			return 0, 0, err
		}
		parentID = parent.ID
	}

	rows, err := tx.NamedStmt(addStmt).Queryx(map[string]interface{}{
		"rdn_norm":   entry.RDNNorm(),
		"rdn_orig":   entry.RDNOrig(),
		"parent_id":  parentID,
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
	if rows.Next() {
		rows.Scan(&id)
	} else {
		log.Printf("debug: Already exists. parentID: %d, rdn_norm: %s", parentID, entry.RDNNorm())
		return 0, 0, NewAlreadyExists()
	}

	// work around to avoid "pq: unexpected Bind response 'C'"
	rows.Close()

	return id, parentID, nil
}

func insertTree(tx *sqlx.Tx, id, parentID int64, entry *AddEntry) error {
	if entry.IsContainer() {
		_, err := tx.NamedStmt(addTreeStmt).Exec(map[string]interface{}{
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
	dc, err := getDC(tx)
	if err != nil {
		return err
	}
	dnIDCache := map[string]int64{} // dn_orig => id cache map
	dnIDCache[dc.DNOrig] = dc.ID

	nodeNorms, err := collectNodeNormsByParentID(dc.ID)
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
			log.Printf("info: Invalid member DN sintax. DN: %s, %s DN: %s", entry.DN().DNOrigStr(), m.RDNNorm, m.MemberOfDNNorm)
			return NewInvalidDNSyntax()
		}
		parent := dn.ParentDN()
		parentID, ok := dnIDCache[parent.DNNormStr()]
		if !ok {
			log.Printf("info: Not found member DN. DN: %s, %s DN: %s", entry.DN().DNOrigStr(), m.RDNNorm, m.MemberOfDNNorm)
			return NewInvalidDNSyntax()
		}
		where[i] = fmt.Sprintf("(parent_id = :parent_id_%d AND rdn_norm = :rdn_norm_%d)", i, i)
		params[fmt.Sprintf("parent_id_%d", i)] = parentID
		params[fmt.Sprintf("rdn_norm_%d", i)] = dn.RDNNormStr()

		// cache
		memberTypeCache[fmt.Sprintf("%d_%s", parentID, dn.RDNNormStr())] = m.RDNNorm
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

func collectNodeNormsByParentID(parentID int64) ([]*nordNorm, error) {
	rows, err := collectNordNormsByParentIDStmt.Queryx(map[string]interface{}{
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
