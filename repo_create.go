package main

import (
	"log"

	"github.com/jmoiron/sqlx"
	"golang.org/x/xerrors"
)

func (r *Repository) Insert(tx *sqlx.Tx, entry *AddEntry) (int64, error) {
	if *twowayEnabled {
		hasMemberEntries, err := findByMemberDNWithLock(tx, entry.DN())
		if err != nil {
			return 0, err
		}
		memberOfDNsOrig := make([]string, len(hasMemberEntries))
		for i, v := range hasMemberEntries {
			memberOfDNsOrig[i] = v.GetDNOrig()
		}
		err = entry.Add("memberOf", memberOfDNsOrig)
		if err != nil {
			return 0, err
		}
	}

	dbEntry, err := mapper.AddEntryToDBEntry(entry)
	if err != nil {
		return 0, err
	}

	var parentID int64
	if entry.IsDC() {
		parentID = ROOT_ID
		// } else if entry.ParentDN().IsDC() {
		// 	parentID = DCID
	} else {
		parent, err := findParentByDN(tx, entry.DN())
		if err != nil {
			return 0, err
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
		return 0, xerrors.Errorf("Failed to insert entry record. entry: %v, err: %w", entry, err)
	}
	defer rows.Close()

	var id int64
	if rows.Next() {
		rows.Scan(&id)
	} else {
		log.Printf("debug: Already exists. parentID: %d, rdn_norm: %s", parentID, entry.RDNNorm())
		return 0, NewAlreadyExists()
	}

	// work around to avoid "pq: unexpected Bind response 'C'"
	rows.Close()

	if entry.IsContainer() {
		_, err := tx.NamedStmt(addTreeStmt).Exec(map[string]interface{}{
			"id":        id,
			"parent_id": parentID,
			"rdn_norm":  entry.dn.RDNNormStr(),
			"rdn_orig":  entry.dn.RDNOrigStr(),
		})
		if err != nil {
			return 0, xerrors.Errorf("Failed to insert tree record. parent_id: %d, rdn_norm: %s err: %w", parentID, entry.RDNNorm(), err)
		}
	}

	if *twowayEnabled {
		if members, ok := entry.GetAttrNorm("member"); ok {
			for _, dnNorm := range members {
				err := r.addMemberOfByDNNorm(tx, dnNorm, entry.DN())
				if err != nil {
					return 0, xerrors.Errorf("Faild to add memberOf. err: %w", err)
				}
			}
		}
	}

	return id, nil
}
