package main

import (
	"log"
	"strings"

	"github.com/jmoiron/sqlx"
	"golang.org/x/xerrors"
)

func (r *Repository) deleteMemberOfByDNNorm(tx *sqlx.Tx, dnNorm string, deleteMemberOfDN *DN) error {
	modifyEntry, err := r.findByDNNormWithLock(tx, dnNorm)
	if err != nil {
		return err
	}
	err = modifyEntry.Delete("memberOf", []string{deleteMemberOfDN.DNOrigStr()})
	if err != nil {
		return err
	}

	err = r.Update(tx, nil, modifyEntry)
	if err != nil {
		return xerrors.Errorf("Failed to delete memberOf. dn: %s, memberOf: %s, err: %w", dnNorm, deleteMemberOfDN.DNOrigStr(), err)
	}
	return nil
}

func (r Repository) DeleteByDN(tx *sqlx.Tx, dn *DN) error {
	err := r.deleteMemberByMemberDN(tx, dn)
	if err != nil {
		return xerrors.Errorf("Faild to delete member. err: %w", err)
	}

	var id int = 0
	err = tx.NamedStmt(deleteByDNStmt).Get(&id, map[string]interface{}{
		"dnNorm": dn.DNNormStr(),
	})
	if err != nil {
		if strings.Contains(err.Error(), "sql: no rows in result set") {
			return NewNoSuchObject()
		}
		return xerrors.Errorf("Faild to delete entry. dn: %s, err: %w", dn.DNNormStr(), err)
	}
	if id == 0 {
		return NewNoSuchObject()
	}

	if *twowayEnabled {
		err := deleteMemberOfByMemberOfDN(tx, dn)
		if err != nil {
			return xerrors.Errorf("Faild to delete memberOf. err: %w", err)
		}
	}

	return nil
}

func (r *Repository) deleteMemberByMemberDN(tx *sqlx.Tx, memberDN *DN) error {
	// We need to fetch all rows and close before updating due to avoiding "pq: unexpected Parse response" error.
	// https://github.com/lib/pq/issues/635
	modifyEntries, err := findByMemberDNWithLock(tx, memberDN)
	if err != nil {
		return err
	}

	if len(modifyEntries) == 0 {
		log.Printf("No entries which have member for delete. memberDN: %s", memberDN.DNNormStr())
		return nil
	}

	for _, modifyEntry := range modifyEntries {
		err := modifyEntry.Delete("member", []string{memberDN.DNOrigStr()})
		if err != nil {
			return err
		}

		err = r.Update(tx, nil, modifyEntry)
		if err != nil {
			return err
		}
	}
	return nil
}

func deleteMemberOfByMemberOfDN(tx *sqlx.Tx, memberOfDN *DN) error {
	// We need to fetch all rows and close before updating due to avoiding "pq: unexpected Parse response" error.
	// https://github.com/lib/pq/issues/635
	modifyEntries, err := findByMemberOfDNWithLock(tx, memberOfDN)
	if err != nil {
		return err
	}

	if len(modifyEntries) == 0 {
		log.Printf("No entries which have memberOf for delete. memberOfDN: %s", memberOfDN.DNNormStr())
		return nil
	}

	for _, modifyEntry := range modifyEntries {
		err := modifyEntry.Delete("memberOf", []string{memberOfDN.DNOrigStr()})
		if err != nil {
			return err
		}

		err = updateWithNoUpdated(tx, modifyEntry)
		if err != nil {
			return err
		}
	}
	return nil
}
