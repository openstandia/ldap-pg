package main

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
	"golang.org/x/xerrors"
)

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

func (e *FetchedDBEntry) Member(IdToDNOrigCache map[int64]string) ([]string, error) {
	if len(e.RawMember) == 0 {
		return nil, nil
	}

	jsonArray := [][]string{}
	err := e.RawMember.Unmarshal(&jsonArray)
	if err != nil {
		return nil, err
	}
	results := make([]string, len(jsonArray))

	for i, m := range jsonArray {
		parentId, err := strconv.ParseInt(m[0], 10, 64)
		if err != nil {
			return nil, xerrors.Errorf("Failed to parse parent_id: %s, err: %w", parentId, err)
		}
		rdnOrig := m[1]

		parentDNOrig, ok := IdToDNOrigCache[parentId]
		if !ok {
			// TODO find parent DN orig from database...
			parentDNOrig = "<unknown>"
		}

		results[i] = rdnOrig + `,` + parentDNOrig
	}
	return results, nil
}

func (e *FetchedDBEntry) MemberOf(IdToDNOrigCache map[int64]string) ([]string, error) {
	if len(e.RawMemberOf) == 0 {
		return nil, nil
	}

	jsonArray := [][]string{}
	err := e.RawMemberOf.Unmarshal(&jsonArray)
	if err != nil {
		return nil, err
	}

	results := make([]string, len(jsonArray))

	for i, m := range jsonArray {
		parentId, err := strconv.ParseInt(m[0], 10, 64)
		if err != nil {
			return nil, xerrors.Errorf("Failed to parse parent_id: %s, err: %w", parentId, err)
		}
		rdnOrig := m[1]

		parentDNOrig, ok := IdToDNOrigCache[parentId]
		if !ok {
			// TODO find parent DN orig from database...
			parentDNOrig = "<unknown>"
		}

		results[i] = rdnOrig + `,` + parentDNOrig
	}
	return results, nil
}

func (e *FetchedDBEntry) AttrsOrig() map[string][]string {
	if len(e.RawAttrsOrig) > 0 {
		jsonMap := make(map[string][]string)
		e.RawAttrsOrig.Unmarshal(&jsonMap)

		if len(e.RawMemberOf) > 0 {
			jsonArray := []string{}
			e.RawMemberOf.Unmarshal(&jsonArray)
			jsonMap["memberOf"] = jsonArray
		}

		return jsonMap
	}
	return nil
}

func (e *FetchedDBEntry) Clear() {
	e.ID = 0
	e.DNOrig = ""
	e.RawAttrsOrig = nil
	e.RawMemberOf = nil
	e.Count = 0
}

type FetchedDNOrig struct {
	ID     int64  `db:"id"`
	DNOrig string `db:"dn_orig"`
}

func (r *Repository) Search(baseDN *DN, scope int, q *Query, reqMemberAttrs []string,
	reqMemberOf, isHasSubordinatesRequested bool, handler func(entry *SearchEntry) error) (int32, int32, error) {

	fetchedDN, err := r.FindPathByDN(nil, baseDN)
	if err != nil {
		log.Printf("debug: Failed to find DN by DN. err: %+v", err)
		return 0, 0, err
	}

	// Cache
	q.IdToDNOrigCache[fetchedDN.ID] = fetchedDN.DNOrig

	where, err := r.AppenScopeFilter(scope, q, fetchedDN)
	if err != nil {
		return 0, 0, err
	}

	log.Printf("debug: where: %s", where)

	var hasSubordinatesCol string
	if isHasSubordinatesRequested {
		hasSubordinatesCol = `,
			CASE
			WHEN EXISTS (
				SELECT 1 FROM ldap_entry sle WHERE sle.parent_id = e.id
			) THEN 'TRUE' ELSE 'FALSE' END as hassubordinates`
	}

	var memberCol string
	var memberJoin string
	var groupBy string
	if len(reqMemberAttrs) > 0 {
		cb := make([]byte, 128)
		jb := make([]byte, 128)
		for i, attr := range reqMemberAttrs {
			index := strconv.Itoa(i)

			cb = append(cb, `
			, JSON_AGG(
				JSONB_BUILD_ARRAY(me`+index+`.parent_id::::text, me`+index+`.rdn_orig) ORDER BY mdn`+index+`.ord ASC
			) FILTER (WHERE me`+index+`.parent_id IS NOT NULL) AS `+attr+`
			`...)
			jb = append(jb, `
				LEFT JOIN JSONB_ARRAY_ELEMENTS(e.attrs_norm->'`+attr+`') WITH ORDINALITY mdn`+index+`(id, ord) ON TRUE
				LEFT JOIN ldap_entry me`+index+` ON mdn`+index+`.id::::bigint = me`+index+`.id  
			`...)
		}
		memberCol = strings.ReplaceAll(string(cb), "\x00", "")
		memberJoin = strings.ReplaceAll(string(jb), "\x00", "")
		groupBy = `GROUP BY e.id`
	}

	var memberOfCol string
	var memberOfJoin string
	if reqMemberOf {
		var cb strings.Builder
		cb.Grow(128)
		var jb strings.Builder
		jb.Grow(128)

		cb.WriteString(`
			, JSON_AGG(
				JSONB_BUILD_ARRAY(mo.parent_id::::text, mo.rdn_orig)
			) FILTER (WHERE mo.parent_id IS NOT NULL) AS member_of	
		`)
		jb.WriteString(`
			LEFT JOIN ldap_entry mo ON mo.attrs_norm @@ FORMAT('$.member[*] == %s || $.uniquemember[*] == %s', e.id, e.id)::::jsonpath
		`)

		memberOfCol = cb.String()
		memberOfJoin = jb.String()

		if groupBy == "" {
			groupBy = `GROUP BY e.id`
		}
	}

	// LEFT JOIN LATERAL(
	// 		SELECT t.rdn_norm, t.rdn_orig FROM ldap_tree t WHERE t.id = e.parent_id
	// 	) p ON true
	searchQuery := fmt.Sprintf(`
		SELECT
			e.id, e.parent_id, e.rdn_orig, '' AS dn_orig,
			e.attrs_orig %s, count(e.id) over() AS count
			%s
			%s
		FROM ldap_entry e 
		%s
		%s
		WHERE %s
		%s
		LIMIT :pageSize OFFSET :offset
	`, hasSubordinatesCol, memberCol, memberOfCol, memberJoin, memberOfJoin, where, groupBy)

	// Resolve pending params
	if len(q.PendingParams) > 0 {
		// Create contaner DN cache
		for k, v := range q.IdToDNOrigCache {
			dn, err := NormalizeDN(v)
			if err != nil {
				log.Printf("error: Failed to normalize DN fetched from DB, err: %s", err)
				return 0, 0, NewUnavailable()
			}
			q.DNNormToIdCache[dn.DNNormStr()] = k
		}
		for pendingDN, paramKey := range q.PendingParams {
			// Find it from cache
			dnNorm := pendingDN.DNNormStr()
			if id, ok := q.DNNormToIdCache[dnNorm]; ok {
				q.Params["filter"] = strings.Replace(q.Params["filter"].(string), ":"+paramKey, strconv.FormatInt(id, 10), 1)
				continue
			}
			// Find the parent container from cache
			parentDNNorm := pendingDN.ParentDN().DNNormStr()
			if parentId, ok := q.DNNormToIdCache[parentDNNorm]; ok {
				// Find by the parent_id and rdn_norm
				rdnNorm := pendingDN.RDNs[0].NormStr()
				id, err := r.FindIDByParentIDAndRDNNorm(nil, parentId, rdnNorm)
				if err != nil {
					log.Printf("debug: Can't find the DN by parent_id: %d and rdn_norm: %s, err: %s", parentId, rdnNorm, err)
					continue
				}

				q.Params["filter"] = strings.Replace(q.Params["filter"].(string), ":"+paramKey, strconv.FormatInt(id, 10), 1)

				// Update cache
				q.DNNormToIdCache[dnNorm] = id

				continue
			}
			// No cache, need to full search...

			dn, err := r.FindPathByDN(nil, pendingDN)
			if err != nil {
				log.Printf("debug: Can't find the DN by DN: %s, err: %s", pendingDN.DNNormStr(), err)
				continue
			}

			q.Params["filter"] = strings.Replace(q.Params["filter"].(string), ":"+paramKey, strconv.FormatInt(dn.ID, 10), 1)

			// Update cache
			q.DNNormToIdCache[dnNorm] = dn.ID
			// Update cache with the parent DN
			if _, ok := q.DNNormToIdCache[parentDNNorm]; !ok {
				parentDN := dn.ParentDN()
				for parentDN != nil {
					if _, ok := q.DNNormToIdCache[parentDN.DNNorm()]; ok {
						break
					}
					q.DNNormToIdCache[parentDN.DNNorm()] = parentDN.ID

					// Next parent
					parentDN = parentDN.ParentDN()
				}
			}
		}
	}

	log.Printf("Fetch Query: %s Params: %v", searchQuery, q.Params)

	var fetchStmt *sqlx.NamedStmt
	var ok bool
	if fetchStmt, ok = filterStmtMap.Get(searchQuery); !ok {
		// cache
		fetchStmt, err = r.db.PrepareNamed(searchQuery)
		if err != nil {
			return 0, 0, err
		}
		filterStmtMap.Put(searchQuery, fetchStmt)
	}

	var rows *sqlx.Rows
	rows, err = fetchStmt.Queryx(q.Params)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()

	dbEntry := FetchedDBEntry{}
	var maxCount int32 = 0
	var count int32 = 0

	for rows.Next() {
		err := rows.StructScan(&dbEntry)
		if err != nil {
			log.Printf("error: DBEntry struct mapping error: %#v", err)
			return 0, 0, err
		}

		// Set dn_orig using cache from fetching before phase
		var dnOrig string
		if dnOrig, ok = q.IdToDNOrigCache[dbEntry.ID]; !ok {
			parentDNOrig, ok := q.IdToDNOrigCache[dbEntry.ParentID]
			if !ok {
				log.Printf("error: Invalid state, failed to retrieve parent by parent_id: %d", dbEntry.ParentID)
				return 0, 0, xerrors.Errorf("Failed to retrieve parent by parent_id: %d", dbEntry.ParentID)
			}

			dnOrig = dbEntry.RDNOrig + "," + parentDNOrig
		}
		dbEntry.DNOrig = dnOrig

		readEntry, err := mapper.FetchedDBEntryToSearchEntry(&dbEntry, q.IdToDNOrigCache)
		if err != nil {
			log.Printf("error: Mapper error: %#v", err)
			return 0, 0, err
		}

		if maxCount == 0 {
			maxCount = dbEntry.Count
		}

		err = handler(readEntry)
		if err != nil {
			log.Printf("error: Handler error: %#v", err)
			return 0, 0, err
		}

		count++
		dbEntry.Clear()
	}

	err = rows.Err()
	if err != nil {
		log.Printf("error: Search error: %#v", err)
		return 0, 0, err
	}

	return maxCount, count, nil
}

func getDC(tx *sqlx.Tx) (*FetchedDBEntry, error) {
	var err error
	dest := FetchedDBEntry{}

	if tx != nil {
		err = tx.NamedStmt(getDCStmt).Get(&dest, map[string]interface{}{})
	} else {
		err = getDCStmt.Get(&dest, map[string]interface{}{})
	}
	if err != nil {
		return nil, err
	}

	return &dest, nil
}

type FindOption struct {
	Lock       bool
	FetchAttrs bool
	FetchCred  bool
}

func (r *Repository) PrepareFindDNByDN(dn *DN, opt *FindOption) (*sqlx.NamedStmt, map[string]interface{}, error) {
	//  Key for stmt cache
	key := fmt.Sprintf("PrepareFindDNByDN/LOCK:%v/FETCH_ATTRS:%v/FETCH_CRED:%v/DEPTH:%d",
		opt.Lock, opt.FetchAttrs, opt.FetchCred, len(dn.RDNs))

	// make params
	params := createFindTreePathByDNParams(dn)

	if stmt, ok := treeStmtCache.Get(key); ok {
		// Already cached
		return stmt, params, nil
	}

	// Not cached yet, create query and params, then cache the stmt
	q, err := createFindBasePathByDNSQL(dn, opt)
	if err != nil {
		return nil, nil, err
	}

	log.Printf("debug: createFindTreePathByDNSQL: %s\nparams: %v", q, params)

	stmt, err := r.db.PrepareNamed(q)
	if err != nil {
		return nil, nil, err
	}
	treeStmtCache.Put(key, stmt)

	return stmt, params, nil
}
func (r *Repository) PrepareFindPathByDN(dn *DN) (*sqlx.NamedStmt, map[string]interface{}, error) {
	//  Key for stmt cache
	key := fmt.Sprintf("PrepareFindPathByDN/DEPTH:%d",
		len(dn.RDNs))

	// make params
	params := createFindTreePathByDNParams(dn)

	if stmt, ok := treeStmtCache.Get(key); ok {
		// Already cached
		return stmt, params, nil
	}

	// Not cached yet, create query and params, then cache the stmt
	q, err := createFindTreePathByDNSQL(dn)
	// q, err := createFindBasePathByDNSQL(dn, opt)
	if err != nil {
		return nil, nil, err
	}

	log.Printf("debug: createFindTreePathByDNSQL: %s\nparams: %v", q, params)

	stmt, err := r.db.PrepareNamed(q)
	if err != nil {
		return nil, nil, err
	}
	treeStmtCache.Put(key, stmt)

	return stmt, params, nil
}

func createFindTreePathByDNParams(baseDN *DN) map[string]interface{} {
	if baseDN == nil {
		return map[string]interface{}{}
	}

	depth := len(baseDN.RDNs)
	last := depth - 1
	params := make(map[string]interface{}, depth)
	ii := 0
	for i := last; i >= 0; i-- {
		params["rdn_norm"+strconv.Itoa(ii)] = baseDN.RDNs[i].NormStr()
		ii++
	}
	return params
}

// createFindBasePathByDNSQL returns a SQL which selects id, parent_id, path and dn_orig.
func createFindBasePathByDNSQL(baseDN *DN, opt *FindOption) (string, error) {
	if len(baseDN.RDNs) == 0 {
		return "", xerrors.Errorf("Invalid DN, it's anonymous")
	}

	var fetchAttrsCols string
	if opt.FetchAttrs {
		fetchAttrsCols = `e0.attrs_orig,`
	}

	var fetchCredCols string
	if opt.FetchCred {
		fetchCredCols = `e0.attrs_orig->'userPassword' as cred,`
	}

	if baseDN.IsRoot() {
		return `
			SELECT
				e0.rdn_orig as dn_orig,
				e0.id,
				e0.parent_id,
				` + fetchAttrsCols + `
				` + fetchCredCols + `
				e0.id::ltree as path
			FROM
				ldap_entry e0 
			WHERE
				e0.rdn_norm = :rdn_norm0 AND e0.parent_id is NULL
		`, nil
	}

	/*
		SELECT
			e2.rdn_orig || ',' || e1.rdn_orig || ',' || e0.rdn_orig,
			e2.id,
			e2.parent_id,
			(e0.id || '.' || e1.id || '.' || e2.id) as path
		FROM
			ldap_entry e0, ldap_entry e1, ldap_entry e2
		WHERE
			e0.rdn_norm = 'dc=com' AND e1.rdn_norm = 'dc=example' AND e2.rdn_norm = 'ou=users'
			AND e0.parent_id is NULL AND e1.parent_id = e0.id AND e2.parent_id = e1.id
			;
				?column?          | id | parent_id | path  | has_sub
		----------------------------+----+-----------+-------+---------
		ou=Users,dc=Example,dc=com |  2 |         1 | 0.1.2 |       1


		SELECT
			e3.rdn_orig || ',' || e2.rdn_orig || ',' || e1.rdn_orig || ',' || e0.rdn_orig,
			e3.id,
			e3.parent_id,
			(e0.id || '.' || e1.id || '.' || e2.id || '.' || e3.id) as path
		FROM
			ldap_entry e0, ldap_entry e1, ldap_entry e2, ldap_entry e3
		WHERE
			e0.rdn_norm = 'dc=com' AND e1.rdn_norm = 'dc=example' AND e2.rdn_norm = 'ou=users' AND e3.rdn_norm = 'uid=u000001'
			AND e0.parent_id is NULL AND e1.parent_id = e0.id AND e2.parent_id = e1.id AND e3.parent_id = e2.id

						?column?                | id | parent_id |  path   | has_sub
		----------------------------------------+----+-----------+---------+---------
		uid=u000001,ou=Users,dc=Example,dc=com |  4 |         2 | 0.1.2.4 |       0

	*/
	lastIndex := len(baseDN.RDNs) - 1
	lastIndexStr := strconv.Itoa(lastIndex)

	proj := []string{}
	proj2 := []string{}
	table := []string{}
	where := []string{}
	where2 := []string{}
	for index := range baseDN.RDNs {
		proj = append(proj, fmt.Sprintf("e%d.rdn_orig", lastIndex-index))
		proj2 = append(proj2, fmt.Sprintf("e%d.id", index))
		table = append(table, fmt.Sprintf("ldap_entry e%d", index))
		where = append(where, fmt.Sprintf("e%d.rdn_norm = :rdn_norm%d", index, index))
		if index == 0 {
			where2 = append(where2, fmt.Sprintf("e%d.parent_id is NULL", index))
		} else {
			where2 = append(where2, fmt.Sprintf("e%d.parent_id = e%d.id", index, index-1))
		}
	}
	if opt.FetchAttrs {
		fetchAttrsCols = `e` + lastIndexStr + `.attrs_orig,`
	}

	if opt.FetchCred {
		fetchCredCols = `e` + lastIndexStr + `.attrs_orig->'userPassword' as cred,`
	}

	var lock string
	if opt.Lock {
		lock = " for UPDATE"
	}

	sql := `
	SELECT
	  ` + strings.Join(proj, " || ',' || ") + ` as dn_orig,
	  e` + lastIndexStr + `.id, 
	  e` + lastIndexStr + `.parent_id, 
	  ` + fetchAttrsCols + `
	  ` + fetchCredCols + `
	  ` + strings.Join(proj2, " || '.' || ") + ` as path
	FROM
	  ` + strings.Join(table, ", ") + `
	WHERE
	  ` + strings.Join(where, " AND ") + ` 
	  AND
	  ` + strings.Join(where2, " AND ") + ` 
	` + lock + `
	`

	log.Printf("debug: createFindBasePathByDNSQL: %s", sql)

	return sql, nil
}

// createFindTreePathByDNSQL returns a SQL which selects id, parent_id, dn_orig, path and has_sub.
// This sql can't offer lock version since it uses outer join.
func createFindTreePathByDNSQL(baseDN *DN) (string, error) {
	if len(baseDN.RDNs) == 0 {
		return "", xerrors.Errorf("Invalid DN, it's anonymous")
	}

	if baseDN.IsRoot() {
		return `
			SELECT
				e0.rdn_orig as dn_orig,
				e0.id,
				e0.parent_id,
				e0.id::ltree as path,
				(CASE WHEN t0.id IS NOT NULL THEN 1 ELSE 0 END) as has_sub
			FROM
				ldap_entry e0 
				LEFT JOIN ldap_tree t0 ON t0.id = e0.id
			WHERE
				e0.rdn_norm = :rdn_norm0 AND e0.parent_id is NULL
		`, nil
	}

	/*
		SELECT
			e2.rdn_orig || ',' || e1.rdn_orig || ',' || e0.rdn_orig,
			e2.id,
			e2.parent_id,
			(e0.id || '.' || e1.id || '.' || e2.id) as path,
			(CASE WHEN t0.id IS NOT NULL THEN 1 ELSE 0 END) as has_sub
		FROM
			ldap_entry e0, ldap_entry e1, ldap_entry e2
			LEFT JOIN ldap_tree t0 ON t0.id = e2.id
		WHERE
			e0.rdn_norm = 'dc=com' AND e1.rdn_norm = 'dc=example' AND e2.rdn_norm = 'ou=users'
			AND e0.parent_id is NULL AND e1.parent_id = e0.id AND e2.parent_id = e1.id
			;
				?column?          | id | parent_id | path  | has_sub
		----------------------------+----+-----------+-------+---------
		ou=Users,dc=Example,dc=com |  2 |         1 | 0.1.2 |       1


		SELECT
			e3.rdn_orig || ',' || e2.rdn_orig || ',' || e1.rdn_orig || ',' || e0.rdn_orig,
			e3.id,
			e3.parent_id,
			(e0.id || '.' || e1.id || '.' || e2.id || '.' || e3.id) as path,
			(CASE WHEN t0.id IS NOT NULL THEN 1 ELSE 0 END) as has_sub
		FROM
			ldap_entry e0, ldap_entry e1, ldap_entry e2, ldap_entry e3
			LEFT JOIN ldap_tree t0 ON t0.id = e3.id
		WHERE
			e0.rdn_norm = 'dc=com' AND e1.rdn_norm = 'dc=example' AND e2.rdn_norm = 'ou=users' AND e3.rdn_norm = 'uid=u000001'
			AND e0.parent_id is NULL AND e1.parent_id = e0.id AND e2.parent_id = e1.id AND e3.parent_id = e2.id

						?column?                | id | parent_id |  path   | has_sub
		----------------------------------------+----+-----------+---------+---------
		uid=u000001,ou=Users,dc=Example,dc=com |  4 |         2 | 0.1.2.4 |       0

	*/
	lastIndex := len(baseDN.RDNs) - 1
	lastIndexStr := strconv.Itoa(lastIndex)

	// var fetchAttrs string
	// if opt.FetchAttrs {
	// 	fetchAttrs = `e` + strconv.Itoa(lastIndex) + `.attrs_orig, e` + lastIndexStr + `.attrs_orig,`
	// }

	proj := []string{}
	proj2 := []string{}
	table := []string{}
	where := []string{}
	where2 := []string{}
	for index := range baseDN.RDNs {
		proj = append(proj, fmt.Sprintf("e%d.rdn_orig", lastIndex-index))
		proj2 = append(proj2, fmt.Sprintf("e%d.id", index))
		table = append(table, fmt.Sprintf("ldap_entry e%d", index))
		where = append(where, fmt.Sprintf("e%d.rdn_norm = :rdn_norm%d", index, index))
		if index == 0 {
			where2 = append(where2, fmt.Sprintf("e%d.parent_id is NULL", index))
		} else {
			where2 = append(where2, fmt.Sprintf("e%d.parent_id = e%d.id", index, index-1))
		}
	}

	sql := `
	SELECT
	  ` + strings.Join(proj, " || ',' || ") + ` as dn_orig,
	  e` + lastIndexStr + `.id, 
	  e` + lastIndexStr + `.parent_id, 
	  ` + strings.Join(proj2, " || '.' || ") + ` as path,
	  (CASE WHEN t0.id IS NOT NULL THEN 1 ELSE 0 END) as has_sub
	FROM
	  ` + strings.Join(table, ", ") + `
	  LEFT JOIN ldap_tree t0 ON t0.id = e` + lastIndexStr + `.id
	WHERE
	  ` + strings.Join(where, " AND ") + ` 
	  AND
	  ` + strings.Join(where2, " AND ") + ` 
	`

	log.Printf("debug: createFindTreePathSQL: %s", sql)

	return sql, nil
}

func namedStmt(tx *sqlx.Tx, stmt *sqlx.NamedStmt) *sqlx.NamedStmt {
	if tx != nil {
		return tx.NamedStmt(stmt)
	}
	return stmt
}

func txLabel(tx *sqlx.Tx) string {
	if tx == nil {
		return "non-tx"
	}
	return "tx"
}

// FindPathByDN returns FetchedDN object from database by DN search.
func (r *Repository) FindPathByDN(tx *sqlx.Tx, dn *DN) (*FetchedDN, error) {
	stmt, params, err := r.PrepareFindPathByDN(dn)
	if err != nil {
		return nil, xerrors.Errorf("Failed to prepare FindDNByDN: %v, err: %w", dn, err)
	}

	var dest FetchedDN
	err = namedStmt(tx, stmt).Get(&dest, params)
	if err != nil {
		if isNoResult(err) {
			return nil, NewNoSuchObject()
		}
		return nil, xerrors.Errorf("Failed to fetch FindDNByDN in %s: %v, err: %w", txLabel(tx), dn, err)
	}

	return &dest, nil
}

func (r *Repository) FindDNByDNWithLock(tx *sqlx.Tx, dn *DN, lock bool) (*FetchedDN, error) {
	stmt, params, err := r.PrepareFindDNByDN(dn, &FindOption{Lock: lock})
	if err != nil {
		return nil, xerrors.Errorf("Failed to prepare FindDNOnlyByDN: %v, err: %w", dn, err)
	}

	var dest FetchedDN
	err = namedStmt(tx, stmt).Get(&dest, params)
	if err != nil {
		if isNoResult(err) {
			return nil, NewNoSuchObject()
		}
		return nil, xerrors.Errorf("Failed to fetch FindDNOnlyByDN in %s: %v, err: %w", txLabel(tx), dn, err)
	}

	return &dest, nil
}

// FindEntryByDN returns FetchedDBEntry object from database by DN search.
func (r *Repository) FindEntryByDN(tx *sqlx.Tx, dn *DN, lock bool) (*ModifyEntry, error) {
	stmt, params, err := r.PrepareFindDNByDN(dn, &FindOption{Lock: lock, FetchAttrs: true})
	if err != nil {
		return nil, xerrors.Errorf("Failed to prepare FindEntryByDN: %v, err: %w", dn, err)
	}

	var dest FetchedEntry
	err = namedStmt(tx, stmt).Get(&dest, params)
	if err != nil {
		if isNoResult(err) {
			return nil, NewNoSuchObject()
		}
		return nil, xerrors.Errorf("Failed to fetch FindEntryByDN in %s: %v, err: %w", txLabel(tx), dn, err)
	}

	return mapper.FetchedEntryToModifyEntry(&dest)
}

func (r *Repository) FindContainerByDN(tx *sqlx.Tx, dn *FetchedDN, scope int) ([]*FetchedDNOrig, error) {
	// Scope handling, sub need to include base.
	// 0: base
	// 1: one
	// 2: sub
	// 3: children

	if scope == 0 || scope == 1 {
		return nil, xerrors.Errorf("Invalid scope, it should be 2(sub) or 3(children): %d", scope)
	}

	var rows *sqlx.Rows
	var err error

	if !dn.HasSub {
		return []*FetchedDNOrig{{
			ID:     dn.ID,
			DNOrig: dn.DNOrig,
		}}, nil
	}

	if scope == 2 { // sub
		rows, err = namedStmt(tx, findContainerByPathStmt).Queryx(map[string]interface{}{
			"path": dn.Path + ".*{0,}",
		})
	} else if scope == 3 { // children
		rows, err = namedStmt(tx, findContainerByPathStmt).Queryx(map[string]interface{}{
			"path": dn.Path + ".*{1,}",
		})
	}

	if err != nil {
		return nil, xerrors.Errorf("Failed to find containers by DN: %v, err: %w", dn, err)
	}
	defer rows.Close()

	list := []*FetchedDNOrig{}
	for rows.Next() {
		child := FetchedDNOrig{}
		err = rows.StructScan(&child)
		if err != nil {
			return nil, xerrors.Errorf("Failed to find containers by DN due to fail struct scan, DN: %v, err: %w", dn, err)
		}
		list = append(list, &child)
	}

	err = rows.Err()
	if err != nil {
		log.Printf("error: Search children error: %#v", err)
		return nil, err
	}

	return list, nil
}

func (r *Repository) FindIDByParentIDAndRDNNorm(tx *sqlx.Tx, parentId int64, rdn_norm string) (int64, error) {
	var dest int64
	err := namedStmt(tx, findIDByParentIDAndRDNNormStmt).Get(&dest, map[string]interface{}{
		"parent_id": parentId,
		"rdn_norm":  rdn_norm,
	})
	if err != nil {
		if isNoResult(err) {
			return 0, NewNoSuchObject()
		}
		return 0, xerrors.Errorf("Failed to find ID by parent_id: %d and rdn_norm: %s, err: %w", parentId, rdn_norm, err)
	}

	return dest, nil
}

func (r *Repository) FindCredByDN(dn *DN) ([]string, error) {
	stmt, params, err := r.PrepareFindDNByDN(dn, &FindOption{FetchCred: true})
	if err != nil {
		return nil, xerrors.Errorf("Failed to prepare FindEntryByDN: %v, err: %w", dn, err)
	}

	dest := struct {
		ID     int64          `db:"id"`
		DNOrig string         `db:"dn_orig"`
		Cred   types.JSONText `db:"cred"`
	}{}

	err = stmt.Get(&dest, params)
	if err != nil {
		if isNoResult(err) {
			return nil, NewInvalidCredentials()
		}
		return nil, xerrors.Errorf("Failed to find cred by DN. dn: %s, err: %w", dn.DNOrigStr(), err)
	}

	var cred []string
	err = dest.Cred.Unmarshal(&cred)
	if err != nil {
		return nil, xerrors.Errorf("Failed to unmarshal cred array. dn: %s, err: %w", dn.DNOrigStr(), err)
	}

	return cred, nil
}

func (r *Repository) AppenScopeFilter(scope int, q *Query, fetchedDN *FetchedDN) (string, error) {

	// Make query based on the requested scope

	// Scope handling, one and sub need to include base.
	// 0: base
	// 1: one
	// 2: sub
	// 3: children
	var parentFilter string
	if scope == 0 { // base
		parentFilter = "e.id = :baseDNID"
		q.Params["baseDNID"] = fetchedDN.ID

	} else if scope == 1 { // one
		parentFilter = "e.parent_id = :baseDNID"
		q.Params["baseDNID"] = fetchedDN.ID

	} else if scope == 2 { // sub
		containers, err := r.FindContainerByDN(nil, fetchedDN, scope)
		if err != nil {
			return "", err
		}

		// Cache
		for _, c := range containers {
			q.IdToDNOrigCache[c.ID] = c.DNOrig
		}

		in, params := expandContainersIn(containers)
		parentFilter = "(e.id = :baseDNID OR e.parent_id IN (" + in + "))"
		q.Params["baseDNID"] = fetchedDN.ID
		for k, v := range params {
			q.Params[k] = v
		}

	} else if scope == 3 { // children
		containers, err := r.FindContainerByDN(nil, fetchedDN, scope)
		if err != nil {
			return "", err
		}

		// Cache
		for _, c := range containers {
			q.IdToDNOrigCache[c.ID] = c.DNOrig
		}

		in, params := expandContainersIn(containers)
		parentFilter = "e.parent_id = :baseDNID OR e.parent_id IN (" + in + ")"
		q.Params["baseDNID"] = fetchedDN.ID
		for k, v := range params {
			q.Params[k] = v
		}
	}

	var query string
	if q.Query != "" {
		query = " AND " + q.Query
	}

	return fmt.Sprintf("%s %s", parentFilter, query), nil
}
