package main

import (
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
	"golang.org/x/xerrors"
)

type FetchedDBEntry struct {
	ID              int64          `db:"id"`
	ParentID        int64          `db:"parent_id"`
	EntryUUID       string         `db:"uuid"`
	Created         time.Time      `db:"created"`
	Updated         time.Time      `db:"updated"`
	RDNOrig         string         `db:"rdn_orig"`
	AttrsOrig       types.JSONText `db:"attrs_orig"`
	Member          types.JSONText `db:"member"`          // No real column in the table
	UniqueMember    types.JSONText `db:"uniquemember"`    // No real column in the table
	MemberOf        types.JSONText `db:"member_of"`       // No real column in the table
	HasSubordinates string         `db:"hassubordinates"` // No real column in the table
	DNOrig          string         `db:"dn_orig"`         // No real clumn in t he table
	Count           int32          `db:"count"`           // No real column in the table
	ParentDNOrig    string         // No real column in t he table
}

type FetchedMember struct {
	RDNOrig      string `db:"r"`
	ParentID     int64  `db:"p"`
	AttrNameNorm string `db:"a"`
}

func (e *FetchedDBEntry) IsDC() bool {
	return e.ParentID == ROOT_ID
}

func (e *FetchedDBEntry) Members(IdToDNOrigCache map[int64]string, suffix string) ([]string, error) {
	if len(e.Member) == 0 {
		return nil, nil
	}

	jsonArray := [][]string{}
	err := e.Member.Unmarshal(&jsonArray)
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

func (e *FetchedDBEntry) MemberOfs(dnOrigCache map[int64]string, suffix string) ([]string, error) {
	if len(e.MemberOf) > 0 {
		jsonArray := []map[string]string{}
		err := e.MemberOf.Unmarshal(&jsonArray)
		if err != nil {
			return nil, err
		}

		dns := make([]string, len(jsonArray))

		for i, m := range jsonArray {
			pid, err := strconv.ParseInt(m["p"], 10, 64)
			if err != nil {
				return nil, xerrors.Errorf("Invalid parent_id: %s", m["p"])
			}
			parentDNOrig, ok := dnOrigCache[pid]
			if !ok {
				return nil, xerrors.Errorf("No cached: %s", m["p"])
			}

			var s string
			if parentDNOrig == "" {
				s = suffix
			} else {
				s = parentDNOrig + "," + suffix
			}

			dns[i] = m["r"] + "," + s
		}
		return dns, nil
	}
	return nil, nil
}

func (e *FetchedDBEntry) GetAttrsOrig() map[string][]string {
	if len(e.AttrsOrig) > 0 {
		jsonMap := make(map[string][]string)
		e.AttrsOrig.Unmarshal(&jsonMap)

		if len(e.MemberOf) > 0 {
			jsonArray := []string{}
			e.MemberOf.Unmarshal(&jsonArray)
			jsonMap["memberOf"] = jsonArray
		}

		return jsonMap
	}
	return nil
}

func (e *FetchedDBEntry) Clear() {
	e.ID = 0
	e.DNOrig = ""
	e.AttrsOrig = nil
	e.MemberOf = nil
	e.Count = 0
}

type FetchedDNOrig struct {
	ID     int64  `db:"id"`
	DNOrig string `db:"dn_orig"`
}

func (r *Repository) Search(baseDN *DN, scope int, q *Query, reqMemberAttrs []string,
	reqMemberOf, isHasSubordinatesRequested bool, handler func(entry *SearchEntry) error) (int32, int32, error) {

	fetchedDN, err := r.FindDNByDN(nil, baseDN)
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

	// LEFT JOIN LATERAL(
	// 		SELECT t.rdn_norm, t.rdn_orig FROM ldap_tree t WHERE t.id = e.parent_id
	// 	) p ON true
	searchQuery := fmt.Sprintf(`
		SELECT
			e.id, e.parent_id, e.uuid, e.created, e.updated, e.rdn_orig, '' AS dn_orig,
			e.attrs_orig %s, count(e.id) over() AS count
			%s
		FROM ldap_entry e 
		%s
		WHERE %s
		%s
		LIMIT :pageSize OFFSET :offset
	`, hasSubordinatesCol, memberCol, memberJoin, where, groupBy)

	// Resolve pending params
	if len(q.PendingParams) > 0 {
		// Create contaner DN cache
		for k, v := range q.IdToDNOrigCache {
			dn, err := NormalizeDN(r.server.suffixOrig, v)
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

			dn, err := r.FindDNByDN(nil, pendingDN)
			if err != nil {
				log.Printf("debug: Can't find the DN by DN: %s, err: %s", pendingDN.DNNormStr(), err)
				continue
			}

			q.Params["filter"] = strings.Replace(q.Params["filter"].(string), ":"+paramKey, strconv.FormatInt(dn.ID, 10), 1)

			// Update cache
			q.DNNormToIdCache[dnNorm] = dn.ID
			// Update cache with the parent DN
			if _, ok := q.DNNormToIdCache[parentDNNorm]; !ok {
				if dn.ParentPath != "" {
					parentIds := strings.Split(dn.ParentPath, ".")

					parentDN := pendingDN
					for i := len(parentIds) - 1; i >= 0; i-- {
						parentDN = parentDN.ParentDN()

						ii, err := strconv.ParseInt(parentIds[i], 10, 64)
						if err != nil {
							log.Printf("error: Failed to detect parent_id from path: %s, err: %s", dn.ParentPath, err)
							return 0, 0, NewUnavailable()
						}

						if _, ok := q.DNNormToIdCache[parentDN.DNNormStr()]; ok {
							break
						}
						q.DNNormToIdCache[parentDN.DNNormStr()] = ii
					}
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

func getDCDNOrig(tx *sqlx.Tx) (*FetchedDNOrig, error) {
	var err error
	dest := FetchedDNOrig{}

	if tx != nil {
		err = tx.NamedStmt(getDCDNOrigStmt).Get(&dest, map[string]interface{}{})
	} else {
		err = getDCDNOrigStmt.Get(&dest, map[string]interface{}{})
	}
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("warn: Not found DC in the tree.")
			return nil, NewNoSuchObject()
		}
		return nil, xerrors.Errorf("Failed to get DC DN. err: %w", err)
	}

	return &dest, nil
}

type FindOption struct {
	Lock       bool
	FetchAttrs bool
	FetchCred  bool
}

func (r *Repository) FindByDN(tx *sqlx.Tx, dn *DN, option *FindOption) (*FetchedDBEntry, error) {
	if dn == nil {
		return nil, xerrors.Errorf("Failed to find by DN because the DN is nil. You might try to find parent of DC entry.")
	}
	if dn.IsDC() {
		return getDC(tx)
	}

	stmt, params, err := r.PrepareFindByDN(tx, dn, option)
	if err != nil {
		return nil, err
	}

	dest := FetchedDBEntry{}

	if tx != nil {
		err = tx.NamedStmt(stmt).Get(&dest, params)
	} else {
		err = stmt.Get(&dest, params)
	}
	if err != nil {
		return nil, err
	}

	return &dest, nil
}

func (r *Repository) PrepareFindByDN(tx *sqlx.Tx, dn *DN, option *FindOption) (*sqlx.NamedStmt, map[string]interface{}, error) {
	//  Key for stmt cache
	key := fmt.Sprintf("LOCK:%v/FETCH_ATTRS:%v/FETCH_CRED:%v/DEPTH:%d",
		option.Lock, option.FetchAttrs, option.FetchCred, len(dn.RDNs))

	if stmt, ok := findByDNStmtCache.Get(key); ok {
		// Already cached, make params only
		depthj := len(dn.RDNs)
		last := depthj - 1
		params := make(map[string]interface{}, depthj)

		for i := last; i >= 0; i-- {
			params[fmt.Sprintf("rdn_norm_%d", i)] = dn.RDNs[i].NormStr()
		}
		return stmt, params, nil
	}

	// Not cached yet, create query and params, then cache the stmt
	q, params := r.CreateFindByDNQuery(dn, option)

	var err error
	var stmt *sqlx.NamedStmt
	if tx != nil {
		stmt, err = tx.PrepareNamed(q)
	} else {
		stmt, err = r.db.PrepareNamed(q)
	}
	if err != nil {
		return nil, nil, err
	}
	findByDNStmtCache.Put(key, stmt)

	return stmt, params, nil
}

func (r *Repository) PrepareFindPathByDN(dn *DN, opt *FindOption) (*sqlx.NamedStmt, map[string]interface{}, error) {
	//  Key for stmt cache
	key := fmt.Sprintf("PATH/DEPTH:%d", len(dn.RDNs))

	// make params
	depth := len(dn.RDNs)
	last := depth - 1
	params := make(map[string]interface{}, depth)
	ii := 0
	for i := last; i >= 0; i-- {
		params["rdn_norm"+strconv.Itoa(ii)] = dn.RDNs[i].NormStr()
		ii++
	}

	if stmt, ok := treeStmtCache.Get(key); ok {
		// Already cached
		return stmt, params, nil
	}

	// Not cached yet, create query and params, then cache the stmt
	q, err := createFindTreePathSQL(dn, opt)
	if err != nil {
		return nil, nil, err
	}

	stmt, err := r.db.PrepareNamed(q)
	if err != nil {
		return nil, nil, err
	}
	treeStmtCache.Put(key, stmt)

	return stmt, params, nil
}

func (r *Repository) PrepareFindTreeByDN(dn *DN) (*sqlx.NamedStmt, map[string]interface{}, error) {
	//  Key for stmt cache
	key := fmt.Sprintf("TREE/DEPTH:%d", len(dn.RDNs))

	if stmt, ok := findByDNStmtCache.Get(key); ok {
		// Already cached, make params only
		depthj := len(dn.RDNs)
		last := depthj - 1
		params := make(map[string]interface{}, depthj)

		for i := last; i >= 0; i-- {
			params[fmt.Sprintf("rdn_norm_%d", i)] = dn.RDNs[i].NormStr()
		}
		return stmt, params, nil
	}

	// Not cached yet, create query and params, then cache the stmt
	dnq, params := r.CreateFindByDNQuery(dn, &FindOption{Lock: false})

	q := fmt.Sprintf(`WITH RECURSIVE dn AS
	(
		%s
	),
	child (depth, dn_orig, id, parent_id) AS
	(
		SELECT 0, dn.dn_orig::::TEXT AS dn_orig, e.id, e.parent_id
			FROM ldap_tree e, dn WHERE e.id = dn.id 
			UNION ALL
				SELECT
					child.depth + 1,
					CASE child.dn_orig
						WHEN '' THEN e.rdn_orig 
						ELSE e.rdn_orig || ',' || child.dn_orig
					END,
					e.id,
					e.parent_id
				FROM ldap_tree e, child
				WHERE e.parent_id = child.id
	)
	SELECT id, dn_orig FROM child ORDER BY depth`, dnq)

	log.Printf("PrepareFindTreeByDN: %s", q)

	stmt, err := r.db.PrepareNamed(q)
	if err != nil {
		return nil, nil, err
	}
	findByDNStmtCache.Put(key, stmt)

	return stmt, params, nil
}

func (r *Repository) CreateFindByDNQuery(dn *DN, option *FindOption) (string, map[string]interface{}) {
	// 	SELECT e.id, e.rdn_orig || ',' || e0.rdn_orig || ',' || e1.rdn_orig || ',' || e2.rdn_orig AS dn_orig
	//	   FROM ldap_tree dc
	//     INNER JOIN ldap_tree e2 ON e2.parent_id = dc.id
	//     INNER JOIN ldap_tree e1 ON e1.parent_id = e2.id
	//     INNER JOIN ldap_tree e0 ON e0.parent_id = e1.id
	//     INNER JOIN ldap_entry e ON e.parent_id = e0.id
	//     WHERE dc.parent_id = 0 AND e2.rdn_norm = 'ou=mycompany' AND e1.rdn_norm = 'ou=mysection' AND e0.rdn_norm = 'ou=mydept' AND e.rdn_norm = 'cn=mygroup'
	//     FOR UPDATE ldap_entry

	var fetchAttrsProjection string
	var memberJoin string
	if option.FetchAttrs {
		fetchAttrsProjection += `, e0.parent_id, e0.rdn_orig, e0.attrs_orig, to_jsonb(ma.member_array) as member`
		// TODO use join when the entry's schema has member
		memberJoin += `, LATERAL (
				SELECT ARRAY (
					SELECT jsonb_build_object('r', ee.rdn_orig, 'p', ee.parent_id::::TEXT, 'a', lm.attr_name_norm) 
						FROM ldap_member lm
							JOIN ldap_entry ee ON ee.id = lm.member_of_id
						WHERE lm.member_id = e0.id 
				) AS member_array
			) ma`
	}
	if option.FetchCred {
		fetchAttrsProjection += `, e0.attrs_norm->>'userPassword' as cred`
	}

	if dn.IsDC() {
		q := fmt.Sprintf(`SELECT id, '' as dn_orig %s FROM ldap_entry
		WHERE parent_id = %d`, fetchAttrsProjection, ROOT_ID)
		return q, map[string]interface{}{}
	}

	size := len(dn.RDNs)
	last := size - 1
	params := make(map[string]interface{}, size)

	projection := make([]string, size)
	join := make([]string, size)
	where := make([]string, size)

	for i := last; i >= 0; i-- {
		projection[i] = fmt.Sprintf("e%d.rdn_orig", i)
		if i == last {
			join[last-i] = fmt.Sprintf("INNER JOIN ldap_tree e%d ON e%d.parent_id = dc.id", i, i)
		} else if i > 0 {
			join[last-i] = fmt.Sprintf("INNER JOIN ldap_tree e%d ON e%d.parent_id = e%d.id", i, i, i+1)
		} else {
			join[last-i] = "INNER JOIN ldap_entry e0 ON e0.parent_id = e1.id"
		}
		where[last-i] = fmt.Sprintf("e%d.rdn_norm = :rdn_norm_%d", i, i)

		params[fmt.Sprintf("rdn_norm_%d", i)] = dn.RDNs[i].NormStr()
	}

	q := fmt.Sprintf(`SELECT e0.id, %s AS dn_orig %s
		FROM ldap_tree dc %s %s
		WHERE dc.parent_id = %d AND %s`,
		strings.Join(projection, " || ',' || "), fetchAttrsProjection,
		strings.Join(join, " "), memberJoin,
		ROOT_ID, strings.Join(where, " AND "))

	if option.Lock {
		q += " FOR UPDATE"
	}

	log.Printf("debug: findByDN query: %s, params: %v", q, params)

	return q, params
}

func collectAllNodeNorm() (map[string]int64, error) {
	dc, err := getDCDNOrig(nil)
	if err != nil {
		return nil, err
	}
	nodes, err := collectNodeNormByParentID(nil, dc.ID)
	if err != nil {
		return nil, err
	}

	cache := make(map[string]int64, len(nodes)+1)
	cache[""] = dc.ID

	for _, n := range nodes {
		cache[n.DNNorm] = n.ID
	}

	return cache, nil
}

func createFindTreePathSQL(baseDN *DN, opt *FindOption) (string, error) {
	if len(baseDN.RDNs) == 0 {
		return "", xerrors.Errorf("Invalid DN, it's anonymous")
	}

	if baseDN.IsRoot() {
		return `SELECT e0.rdn_orig as dn_orig, e0.id, '' as parent_path, (CASE WHEN ex.id IS NOT NULL THEN 1 ELSE 0 END) as has_sub FROM ldap_entry e0 LEFT JOIN ldap_tree ex ON e0.id = ex.id WHERE e0.rdn_norm = :rdn_norm0 AND e0.parent_id is NULL`, nil
	}

	/*
		SELECT
			e4.rdn_orig || ',' || e3.rdn_orig || ',' || e2.rdn_orig || ',' || e1.rdn_orig,
			e4.id, t3.path as parent_path,
			(CASE WHEN ex.id IS NOT NULL THEN 1 ELSE 0 END) as has_sub
		FROM
			ldap_tree t1, ldap_tree t2, ldap_tree t3,
			ldap_entry e1, ldap_entry e2, ldap_entry e3, ldap_entry e4
			LEFT JOIN ldap_tree ex ON e4.id = ex.id
		WHERE
			e1.rdn_norm = 'dc=com' AND e2.rdn_norm = 'dc=example' AND e3.rdn_norm = 'ou=users' AND e4.rdn_norm = 'uid=u000001'
			AND t1.parent_id is NULL AND t2.parent_id = t1.id AND t3.parent_id = t2.id AND e4.parent_id = t3.id
			AND t1.id = e1.id
			AND t2.id = e2.id
			AND t3.id = e3.id

		                ?column?                |  id  | parent_path | has_sub
		----------------------------------------+------+-------------+---------
		 uid=u000001,ou=Users,dc=Example,dc=com |   4  |0.1.2        |       0
	*/
	proj := []string{}
	table := []string{}
	where := []string{}
	where2 := []string{}
	for index := range baseDN.RDNs {
		proj = append(proj, fmt.Sprintf("e%d.rdn_orig", len(baseDN.RDNs)-index-1))
		if index < len(baseDN.RDNs)-1 {
			table = append(table, fmt.Sprintf("ldap_tree t%d, ldap_entry e%d", index, index))
		} else {
			table = append(table, fmt.Sprintf("ldap_entry e%d", index))
		}
		where = append(where, fmt.Sprintf("e%d.rdn_norm = :rdn_norm%d", index, index))
		if index == 0 {
			where2 = append(where2, fmt.Sprintf("t%d.parent_id is NULL AND t%d.id = e%d.id", index, index, index))
		} else if index < len(baseDN.RDNs)-1 {
			where2 = append(where2, fmt.Sprintf("t%d.parent_id = t%d.id AND t%d.id = e%d.id", index, index-1, index, index))
		} else {
			where2 = append(where2, fmt.Sprintf("e%d.parent_id = t%d.id", index, index-1))
		}
	}

	sql := fmt.Sprintf(`
	SELECT
	  %s as dn_orig,
	  e%d.id, t%d.path as parent_path,
	  (CASE WHEN ex.id IS NOT NULL THEN 1 ELSE 0 END) as has_sub
	FROM
	  %s
	  LEFT JOIN ldap_tree ex ON e%d.id = ex.id
	WHERE
	  %s
	  AND
	  %s
	`,
		strings.Join(proj, " || ',' || "),
		len(baseDN.RDNs)-1,
		len(baseDN.RDNs)-2,
		strings.Join(table, ", "),
		len(baseDN.RDNs)-1,
		strings.Join(where, " AND "),
		strings.Join(where2, " AND "))

	if opt.Lock {
		sql += " for UPDATE"
	}

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

func (r *Repository) FindDNByDN(tx *sqlx.Tx, dn *DN) (*FetchedDN, error) {
	stmt, params, err := r.PrepareFindPathByDN(dn, &FindOption{Lock: false})
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

	if scope == 2 { // sub
		rows, err = namedStmt(tx, findContainerByPathStmt).Queryx(map[string]interface{}{
			"path": dn.ParentPath + ".*{1,}",
		})
	} else if scope == 3 { // children
		rows, err = namedStmt(tx, findContainerByPathStmt).Queryx(map[string]interface{}{
			"path": dn.ParentPath + ".*{2,}",
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

func collectAllNodeOrig(tx *sqlx.Tx) (map[int64]string, error) {
	dc, err := getDCDNOrig(tx)
	if err != nil {
		return nil, err
	}
	nodes, err := collectNodeOrigByParentID(tx, dc.ID)
	if err != nil {
		return nil, err
	}

	cache := make(map[int64]string, len(nodes)+1)
	cache[dc.ID] = dc.DNOrig

	for _, n := range nodes {
		cache[n.ID] = n.DNOrig
	}

	return cache, nil
}

func collectNodeOrigByParentID(tx *sqlx.Tx, parentID int64) ([]*FetchedDNOrig, error) {
	if parentID == ROOT_ID {
		return nil, xerrors.Errorf("Invalid parentID: %d", parentID)
	}
	var rows *sqlx.Rows
	var err error
	if tx != nil {
		rows, err = tx.NamedStmt(collectNodeOrigByParentIDStmt).Queryx(map[string]interface{}{
			"parent_id": parentID,
		})
	} else {
		rows, err = collectNodeOrigByParentIDStmt.Queryx(map[string]interface{}{
			"parent_id": parentID,
		})
	}
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch child ID by parentID: %s, err: %w", parentID, err)
	}
	defer rows.Close()

	list := []*FetchedDNOrig{}
	for rows.Next() {
		child := FetchedDNOrig{}
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

func (r *Repository) FindByDNWithLock(tx *sqlx.Tx, dn *DN) (*ModifyEntry, error) {
	// TODO optimize collecting all container DN orig
	dnOrigCache, err := collectAllNodeOrig(tx)
	if err != nil {
		return nil, err
	}

	entry, err := r.FindByDN(tx, dn, &FindOption{Lock: true, FetchAttrs: true})
	if err != nil {
		return nil, err
	}
	return mapper.FetchedDBEntryToModifyEntry(entry, dnOrigCache)
}

func (r *Repository) FindCredByDN(dn *DN) ([]string, error) {
	q, params := r.CreateFindByDNQuery(dn, &FindOption{Lock: false, FetchCred: true})

	key := "DEPTH:" + strconv.Itoa(len(dn.RDNs))

	dest := struct {
		ID     int64          `db:"id"`
		DNOrig string         `db:"dn_orig"`
		Cred   types.JSONText `db:"cred"`
	}{}

	var stmt *sqlx.NamedStmt
	var ok bool

	if stmt, ok = findCredByDNStmtCache.Get(key); !ok {
		var err error
		stmt, err = r.db.PrepareNamed(q)
		if err != nil {
			return nil, xerrors.Errorf("Failed to prepare name query. query: %s, params: %v, dn: %s, err: %w", q, params, dn.DNOrigStr(), err)
		}
		findCredByDNStmtCache.Put(key, stmt)
	}

	err := stmt.Get(&dest, params)
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
		parentFilter = "e.parent_id IN (" + in + ")"
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
