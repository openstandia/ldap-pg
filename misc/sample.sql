CREATE EXTENSION pgcrypto;
CREATE EXTENSION ltree;


DROP TABLE IF EXISTS ldap_tree;

CREATE TABLE ldap_tree (
    id BIGINT PRIMARY KEY,
    path ltree NOT NULL
);
-- CREATE UNIQUE INDEX idx_ldap_tree_parent_id_rdn_norm ON ldap_tree (parent_id, rdn_norm);
CREATE INDEX idx_ldap_tree_path ON ldap_tree USING GIST (path);


DROP TABLE IF EXISTS ldap_entry;

CREATE TABLE ldap_entry (
    id BIGSERIAL PRIMARY KEY,
    parent_id BIGINT,
    rdn_norm VARCHAR(255) NOT NULL,
    rdn_orig VARCHAR(255) NOT NULL,
    attrs_norm JSONB NOT NULL,
    attrs_orig JSONB NOT NULL
);

-- Can't define this reference since it's created when the parent has a child.
-- ALTER TABLE ldap_entry ADD CONSTRAINT SET FOREIGN KEY (parent_id) REFERENCES ldap_tree(id);

-- basic index
CREATE UNIQUE INDEX idx_ldap_entry_rdn_norm ON ldap_entry (parent_id, rdn_norm);

-- all json index
CREATE INDEX idx_ldap_entry_attrs ON ldap_entry USING gin (attrs_norm jsonb_path_ops);

-- single/mutiple value
-- CREATE INDEX idx_ldap_entry_attrs_ou ON ldap_entry USING gin ((attrs_norm->'ou') jsonb_path_ops);
-- CREATE INDEX idx_ldap_entry_attrs_dc ON ldap_entry USING gin ((attrs_norm->'dc') jsonb_path_ops);
-- CREATE INDEX idx_ldap_entry_attrs_cn ON ldap_entry USING gin ((attrs_norm->'cn') jsonb_path_ops);
-- CREATE INDEX idx_ldap_entry_attrs_uid ON ldap_entry USING gin ((attrs_norm->'uid') jsonb_path_ops);
-- CREATE INDEX idx_ldap_entry_attrs_mail ON ldap_entry USING gin ((attrs_norm->'mail') jsonb_path_ops);
-- CREATE INDEX idx_ldap_entry_attrs_object_class ON ldap_entry USING gin ((attrs_norm->'objectClass') jsonb_path_ops);
-- CREATE INDEX idx_ldap_entry_attrs_member ON ldap_entry USING gin ((attrs_norm->'member') jsonb_path_ops);
-- CREATE INDEX idx_ldap_entry_attrs_memberOf ON ldap_entry USING gin ((attrs_norm->'memberOf') jsonb_path_ops);

-- exists index
-- CREATE INDEX idx_ldap_entry_attrs_objectclass_exists ON ldap_entry ((attrs_norm ? 'objectclass'));
-- CREATE INDEX idx_ldap_entry_attrs_cn_exists ON ldap_entry ((attrs_norm ? 'cn'));
-- CREATE INDEX idx_ldap_entry_attrs_uid_exists ON ldap_entry ((attrs_norm ? 'uid'));
-- CREATE INDEX idx_ldap_entry_attrs_mail_exists ON ldap_entry ((attrs_norm ? 'mail'));


-- insert into ldap_entry values
--    (0, NULL, 'dc=com', 'dc=com', '{"dc":["com"],"objectClass":["top","dcObject","organization"]}', '{"dc":["com"],"objectClass":["top","dcObject","organization"]}'),
--    (1, 0, 'dc=example', 'dc=Example', '{"dc":["example"],"objectClass":["top","dcObject","organization"]}', '{"dc":["Example"],"objectClass":["top","dcObject","organization"]}'),
--    (2, 1, 'ou=users', 'ou=Users', '{"ou":["Users"],"objectClass":["organizationalunit"]}', '{"ou":["People"],"objectClass":["organizationalUnit"]}'),
--    (3, 1, 'ou=groups','ou=Groups', '{"ou":["Groups"],"objectClass":["organizationalunit"]}', '{"ou":["Groups"],"objectClass":["organizationalUnit"]}'),
--    (4, 2, 'uid=u000001','uid=u000001', '{"uid":["u000001"],"sn":["user000001"],"objectClass":["inetorgperson"]}', '{"uid":["u000001"],"sn":["user000001"],"objectClass":["inetOrgPerson"]}'),
--    (5, 3, 'cn=g000001','cn=g000001', '{"cn":["g000001"],"objectClass":["groupofuniquenames"],"member":[8]}', '{"cn":["g000001"],"objectClass":["groupOfUniqueNames"]}'),
--    (6, 5, 'cn=g000002','cn=g000002', '{"cn":["g000002"],"objectClass":["groupofuniquenames"],"member":[8,9]}', '{"cn":["g000002"],"objectClass":["groupOfUniqueNames"],"member":[8,9]}'),
--    (7, 3, 'cn=g000003','cn=g000003', '{"cn":["g000003"],"objectClass":["groupofuniquenames"],"member":[9]}', '{"cn":["g000003"],"objectClass":["groupOfUniqueNames"]}'),
--    (8, 2, 'uid=u000002','uid=u000002', '{"uid":["u000002"],"sn":["user000002"],"objectClass":["inetorgperson"],"memberOf":["5","6"]}', '{"uid":["u000002"],"sn":["user000002"],"objectClass":["inetOrgPerson"]}'),
--    (9, 2, 'uid=u000003','uid=u000003', '{"uid":["u000003"],"sn":["user000003"],"objectClass":["inetorgperson"],"memberOf":["6","7"]}', '{"uid":["u000003"],"sn":["user000003"],"objectClass":["inetOrgPerson"]}'),
--    (10, NULL, 'dc=net','dc=net', '{"dc":["net"],"objectClass":["top","dcObject","organization"]}', '{"dc":["net"],"objectClass":["top","dcObject","organization"]}');

-- SELECT setval('ldap_entry_id_seq', max(id)) FROM ldap_entry;

-- insert into ldap_tree values
--    (0, '0'),
--    (1, '0.1'),
--    (2, '0.1.2'),
--    (3, '0.1.3'),
--    (5, '0.1.3.5');

-- SELECT setval('ldap_tree_id_seq', max(id)) FROM ldap_tree;