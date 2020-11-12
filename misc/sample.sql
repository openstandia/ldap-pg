CREATE EXTENSION pgcrypto;
CREATE EXTENSION ltree;


DROP TABLE IF EXISTS ldap_tree;

CREATE TABLE ldap_tree (
    id BIGSERIAL PRIMARY KEY,
    parent_id BIGINT,
    rdn_norm VARCHAR(255) NOT NULL,
    rdn_orig VARCHAR(255) NOT NULL,
    path ltree
);
CREATE UNIQUE INDEX idx_ldap_tree_parent_id_rdn_norm ON ldap_tree (parent_id, rdn_norm);

DROP TABLE IF EXISTS ldap_member;

CREATE TABLE ldap_member (
    member_id BIGINT NOT NULL,
    attr_name_norm VARCHAR(255) NOT NULL,
    member_of_id BIGINT NOT NULL,
    PRIMARY KEY(member_id, attr_name_norm, member_of_id)
);
CREATE UNIQUE INDEX idx_ldap_member_member_of_id ON ldap_member (member_of_id, attr_name_norm, member_id);

DROP TABLE IF EXISTS ldap_entry;

CREATE TABLE ldap_entry (
    id BIGSERIAL PRIMARY KEY,
    parent_id BIGINT,
    rdn_norm VARCHAR(255) NOT NULL,
    rdn_orig VARCHAR(255) NOT NULL,
    uuid VARCHAR(36) NOT NULL,
    created TIMESTAMP WITH TIME ZONE NOT NULL,
    updated TIMESTAMP WITH TIME ZONE NOT NULL,
    attrs_norm JSONB NOT NULL,
    attrs_orig JSONB NOT NULL
);

-- Can't define this reference since it's created when the parent has a child.
-- ALTER TABLE ldap_entry ADD CONSTRAINT SET FOREIGN KEY (parent_id) REFERENCES ldap_tree(id);

-- basic index
CREATE UNIQUE INDEX idx_ldap_entry_rdn_norm ON ldap_entry (parent_id, rdn_norm);
CREATE UNIQUE INDEX idx_ldap_entry_uuid ON ldap_entry (uuid);
CREATE INDEX idx_ldap_entry_created ON ldap_entry (created);
CREATE INDEX idx_ldap_entry_updated ON ldap_entry (updated);

-- single/mutiple value
CREATE INDEX idx_ldap_entry_attrs_ou ON ldap_entry USING gin ((attrs_norm->'ou') jsonb_path_ops);
CREATE INDEX idx_ldap_entry_attrs_dc ON ldap_entry USING gin ((attrs_norm->'dc') jsonb_path_ops);
CREATE INDEX idx_ldap_entry_attrs_cn ON ldap_entry USING gin ((attrs_norm->'cn') jsonb_path_ops);
CREATE INDEX idx_ldap_entry_attrs_uid ON ldap_entry USING gin ((attrs_norm->'uid') jsonb_path_ops);
CREATE INDEX idx_ldap_entry_attrs_mail ON ldap_entry USING gin ((attrs_norm->'mail') jsonb_path_ops);
CREATE INDEX idx_ldap_entry_attrs_object_class ON ldap_entry USING gin ((attrs_norm->'objectClass') jsonb_path_ops);
CREATE INDEX idx_ldap_entry_attrs_member ON ldap_entry USING gin ((attrs_norm->'member') jsonb_path_ops);
CREATE INDEX idx_ldap_entry_attrs_memberOf ON ldap_entry USING gin ((attrs_norm->'memberOf') jsonb_path_ops);

-- exists index
CREATE INDEX idx_ldap_entry_attrs_objectclass_exists ON ldap_entry ((attrs_norm ? 'objectclass'));
CREATE INDEX idx_ldap_entry_attrs_cn_exists ON ldap_entry ((attrs_norm ? 'cn'));
CREATE INDEX idx_ldap_entry_attrs_uid_exists ON ldap_entry ((attrs_norm ? 'uid'));
CREATE INDEX idx_ldap_entry_attrs_mail_exists ON ldap_entry ((attrs_norm ? 'mail'));

insert into ldap_entry values
   (0, NULL, 'dc=com', 'dc=com', gen_random_uuid(), NOW(), NOW(), '{"dc":["com"],"objectclass":["top","dcObject","organization"]}', '{"dc":["com"],"objectClass":["top","dcObject","organization"]}'),
   (1, 0, 'dc=example', 'dc=Example', gen_random_uuid(), NOW(), NOW(), '{"dc":["example"],"objectclass":["top","dcObject","organization"]}', '{"dc":["Example"],"objectClass":["top","dcObject","organization"]}'),
   (2, 1, 'ou=users', 'ou=Users', gen_random_uuid(), NOW(), NOW(), '{"ou":["Users"],"objectclass":["organizationalunit"]}', '{"ou":["People"],"objectClass":["organizationalUnit"]}'),
   (3, 1, 'ou=groups','ou=Groups', gen_random_uuid(), NOW(), NOW(), '{"ou":["Groups"],"objectclass":["organizationalunit"]}', '{"ou":["Groups"],"objectClass":["organizationalUnit"]}'),
   (4, 2, 'uid=u000001','uid=u000001', gen_random_uuid(), NOW(), NOW(), '{"uid":["u000001"],"sn":["user000001"],"objectclass":["inetorgperson"]}', '{"uid":["u000001"],"sn":["user000001"],"objectClass":["inetOrgPerson"]}'),
   (5, 3, 'cn=g000001','cn=g000001', gen_random_uuid(), NOW(), NOW(), '{"cn":["g000001"],"objectclass":["groupofuniquenames"]}', '{"cn":["g000001"],"objectclass":["groupOfUniqueNames"]}'),
   (6, 5, 'cn=g000002','cn=g000002', gen_random_uuid(), NOW(), NOW(), '{"cn":["g000002"],"objectclass":["groupofuniquenames"]}', '{"cn":["g000002"],"objectClass":["groupOfUniqueNames"]}'),
   (7, NULL, 'dc=net','dc=net', gen_random_uuid(), NOW(), NOW(), '{"dc":["net"],"objectclass":["top","dcObject","organization"]}', '{"dc":["net"],"objectClass":["top","dcObject","organization"]}');

SELECT setval('ldap_entry_id_seq', max(id)) FROM ldap_entry;

insert into ldap_tree values
   (0, NULL, 'dc=com', 'dc=com', '0'),
   (1, 0, 'dc=example', 'dc=Example', '0.1'),
   (2, 1, 'ou=users', 'ou=Users', '0.1.2'),
   (3, 1, 'ou=groups','ou=Groups', '0.1.3'),
   (5, 3, 'cn=g000001','cn=g000001', '0.1.3.5'),
   (6, 5, 'cn=g000002','cn=g000002', '0.1.3.5.6');

SELECT setval('ldap_tree_id_seq', max(id)) FROM ldap_tree;