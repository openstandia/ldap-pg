CREATE EXTENSION pgcrypto;
CREATE EXTENSION pg_trgm;

DROP TABLE ldap_entry;

CREATE TABLE ldap_entry (
    id BIGSERIAL PRIMARY KEY,
    path VARCHAR(255) NOT NULL,
    dn_norm VARCHAR(255) NOT NULL,
    uuid VARCHAR(36) NOT NULL,
    created TIMESTAMP WITH TIME ZONE NOT NULL,
    updated TIMESTAMP WITH TIME ZONE NOT NULL,
    attrs_norm JSONB NOT NULL,
    attrs_orig JSONB NOT NULL
);

-- basic index
CREATE INDEX idx_ldap_entry_path ON ldap_entry (path);
CREATE UNIQUE INDEX idx_ldap_entry_uuid ON ldap_entry (uuid);
CREATE UNIQUE INDEX idx_ldap_entry_dn_norm ON ldap_entry (dn_norm);
CREATE INDEX idx_ldap_entry_created ON ldap_entry (created);
CREATE INDEX idx_ldap_entry_updated ON ldap_entry (updated);

-- single value
CREATE INDEX idx_ldap_entry_attrs_ou ON ldap_entry USING btree ((attrs_norm->>'ou') text_pattern_ops);
CREATE INDEX idx_ldap_entry_attrs_dc ON ldap_entry USING btree ((attrs_norm->>'dc') text_pattern_ops);

-- multiple value
CREATE INDEX idx_ldap_entry_attrs_cn ON ldap_entry USING gin ((attrs_norm->'cn') jsonb_path_ops);
CREATE INDEX idx_ldap_entry_attrs_uid ON ldap_entry USING gin ((attrs_norm->'uid') jsonb_path_ops);
CREATE INDEX idx_ldap_entry_attrs_mail ON ldap_entry USING gin ((attrs_norm->'mail') jsonb_path_ops);
CREATE INDEX idx_ldap_entry_attrs_object_class ON ldap_entry USING gin ((attrs_norm->'objectClass') jsonb_path_ops);
CREATE INDEX idx_ldap_entry_attrs_member ON ldap_entry USING gin ((attrs_norm->'member') jsonb_path_ops);
CREATE INDEX idx_ldap_entry_attrs_memberOf ON ldap_entry USING gin ((attrs_norm->'memberOf') jsonb_path_ops);


-- sample data
-- INSERT INTO ldap_entry (uuid, dn, path, created, updated, attrs) VALUES (gen_random_uuid(), 'dc=example,dc=com', 'dc=com/', now(), now(), '{
--   "dc": "example",
--   "objectClass": ["dcObject", "organization"],
--   "o": "example"
-- }');
--
-- INSERT INTO ldap_entry (uuid, dn, path, created, updated, attrs) VALUES (gen_random_uuid(), 'ou=Users,dc=example,dc=com', 'dc=com/dc=example/', now(), now(), '{
--   "ou": "Users",
--   "objectClass": ["organizationalUnit"]
-- }');
--
-- INSERT INTO ldap_entry (uuid, dn, path, created, updated, attrs) VALUES (gen_random_uuid(), 'ou=Groups,dc=example,dc=com', 'dc=com/dc=example/', now(), now(), '{
--   "ou": "Groups",
--   "objectClass": ["organizationalUnit"]
-- }');
--
-- INSERT INTO ldap_entry (uuid, dn, path, created, updated, attrs) VALUES (gen_random_uuid(), 'uid=user1,ou=Users,dc=example,dc=com', 'dc=com/dc=example/ou=users/', now(), now(), '{
--   "objectClass": ["inetOrgPerson"],
--   "uid": "user1",
--   "cn": "user1",
--   "mail": "user1@example.com",
--   "sn": "user1",
--   "givenName": "user1",
--   "userPassword": "password"
-- }');
--
-- INSERT INTO ldap_entry (uuid, dn, path, created, updated, attrs) VALUES (gen_random_uuid(), 'uid=user2,ou=Users,dc=example,dc=com', 'dc=com/dc=example/ou=users/', now(), now(), '{
--   "objectClass": ["inetOrgPerson"],
--   "uid": "user2",
--   "cn": "user2",
--   "mail": "user2@example.com",
--   "sn": "user2",
--   "givenName": "user2",
--   "userPassword": "password"
-- }');
--
-- INSERT INTO ldap_entry (uuid, dn, path, created, updated, attrs) VALUES (gen_random_uuid(), 'cn=group1,ou=Groups,dc=example,dc=com', 'dc=com/dc=example/ou=groups/', now(), now(), '{
--   "cn": "group1",
--   "objectClass": ["groupOfNames"],
--   "displayName": "Group1",
--   "description": "This is group1.",
--   "member" : [
--     "cn=group2,ou=Groups,dc=example,dc=com"
--   ]
-- }');
--
-- INSERT INTO ldap_entry (uuid, dn, path, created, updated, attrs) VALUES (gen_random_uuid(), 'cn=group2,ou=Groups,dc=example,dc=com', 'dc=com/dc=example/ou=groups/', now(), now(), '{
--   "cn": "group2",
--   "objectClass": ["groupOfNames"],
--   "displayName": "Group2",
--   "description": "This is group2.",
--   "member" : [
--     "cn=group3,ou=Groups,dc=example,dc=com"
--   ]
-- }');
--
-- INSERT INTO ldap_entry (uuid, dn, path, created, updated, attrs) VALUES (gen_random_uuid(), 'cn=group3,ou=Groups,dc=example,dc=com', 'dc=com/dc=example/ou=groups/', now(), now(), '{
--   "cn": "group3",
--   "objectClass": ["groupOfNames"],
--   "displayName": "Group3",
--   "description": "This is group3.",
--   "member" : [
--     "uid=user1,ou=Users,dc=example,dc=com",
--     "uid=user2,ou=Users,dc=example,dc=com"
--   ]
-- }');
--
