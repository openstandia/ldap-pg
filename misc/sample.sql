CREATE EXTENSION pgcrypto;
CREATE EXTENSION pg_trgm;

CREATE OR REPLACE FUNCTION f_jsonb_array_lower(_j jsonb)
  RETURNS jsonb LANGUAGE sql IMMUTABLE AS
'SELECT jsonb_agg(lower(elem)) FROM jsonb_array_elements_text(_j) elem';

CREATE TABLE ldap_entry (
    id BIGSERIAL PRIMARY KEY,
    uuid VARCHAR(36) NOT NULL,
    dn VARCHAR(100) NOT NULL,
    path VARCHAR(100) NOT NULL,
    created TIMESTAMP WITH TIME ZONE NOT NULL,
    updated TIMESTAMP WITH TIME ZONE NOT NULL,
    attrs JSONB NOT NULL
);

-- basic index
CREATE UNIQUE INDEX idx_ldap_entry_uuid ON ldap_entry (uuid);
CREATE UNIQUE INDEX idx_ldap_entry_dn ON ldap_entry USING btree (LOWER(dn));
CREATE INDEX idx_ldap_entry_path ON ldap_entry (path);
CREATE INDEX idx_ldap_entry_created ON ldap_entry (created);
CREATE INDEX idx_ldap_entry_updated ON ldap_entry (updated);

-- single value, case-insensitive only
CREATE INDEX idx_ldap_entry_attrs_cn ON ldap_entry USING btree (LOWER(attrs->>'cn') text_pattern_ops);
CREATE INDEX idx_ldap_entry_attrs_uid ON ldap_entry USING btree (LOWER(attrs->>'uid') text_pattern_ops);
CREATE INDEX idx_ldap_entry_attrs_mail ON ldap_entry USING btree (LOWER(attrs->>'mail') text_pattern_ops);
CREATE INDEX idx_ldap_entry_attrs_ou ON ldap_entry USING btree (LOWER(attrs->>'ou') text_pattern_ops);
CREATE INDEX idx_ldap_entry_attrs_dc ON ldap_entry USING btree (LOWER(attrs->>'dc') text_pattern_ops);

-- multiple value, case-insensitive only
CREATE INDEX idx_ldap_entry_attrs_object_class ON ldap_entry USING gin (f_jsonb_array_lower(attrs->'objectClass') jsonb_path_ops);
CREATE INDEX idx_ldap_entry_attrs_member ON ldap_entry USING gin (f_jsonb_array_lower(attrs->'member') jsonb_path_ops);
CREATE INDEX idx_ldap_entry_attrs_memberOf ON ldap_entry USING gin (f_jsonb_array_lower(attrs->'memberOf') jsonb_path_ops);


-- sample data
INSERT INTO ldap_entry (uuid, dn, path, created, updated, attrs) VALUES (gen_random_uuid(), 'dc=example,dc=com', 'dc=com/', now(), now(), '{
  "dc": "example",
  "objectClass": ["dcObject", "organization"],
  "o": "example"
}');

INSERT INTO ldap_entry (uuid, dn, path, created, updated, attrs) VALUES (gen_random_uuid(), 'ou=Users,dc=example,dc=com', 'dc=com/dc=example/', now(), now(), '{
  "ou": "Users",
  "objectClass": ["organizationalUnit"]
}');

INSERT INTO ldap_entry (uuid, dn, path, created, updated, attrs) VALUES (gen_random_uuid(), 'ou=Groups,dc=example,dc=com', 'dc=com/dc=example/', now(), now(), '{
  "ou": "Groups",
  "objectClass": ["organizationalUnit"]
}');

INSERT INTO ldap_entry (uuid, dn, path, created, updated, attrs) VALUES (gen_random_uuid(), 'uid=user1,ou=Users,dc=example,dc=com', 'dc=com/dc=example/ou=users/', now(), now(), '{
  "objectClass": ["inetOrgPerson"],
  "uid": "user1",
  "cn": "user1",
  "mail": "user1@example.com",
  "sn": "user1",
  "givenName": "user1",
  "userPassword": "password"
}');

INSERT INTO ldap_entry (uuid, dn, path, created, updated, attrs) VALUES (gen_random_uuid(), 'uid=user2,ou=Users,dc=example,dc=com', 'dc=com/dc=example/ou=users/', now(), now(), '{
  "objectClass": ["inetOrgPerson"],
  "uid": "user2",
  "cn": "user2",
  "mail": "user2@example.com",
  "sn": "user2",
  "givenName": "user2",
  "userPassword": "password"
}');

INSERT INTO ldap_entry (uuid, dn, path, created, updated, attrs) VALUES (gen_random_uuid(), 'cn=group1,ou=Groups,dc=example,dc=com', 'dc=com/dc=example/ou=groups/', now(), now(), '{
  "cn": "group1",
  "objectClass": ["groupOfNames"],
  "displayName": "Group1",
  "description": "This is group1.",
  "member" : [
    "cn=group2,ou=Groups,dc=example,dc=com"
  ]
}');

INSERT INTO ldap_entry (uuid, dn, path, created, updated, attrs) VALUES (gen_random_uuid(), 'cn=group2,ou=Groups,dc=example,dc=com', 'dc=com/dc=example/ou=groups/', now(), now(), '{
  "cn": "group2",
  "objectClass": ["groupOfNames"],
  "displayName": "Group2",
  "description": "This is group2.",
  "member" : [
    "cn=group3,ou=Groups,dc=example,dc=com"
  ]
}');

INSERT INTO ldap_entry (uuid, dn, path, created, updated, attrs) VALUES (gen_random_uuid(), 'cn=group3,ou=Groups,dc=example,dc=com', 'dc=com/dc=example/ou=groups/', now(), now(), '{
  "cn": "group3",
  "objectClass": ["groupOfNames"],
  "displayName": "Group3",
  "description": "This is group3.",
  "member" : [
    "uid=user1,ou=Users,dc=example,dc=com",
    "uid=user2,ou=Users,dc=example,dc=com"
  ]
}');
