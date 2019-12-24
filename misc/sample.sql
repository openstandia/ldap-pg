CREATE EXTENSION pgcrypto;
CREATE EXTENSION pg_trgm;


DROP TABLE IF EXISTS ldap_tree;

CREATE TABLE ldap_tree (
    id BIGSERIAL PRIMARY KEY,
    parent_id BIGINT,
    rdn_norm VARCHAR(255) NOT NULL,
    rdn_orig VARCHAR(255) NOT NULL,
    parent_dn_norm VARCHAR(255), -- cache
    parent_dn_orig VARCHAR(255)  -- cache
);
CREATE UNIQUE INDEX idx_ldap_tree_parent_id_rdn_norm ON ldap_tree (parent_id, rdn_norm);
CREATE UNIQUE INDEX idx_ldap_tree_parent_dn_norm_rdn_norm ON ldap_tree (parent_dn_norm, rdn_norm);

DROP TABLE IF EXISTS ldap_member;

CREATE TABLE ldap_member (
    member_id BIGINT NOT NULL,
    rdn_norm VARCHAR(255) NOT NULL,
    member_of_id BIGINT NOT NULL,
    PRIMARY KEY(member_id, rdn_norm, member_of_id)
);
CREATE UNIQUE INDEX idx_ldap_member_member_of_id ON ldap_member (member_of_id, rdn_norm, member_id);

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

-- ALTER TABLE ldap_entry ADD CONSTRAINT SET FOREIGN KEY (parent_id) REFERENCES ldap_tree(id);

-- basic index
CREATE UNIQUE INDEX idx_ldap_entry_rdn_norm ON ldap_entry (parent_id, rdn_norm);
CREATE UNIQUE INDEX idx_ldap_entry_uuid ON ldap_entry (uuid);
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

-- insert into ldap_entry values
--     (0, '/', NULL, 'ou=people', gen_random_uuid(), NOW(), NOW(), '{"ou":"people"}', '{"ou":"people"}'),
--     (1, '/', NULL, 'ou=group', gen_random_uuid(), NOW(), NOW(), '{"ou":"group"}', '{"ou":"group"}');

-- SELECT setval('ldap_entry_id_seq', max(id)) FROM ldap_entry;