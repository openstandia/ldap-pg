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

