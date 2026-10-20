-- OCS-LITE step 2 (run as SFC_OWNER)
--
-- Key table. Only SFC_OWNER owns it and nobody else is granted access.
-- The root key is never stored in clear: it is wrapped with a key derived from
-- the seal kept in package SFC_SEAL (see 21_seal.sql).

CREATE TABLE SFC_KEY (
  key_id        NUMBER(5)     NOT NULL,
  key_state     VARCHAR2(8)   NOT NULL,
  root_wrapped  RAW(256)      NOT NULL,
  created_at    TIMESTAMP(6)  DEFAULT SYSTIMESTAMP NOT NULL,
  retired_at    TIMESTAMP(6),
  CONSTRAINT pk_sfc_key       PRIMARY KEY (key_id),
  CONSTRAINT ck_sfc_key_state CHECK (key_state IN ('ACTIVE', 'OLD')),
  CONSTRAINT ck_sfc_key_id    CHECK (key_id BETWEEN 1 AND 65535)
);

-- At most one ACTIVE key. Two active keys would make the encryption key ambiguous.
CREATE UNIQUE INDEX ux_sfc_key_active
  ON SFC_KEY (CASE WHEN key_state = 'ACTIVE' THEN 1 END);

CREATE SEQUENCE SFC_KEY_SEQ START WITH 1 INCREMENT BY 1 MAXVALUE 65535 NOCYCLE NOCACHE;

COMMENT ON TABLE SFC_KEY IS
  'OCS-LITE root keys. ACTIVE encrypts new data, OLD is kept only to decrypt older data.';

COMMENT ON COLUMN SFC_KEY.key_id IS
  'Key number. It is written into every ciphertext (characters 5 to 8 of the hex value).';
COMMENT ON COLUMN SFC_KEY.key_state IS
  'ACTIVE = used for new data. OLD = kept only to decrypt older data. Never delete OLD rows.';
COMMENT ON COLUMN SFC_KEY.root_wrapped IS
  'The root key, stored protected. Do not copy this table to another database without SFC_SEAL.';
