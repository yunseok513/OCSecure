-- OCS-LITE step 2 (run as SFC_OWNER)
--
-- Key table. Only SFC_OWNER owns it and nobody else is granted access.
-- The root key is never stored in clear: it is wrapped with a key derived from
-- the seal kept in package LITE_SEAL (see 21_seal.sql).

CREATE TABLE LITE_KEY (
  key_id        NUMBER(5)     NOT NULL,
  key_state     VARCHAR2(8)   NOT NULL,
  root_wrapped  RAW(256)      NOT NULL,
  created_at    TIMESTAMP(6)  DEFAULT SYSTIMESTAMP NOT NULL,
  retired_at    TIMESTAMP(6),
  CONSTRAINT pk_lite_key       PRIMARY KEY (key_id),
  CONSTRAINT ck_lite_key_state CHECK (key_state IN ('ACTIVE', 'OLD')),
  CONSTRAINT ck_lite_key_id    CHECK (key_id BETWEEN 1 AND 65535)
);

-- At most one ACTIVE key. Two active keys would make the encryption key ambiguous.
CREATE UNIQUE INDEX ux_lite_key_active
  ON LITE_KEY (CASE WHEN key_state = 'ACTIVE' THEN 1 END);

CREATE SEQUENCE LITE_KEY_SEQ START WITH 1 INCREMENT BY 1 MAXVALUE 65535 NOCYCLE NOCACHE;

COMMENT ON TABLE LITE_KEY IS
  'OCS-LITE root keys. ACTIVE encrypts new data, OLD is kept only to decrypt older data.';
