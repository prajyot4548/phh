-- Run automatically by app.py / db.init_db() on first start (shown here for reference). Oracle 12c+.
CREATE TABLE vault_files (
  id            NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  original_path VARCHAR2(1000) NOT NULL,
  enc_path      VARCHAR2(1000) NOT NULL,
  pii_types     VARCHAR2(300),
  risk_level    VARCHAR2(10) DEFAULT 'medium',
  size_bytes    NUMBER,
  sha256        VARCHAR2(64),
  status        VARCHAR2(12) DEFAULT 'ENCRYPTED' NOT NULL,
  created_at    TIMESTAMP DEFAULT SYSTIMESTAMP,
  restored_at   TIMESTAMP
);
CREATE TABLE activity_log (
  id         NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  action     VARCHAR2(30) NOT NULL,
  detail     VARCHAR2(1000),
  created_at TIMESTAMP DEFAULT SYSTIMESTAMP
);
CREATE TABLE app_settings (
  key_name VARCHAR2(100) PRIMARY KEY,
  value    VARCHAR2(500)
);
CREATE INDEX idx_vault_status ON vault_files(status);
CREATE INDEX idx_log_created ON activity_log(created_at);
