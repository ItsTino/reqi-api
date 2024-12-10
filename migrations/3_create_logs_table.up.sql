CREATE TABLE IF NOT EXISTS logs (
    id CHAR(36) NOT NULL PRIMARY KEY,
    api_key_id CHAR(36) NOT NULL,
    uuid VARCHAR(36) NOT NULL,
    body TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;