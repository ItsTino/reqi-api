CREATE TABLE IF NOT EXISTS log_entries (
    id CHAR(36) NOT NULL PRIMARY KEY,
    logger_id CHAR(36) NOT NULL,
    method VARCHAR(10) NOT NULL,
    path VARCHAR(255),
    headers TEXT,
    query TEXT,
    body MEDIUMTEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (logger_id) REFERENCES loggers(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;