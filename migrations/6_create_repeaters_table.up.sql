CREATE TABLE IF NOT EXISTS repeaters (
    id CHAR(36) NOT NULL PRIMARY KEY,
    logger_id CHAR(36) NOT NULL,
    forward_url VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    preserve_host BOOLEAN DEFAULT FALSE,
    timeout INT DEFAULT 30,
    retry_count INT DEFAULT 3,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (logger_id) REFERENCES loggers(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;