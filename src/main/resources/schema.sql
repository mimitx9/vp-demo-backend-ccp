-- H2 schema creation script
-- This will run automatically when the application starts

-- Users table
CREATE TABLE IF NOT EXISTS users (
                                     id BIGINT AUTO_INCREMENT PRIMARY KEY,
                                     username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    ciam_id VARCHAR(255) UNIQUE,
    last_login TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
    );

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
                                        id BIGINT AUTO_INCREMENT PRIMARY KEY,
                                        session_id VARCHAR(255) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL,
    access_token VARCHAR(4000),
    refresh_token VARCHAR(4000),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL,
    last_accessed_at TIMESTAMP,
    ip_address VARCHAR(50),
    user_agent VARCHAR(500),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(id)
    );

-- Index for performance
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_is_active ON sessions(is_active);