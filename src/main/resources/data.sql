-- Initial demo data for users table
INSERT INTO users (username, email, first_name, last_name, ciam_id, last_login, created_at, updated_at)
VALUES
    ('testuser', 'test@example.com', 'Test', 'User', 'ciam_123456', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP()),
    ('johndoe', 'john.doe@example.com', 'John', 'Doe', 'ciam_654321', CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP());

-- Don't add session data as these would be created dynamically during runtime