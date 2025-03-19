CREATE TABLE users(
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(15) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    password_changed_on TIMESTAMP NULL, 
    secondary_verification BOOLEAN NOT NULL DEFAULT FALSE,
    secret_key VARCHAR(255) NULL,
    UNIQUE(username,email,secret_key)
);

// This table will be used when the session storage is switched from filesystem to mysql database.
    
CREATE TABLE user_sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    user_id INT NOT NULL,
    session_data TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL
);
