CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(100) NOT NULL UNIQUE,
    role VARCHAR(50) NOT NULL
);

CREATE TABLE resources (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    owner_id INT,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

CREATE TABLE audit_log (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    action VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

INSERT INTO users(username, role) VALUES
('alice', 'user'),
('bob', 'admin');

INSERT INTO resources(name, owner_id) VALUES
('Document A', 1),
('Document B', 2);

INSERT INTO audit_log(user_id, action) VALUES
(1, 'GET /users'),
(2, 'GET /admin/users');