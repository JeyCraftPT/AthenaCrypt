USE ProjetoFinal;

-- Drop tables if they exist
DROP TABLE IF EXISTS handShake;
DROP TABLE IF EXISTS offline_messages;
DROP TABLE IF EXISTS oneTimeKeys;
DROP TABLE IF EXISTS message;
DROP TABLE IF EXISTS sessionKeys;
DROP TABLE IF EXISTS client;


-- Create client table
CREATE TABLE client (
    client_id                   INT AUTO_INCREMENT PRIMARY KEY,
    client_name                 VARCHAR(255)  NOT NULL,
    client_pass                 VARBINARY(80) NOT NULL,
    client_IPKey                BLOB          NOT NULL,
    client_x25519IdentityKey    BLOB          NOT NULL,
    client_SPKey                BLOB          NOT NULL,
    client_signature            BLOB          NOT NULL,
    client_online               TINYINT(1)    NOT NULL,
    UNIQUE (client_IPKey)
);


-- Create message table
CREATE TABLE sessionKeys (
    chat_id INT AUTO_INCREMENT PRIMARY KEY,
    sender VARCHAR(255) NOT NULL,
    receiver VARCHAR(255) NOT NULL,
    encrypted_session_key blob NOT NULL
);

-- ola
-- Create sessionKeys table
CREATE TABLE oneTimeKeys (
    key_id INT AUTO_INCREMENT PRIMARY KEY,
    client_id INT,
    client_one_time_key blob,
    FOREIGN KEY (client_id) REFERENCES client(client_id) ON DELETE CASCADE
);

-- Create oneTimeKeys table
CREATE TABLE handShake (
                           id INT AUTO_INCREMENT PRIMARY KEY,
                           initiator varchar(255),
                           receiver varchar(255),
                           key_id INT,
                           ephemeral_Key blob,
                           Foreign Key (key_id) REFERENCES oneTimeKeys(key_id) ON DELETE CASCADE
);

CREATE TABLE offline_messages (
                                  id INT AUTO_INCREMENT PRIMARY KEY,
                                  sender VARCHAR(255) NOT NULL,
                                  receiver VARCHAR(255) NOT NULL,
                                  packet BLOB       NOT NULL,
                                  iv BLOB           NOT NULL,
                                  header_pub BLOB   NOT NULL,
                                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE message (
    message_id INT AUTO_INCREMENT PRIMARY KEY,
    chat_id INT,
    client_id INT,
    message_cont VARCHAR(500) NOT NULL,
    count int NOT NULL,
    time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES client(client_id) ON DELETE CASCADE,
    FOREIGN KEY (chat_id) REFERENCES sessionKeys(chat_id) ON DELETE CASCADE
);

-- Existing index on message(client_id)
CREATE INDEX idx_client_id ON message(client_id);

-- New index for the message → sessionKeys FK
CREATE INDEX idx_message_chat_id ON message(chat_id);

-- New index for the oneTimeKeys → client FK
CREATE INDEX idx_oneTimeKeys_client_id ON oneTimeKeys(client_id);
