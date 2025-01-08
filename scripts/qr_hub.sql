CREATE DATABASE IF NOT EXISTS qrhub;
USE qrhub;

CREATE TABLE IF NOT EXISTS QR_Generic (
    QR_Generic_ID INT PRIMARY KEY AUTO_INCREMENT,
    Content VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS QR_vCard (
    QR_vCard_ID INT PRIMARY KEY AUTO_INCREMENT,
    Full_Name VARCHAR(150) NOT NULL,    -- Increased length for names
    Org VARCHAR(100),                   -- Increased length for organization names
    Email VARCHAR(255) UNIQUE,          -- Emails should be unique and support larger lengths
    Phone VARCHAR(15),                  -- Phone numbers as VARCHAR to handle country codes
    Address VARCHAR(255),               -- Extended length for addresses
    Website VARCHAR(255)                -- Extended length for website URLs
);

CREATE TABLE IF NOT EXISTS QR_MeCard (
    QR_MeCard_ID INT PRIMARY KEY AUTO_INCREMENT,
    Full_Name VARCHAR(150) NOT NULL,
    Phone VARCHAR(15),
    Email VARCHAR(255) UNIQUE,
    Website VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS QR_Email (
    QR_Email_ID INT PRIMARY KEY AUTO_INCREMENT,
    Recipient VARCHAR(255) NOT NULL,    -- Increased length for email recipient
    Subject TEXT,                       -- Subject is unlikely to exceed TEXT limits
    Body TEXT                           -- Kept TEXT for larger email content
);

CREATE TABLE IF NOT EXISTS QR_Geo (
    QR_Geo_ID INT PRIMARY KEY AUTO_INCREMENT,
    Latitude DECIMAL(9,6) NOT NULL,     -- Increased precision for geographical coordinates
    Longitude DECIMAL(9,6) NOT NULL
);

CREATE TABLE IF NOT EXISTS QR_WiFi (
    QR_Wifi_ID INT PRIMARY KEY AUTO_INCREMENT,
    SSID VARCHAR(32) NOT NULL,         -- SSID can go up to 32 characters
    Password VARCHAR(64),              -- Extended length for WPA3 and long passwords
    Encryption ENUM('WPA/WPA2', 'WEP', 'None') DEFAULT 'WPA/WPA2' -- Default to WPA/WPA2
);

CREATE TABLE IF NOT EXISTS QR_Detail (
    QR_Detail_ID INT PRIMARY KEY AUTO_INCREMENT,        -- Unique ID for each QR detail
    QR_Type ENUM('Generic', 'vCard', 'MeCard', 'Email', 'Geo', 'WiFi') NOT NULL, -- QR type
    QR_Type_ID INT NOT NULL,                            -- ID referencing the corresponding QR type table
    Created_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP,     -- Timestamp for when the detail was created
    UNIQUE (QR_Type, QR_Type_ID)                        -- Ensures no duplicate QR_Type and QR_Type_ID combination
);*/

DELIMITER $$

CREATE TRIGGER Validate_QR_Detail_Insert
BEFORE INSERT ON QR_Detail
FOR EACH ROW
BEGIN
    -- Validate QR_Type and QR_Type_ID combination for 'Generic'
    IF NEW.QR_Type = 'Generic' THEN
        IF NOT EXISTS (SELECT 1 FROM QR_Generic WHERE QR_Generic_ID = NEW.QR_Type_ID) THEN
            SIGNAL SQLSTATE '45000' 
            SET MESSAGE_TEXT = 'Invalid QR_Type_ID for QR_Generic';
        END IF;
    END IF;

    -- Validate QR_Type and QR_Type_ID combination for 'vCard'
    IF NEW.QR_Type = 'vCard' THEN
        IF NOT EXISTS (SELECT 1 FROM QR_vCard WHERE QR_vCard_ID = NEW.QR_Type_ID) THEN
            SIGNAL SQLSTATE '45000' 
            SET MESSAGE_TEXT = 'Invalid QR_Type_ID for QR_vCard';
        END IF;
    END IF;

    -- Validate QR_Type and QR_Type_ID combination for 'MeCard'
    IF NEW.QR_Type = 'MeCard' THEN
        IF NOT EXISTS (SELECT 1 FROM QR_MeCard WHERE QR_MeCard_ID = NEW.QR_Type_ID) THEN
            SIGNAL SQLSTATE '45000' 
            SET MESSAGE_TEXT = 'Invalid QR_Type_ID for QR_MeCard';
        END IF;
    END IF;

    -- Validate QR_Type and QR_Type_ID combination for 'Email'
    IF NEW.QR_Type = 'Email' THEN
        IF NOT EXISTS (SELECT 1 FROM QR_Email WHERE QR_Email_ID = NEW.QR_Type_ID) THEN
            SIGNAL SQLSTATE '45000' 
            SET MESSAGE_TEXT = 'Invalid QR_Type_ID for QR_Email';
        END IF;
    END IF;

    -- Validate QR_Type and QR_Type_ID combination for 'Geo'
    IF NEW.QR_Type = 'Geo' THEN
        IF NOT EXISTS (SELECT 1 FROM QR_Geo WHERE QR_Geo_ID = NEW.QR_Type_ID) THEN
            SIGNAL SQLSTATE '45000' 
            SET MESSAGE_TEXT = 'Invalid QR_Type_ID for QR_Geo';
        END IF;
    END IF;

    -- Validate QR_Type and QR_Type_ID combination for 'WiFi'
    IF NEW.QR_Type = 'WiFi' THEN
        IF NOT EXISTS (SELECT 1 FROM QR_WiFi WHERE QR_Wifi_ID = NEW.QR_Type_ID) THEN
            SIGNAL SQLSTATE '45000' 
            SET MESSAGE_TEXT = 'Invalid QR_Type_ID for QR_WiFi';
        END IF;
    END IF;
END$$

DELIMITER ;

