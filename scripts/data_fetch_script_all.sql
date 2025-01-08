SELECT 
    QR_Detail.QR_Detail_ID,
    'Generic' AS QR_Type,
    QR_Generic.QR_Generic_ID AS QR_Type_ID,
    QR_Generic.Content AS Details,
    QR_Detail.Created_At
FROM 
    QR_Detail
JOIN 
    QR_Generic 
ON 
    QR_Detail.QR_Type = 'Generic' AND QR_Detail.QR_Type_ID = QR_Generic.QR_Generic_ID

UNION ALL

SELECT 
    QR_Detail.QR_Detail_ID,
    'vCard' AS QR_Type,
    QR_vCard.QR_vCard_ID AS QR_Type_ID,
    CONCAT('Name: ', QR_vCard.Full_Name, ', Org: ', QR_vCard.Org, ', Email: ', QR_vCard.Email, ', Phone: ', QR_vCard.Phone) AS Details,
    QR_Detail.Created_At
FROM 
    QR_Detail
JOIN 
    QR_vCard 
ON 
    QR_Detail.QR_Type = 'vCard' AND QR_Detail.QR_Type_ID = QR_vCard.QR_vCard_ID

UNION ALL

SELECT 
    QR_Detail.QR_Detail_ID,
    'MeCard' AS QR_Type,
    QR_MeCard.QR_MeCard_ID AS QR_Type_ID,
    CONCAT('Name: ', QR_MeCard.Full_Name, ', Phone: ', QR_MeCard.Phone, ', Email: ', QR_MeCard.Email) AS Details,
    QR_Detail.Created_At
FROM 
    QR_Detail
JOIN 
    QR_MeCard 
ON 
    QR_Detail.QR_Type = 'MeCard' AND QR_Detail.QR_Type_ID = QR_MeCard.QR_MeCard_ID

UNION ALL

SELECT 
    QR_Detail.QR_Detail_ID,
    'Email' AS QR_Type,
    QR_Email.QR_Email_ID AS QR_Type_ID,
    CONCAT('Recipient: ', QR_Email.Recipient, ', Subject: ', QR_Email.Subject, ', Body: ', QR_Email.Body) AS Details,
    QR_Detail.Created_At
FROM 
    QR_Detail
JOIN 
    QR_Email 
ON 
    QR_Detail.QR_Type = 'Email' AND QR_Detail.QR_Type_ID = QR_Email.QR_Email_ID

UNION ALL

SELECT 
    QR_Detail.QR_Detail_ID,
    'Geo' AS QR_Type,
    QR_Geo.QR_Geo_ID AS QR_Type_ID,
    CONCAT('Latitude: ', QR_Geo.Latitude, ', Longitude: ', QR_Geo.Longitude) AS Details,
    QR_Detail.Created_At
FROM 
    QR_Detail
JOIN 
    QR_Geo 
ON 
    QR_Detail.QR_Type = 'Geo' AND QR_Detail.QR_Type_ID = QR_Geo.QR_Geo_ID

UNION ALL

SELECT 
    QR_Detail.QR_Detail_ID,
    'WiFi' AS QR_Type,
    QR_WiFi.QR_Wifi_ID AS QR_Type_ID,
    CONCAT('SSID: ', QR_WiFi.SSID, ', Encryption: ', QR_WiFi.Encryption) AS Details,
    QR_Detail.Created_At
FROM 
    QR_Detail
JOIN 
    QR_WiFi 
ON 
    QR_Detail.QR_Type = 'WiFi' AND QR_Detail.QR_Type_ID = QR_WiFi.QR_Wifi_ID;
