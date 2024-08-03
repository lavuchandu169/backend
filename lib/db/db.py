import sqlite3
from datetime import datetime
from lib.utils.actions import generate_alphanumeric_code
from lib.utils.cryptic import hash_string, encrypt_to_fixed_length_string, decrypt_from_fixed_length_string

def connect_db():
    return sqlite3.connect('example.db')

def create_tables():
    conn = connect_db()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        user_id TEXT PRIMARY KEY,
                        password_hash TEXT NOT NULL
                      )''')
    
    # Create files table
    cursor.execute('''CREATE TABLE IF NOT EXISTS files (
                        file_id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        date_created TEXT NOT NULL,
                        file_name TEXT NOT NULL,
                        content BLOB NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users(user_id)
                      )''')
    
    # Create shared_files table
    cursor.execute('''CREATE TABLE IF NOT EXISTS shared_files (
                        id TEXT PRIMARY KEY,
                        file_id TEXT NOT NULL,
                        owner_id TEXT NOT NULL,
                        receiver_id TEXT NOT NULL,
                        permission TEXT NOT NULL,
                        FOREIGN KEY (file_id) REFERENCES files(file_id),
                        FOREIGN KEY (owner_id) REFERENCES users(user_id),
                        FOREIGN KEY (receiver_id) REFERENCES users(user_id)
                      )''')
    
    # Create cookies table
    cursor.execute('''CREATE TABLE IF NOT EXISTS cookies (
                        identifier TEXT NOT NULL,
                        encrypted_data BLOB NOT NULL
                      )''')
    
    conn.commit()
    conn.close()

def register_user(username, password):
    if check_username_exists(username):
        return {"body": {"message": "Username already exists"}, "status_code": 401}
    else:
        password_hash = hash_string(password)
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (user_id, password_hash) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        conn.close()
        return {"body": {"message": "Registered Successfully"}, "status_code": 200}

def check_username_exists(username):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE user_id = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    return user is not None

def login_user(username, password):
    password_hash = hash_string(password)
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE user_id = ? AND password_hash = ?', (username, password_hash))
    user = cursor.fetchone()
    conn.close()
    if user:
        return {"body": {"message": "Login Successfully"}, "status_code": 200}
    else:
        return {"body": {"message": "Invalid Credentials"}, "status_code": 401}

def insert_encryption(key, value):
    try:
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO cookies (identifier, encrypted_data) VALUES (?, ?)', (key, value))
        conn.commit()
        conn.close()
        return True
    except:
        return False

def get_encryption(key):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT encrypted_data FROM cookies WHERE identifier = ?', (key,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return {"signal": True, "encrypted_string": result[0]}
    else:
        return {"signal": False}

def getDocuments(userId):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT file_id, file_name, date_created  FROM files WHERE user_id = ?', (userId,))
    userDocuments = [{"fileId": row[0], "fileName": row[1], "dateCreated": row[2], "ownerName": userId} for row in cursor.fetchall()]
    
    for document in userDocuments:
        cursor.execute('SELECT receiver_id, permission FROM shared_files WHERE file_id = ?', (document["fileId"],))
        sharedUsers = [{"userId": row[0], "permission": row[1]} for row in cursor.fetchall()]
        document["sharedUsers"] = sharedUsers
    
    conn.close()
    return {"body": {"message": "Documents fetched Successfully", "filesList": userDocuments}, "status_code": 200}

def getSharedDocuments(userId):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT file_id, owner_id, permission FROM shared_files WHERE receiver_id = ?', (userId,))
    sharedDocuments = [{"fileId": row[0], "ownerName": row[1], "permissions": row[2]} for row in cursor.fetchall()]
    
    for document in sharedDocuments:
        cursor.execute('SELECT file_name FROM files WHERE file_id = ?', (document["fileId"],))
        fileName = cursor.fetchone()[0]
        document["fileName"] = fileName
        
        cursor.execute('SELECT receiver_id, permission FROM shared_files WHERE file_id = ?', (document["fileId"],))
        sharedUsers = [{"userId": row[0], "permission": row[1]} for row in cursor.fetchall()]
        document["sharedUsers"] = sharedUsers
    
    conn.close()
    return {"body": {"message": "Documents fetched Successfully", "filesList": sharedDocuments}, "status_code": 200}

def getDocumentContent(userId, fileId):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT content FROM files WHERE file_id = ? AND user_id = ?', (fileId, userId))
    fileContent = cursor.fetchone()
    conn.close()
    if fileContent:
        decrypted_content = decrypt_from_fixed_length_string(fileContent[0])
        return {"body": {"message": "Document fetched Successfully", "fileId": fileId, "fileContent": decrypted_content}, "status_code": 200}
    else:
        return {"body": {"message": "File not found"}, "status_code": 401}

def deleteDocument(userId, fileId):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM files WHERE file_id = ? AND user_id = ?', (fileId, userId))
    file = cursor.fetchone()
    if file:
        cursor.execute('DELETE FROM files WHERE file_id = ? AND user_id = ?', (fileId, userId))
        cursor.execute('DELETE FROM shared_files WHERE file_id = ?', (fileId,))
        conn.commit()
        conn.close()
        return {"body": {"message": "File Deleted Successfully"}, "status_code": 200}
    else:
        conn.close()
        return {"body": {"message": "File not found"}, "status_code": 401}

def renameDocument(userId, fileId, newFileName):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM files WHERE file_id = ? AND user_id = ?', (fileId, userId))
    file = cursor.fetchone()
    if file:
        cursor.execute('UPDATE files SET file_name = ? WHERE file_id = ? AND user_id = ?', (newFileName, fileId, userId))
        conn.commit()
        conn.close()
        return {"body": {"message": "File Renamed Successfully"}, "status_code": 200}
    else:
        conn.close()
        return {"body": {"message": "File not found"}, "status_code": 401}

def newFile(userId, fileName, dateCreated):
    conn = connect_db()
    cursor = conn.cursor()    
    cursor.execute('SELECT * FROM users WHERE user_id = ?', (userId,))
    user = cursor.fetchone()
    if user:
        fileId = generate_alphanumeric_code()
        encrypted_content = encrypt_to_fixed_length_string("")["encrypted_data"]
        cursor.execute('INSERT INTO files (file_id, user_id, date_created, file_name, content) VALUES (?, ?, ?, ?, ?)', 
                       (fileId, userId, dateCreated, fileName, encrypted_content))
        conn.commit()
        conn.close()
        return {"body": {"message": "File Created Successfully"}, "status_code": 200}
    else:
        conn.close()
        return {"body": {"message": "User not found"}, "status_code": 401}

def updateFilePermissions(userId, fileId, sharedUsers):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM files WHERE file_id = ? AND user_id = ?', (fileId, userId))
    file = cursor.fetchone()
    if file:
        cursor.execute('DELETE FROM shared_files WHERE file_id = ?', (fileId,))
        rejected_users = []
        for entry in sharedUsers:
            sharedUserId = entry["userId"]
            cursor.execute('SELECT * FROM users WHERE user_id = ?', (entry["userId"],))
            user = cursor.fetchone()
            if user:
                permission = entry["permission"]
                cursor.execute('INSERT INTO shared_files (file_id, owner_id, receiver_id, permission) VALUES (?, ?, ?, ?)', 
                               (fileId, userId, sharedUserId, permission))
            else:
                rejected_users.append(entry["userId"])
        conn.commit()
        conn.close()
        message = "File Permissions Updated Successfully"
        if rejected_users:
            for userId in rejected_users:
                message += f"\nUserId {userId} not found"
        return {"body": {"message": message, "rejectedUsers": rejected_users, "isRejected": bool(rejected_users)}, "status_code": 200}
    else:
        conn.close()
        return {"body": {"message": "File not found"}, "status_code": 401}

def saveDocumentContent(userId, fileId, content):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM files WHERE file_id = ? AND user_id = ?', (fileId, userId))
    file = cursor.fetchone()    
    if file:
        encrypted_content = encrypt_to_fixed_length_string(content)["encrypted_data"]
        cursor.execute('UPDATE files SET content = ? WHERE file_id = ? AND user_id = ?', (encrypted_content, fileId, userId))
        conn.commit()
        conn.close()
        return {"body": {"message": "File updated Successfully"}, "status_code": 200}
    else:
        cursor.execute('SELECT permission FROM shared_files WHERE file_id = ? AND receiver_id = ?', (fileId, userId))
        shared_file = cursor.fetchone()
        if shared_file:
            permission = shared_file[0]
            if "edit" in permission.split(","):
                encrypted_content = encrypt_to_fixed_length_string(content)["encrypted_data"]
                cursor.execute('UPDATE files SET content = ? WHERE file_id = ?', (encrypted_content, fileId))
                conn.commit()
                conn.close()
                return {"body": {"message": "File updated Successfully"}, "status_code": 200}
            else:
                conn.close()
                return {"body": {"message": "User doesn't have sufficient privileges"}, "status_code": 403}
        else:
            conn.close()
            return {"body": {"message": "File not found"}, "status_code": 401}

def logout(identifier):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM cookies WHERE identifier = ?', (identifier,))
    conn.commit()
    conn.close()
    return {"body": {"message": "User logged out Successfully"}, "status_code": 200}
