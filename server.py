from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from lib.db.db import (
    register_user, login_user, insert_encryption, get_encryption, getDocuments,
    getSharedDocuments as getSharedDocs, getDocumentContent as getDocContent,
    deleteDocument as deleteDoc, renameDocument as renameDoc, updateFilePermissions as updateFileAccess,
    newFile as newFileDoc, saveDocumentContent as saveDoContent, logout as logout_user
)
from lib.utils.cryptic import encrypt_to_fixed_length_string, decrypt_from_fixed_length_string
import traceback

app = Flask(__name__)
app.config["SECRET_KEY"] = "vafuiwkxdml"
cors = CORS(app, supports_credentials=True, resources={r'/verifyCookie': {'origins': 'http://127.0.0.1:3000', "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"], "methods": ["GET", "POST", "OPTIONS", "PUT", "DELETE"], "expose_headers": ["Content-Disposition"]}})

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "http://localhost:3000"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
    return response

@app.route("/register", methods=["POST"])
def register():
    try:
        content_type = request.headers.get('Content-Type')
        if content_type == 'application/json':
            json = request.json
            if json["username"] == "" or json["password"] == "" or json["confirmPassword"] != json["password"]:
                response = make_response(jsonify({"message": 'Invalid Data'}))
                response.status_code = 400
                return response
            else:
                result = register_user(json["username"], json["password"])
                return jsonify(result["body"]), result["status_code"]
        else:
            response = make_response(jsonify({"message": 'Content-Type not supported!'}))
            response.status_code = 400
            return response
    except Exception as error:
        response = make_response(jsonify({"message": repr(error)}))
        response.status_code = 500
        return response

@app.route("/login", methods=["POST"])
def login():
    try:
        content_type = request.headers.get('Content-Type')
        if content_type == 'application/json':
            json = request.json
            if json["username"] == "" or json["password"] == "":
                response = make_response(jsonify({"message": 'Invalid Data'}))
                response.status_code = 400
                return response
            else:
                result = login_user(json["username"], json["password"])
                enc_object = encrypt_to_fixed_length_string({"ip": request.remote_addr, "userId": json["username"]})
                insert_encryption(enc_object["identifier"], enc_object["encrypted_data"])
                result["body"]["user"] = enc_object["identifier"]
                return jsonify(result["body"]), result["status_code"]
        else:
            response = make_response(jsonify({"message": 'Content-Type not supported!'}))
            response.status_code = 400
            return response
    except Exception as error:
        response = make_response(jsonify({"message": repr(error)}))
        response.status_code = 500
        return response

@app.route("/verifyUser", methods=["POST"])
def verifyCookie():
    try:
        content_type = request.headers.get('Content-Type')
        if content_type == 'application/json':
            json = request.json
            if json["user"] == "" or json["user"] is None:
                response = make_response(jsonify({"message": 'Invalid Data'}))
                response.status_code = 400
                return response
            else:
                identifier = json["user"]
                if identifier:
                    enc_signal_obj = get_encryption(identifier)
                    if enc_signal_obj["signal"]:
                        enc_obj = decrypt_from_fixed_length_string(enc_signal_obj["encrypted_string"])
                        if enc_obj["ip"] == request.remote_addr:
                            response = make_response(jsonify({"message": "User Verified", "userId": enc_obj["userId"]}))
                            response.status_code = 200
                            return response
                        else:
                            response = make_response(jsonify({"message": "Please login Again"}))
                            response.status_code = 401
                            return response
                    else:
                        response = make_response(jsonify({"message": "Invalid User"}))
                        response.status_code = 401
                        return response
                else:
                    response = make_response(jsonify({"message": "User not found"}))
                    response.status_code = 401
                    return response
        else:
            response = make_response(jsonify({"message": 'Content-Type not supported!'}))
            response.status_code = 400
            return response
    except Exception as error:
        print(traceback.format_exc())
        response = make_response(jsonify({"message": repr(error)}))
        response.status_code = 500
        return response

@app.route("/getUserDocuments", methods=["POST"])
def getUserDocuments():
    try:
        content_type = request.headers.get('Content-Type')
        if content_type == 'application/json':
            json = request.json
            if json["userId"] == "" or json["userId"] is None:
                response = make_response(jsonify({"message": 'Invalid Data'}))
                response.status_code = 400
                return response
            else:
                result = getDocuments(json["userId"])
                return jsonify(result["body"]), result["status_code"]
        else:
            response = make_response(jsonify({"message": 'Content-Type not supported!'}))
            response.status_code = 400
            return response
    except Exception as error:
        response = make_response(jsonify({"message": repr(error)}))
        response.status_code = 500
        return response

@app.route("/getSharedDocuments", methods=["POST"])
def getSharedDocuments():
    try:
        content_type = request.headers.get('Content-Type')
        if content_type == 'application/json':
            json = request.json
            if json["userId"] == "" or json["userId"] is None:
                response = make_response(jsonify({"message": 'Invalid Data'}))
                response.status_code = 400
                return response
            else:
                result = getSharedDocs(json["userId"])
                return jsonify(result["body"]), result["status_code"]
        else:
            response = make_response(jsonify({"message": 'Content-Type not supported!'}))
            response.status_code = 400
            return response
    except Exception as error:
        response = make_response(jsonify({"message": repr(error)}))
        response.status_code = 500
        return response

@app.route("/getDocumentContent", methods=["POST"])
def getDocumentContent():
    try:
        content_type = request.headers.get('Content-Type')
        if content_type == 'application/json':
            json = request.json
            if json["fileId"] == "" or json["fileId"] is None or json["userId"] == "" or json["userId"] is None:
                response = make_response(jsonify({"message": 'Invalid Data'}))
                response.status_code = 400
                return response
            else:
                result = getDocContent(json["userId"], json["fileId"])
                return jsonify(result["body"]), result["status_code"]
        else:
            response = make_response(jsonify({"message": 'Content-Type not supported!'}))
            response.status_code = 400
            return response
    except Exception as error:
        response = make_response(jsonify({"message": repr(error)}))
        response.status_code = 500
        return response

@app.route("/deleteDocument", methods=["POST"])
def deleteDocument():
    try:
        content_type = request.headers.get('Content-Type')
        if content_type == 'application/json':
            json = request.json
            if json["fileId"] == "" or json["fileId"] is None or json["userId"] == "" or json["userId"] is None:
                response = make_response(jsonify({"message": 'Invalid Data'}))
                response.status_code = 400
                return response
            else:
                result = deleteDoc(json["userId"], json["fileId"])
                return jsonify(result["body"]), result["status_code"]
        else:
            response = make_response(jsonify({"message": 'Content-Type not supported!'}))
            response.status_code = 400
            return response
    except Exception as error:
        response = make_response(jsonify({"message": repr(error)}))
        response.status_code = 500
        return response

@app.route("/renameDocument", methods=["POST"])
def renameDocument():
    try:
        content_type = request.headers.get('Content-Type')
        if content_type == 'application/json':
            json = request.json
            if json["fileId"] == "" or json["fileId"] is None or json["userId"] == "" or json["userId"] is None or json["newFileName"] == "" or json["newFileName"] is None:
                response = make_response(jsonify({"message": 'Invalid Data'}))
                response.status_code = 400
                return response
            else:
                result = renameDoc(json["userId"], json["fileId"], json["newFileName"])
                return jsonify(result["body"]), result["status_code"]
        else:
            response = make_response(jsonify({"message": 'Content-Type not supported!'}))
            response.status_code = 400
            return response
    except Exception as error:
        response = make_response(jsonify({"message": repr(error)}))
        response.status_code = 500
        return response

@app.route("/updateFilePermissions", methods=["POST"])
def updateFilePermissions():
    try:
        content_type = request.headers.get('Content-Type')
        if content_type == 'application/json':
            json = request.json
            if json["fileId"] == "" or json["fileId"] is None or json["userId"] == "" or json["userId"] is None or json["sharedUsers"] is None:
                response = make_response(jsonify({"message": 'Invalid Data'}))
                response.status_code = 400
                return response
            else:
                result = updateFileAccess(json["userId"], json["fileId"], json["sharedUsers"])
                return jsonify(result["body"]), result["status_code"]
        else:
            response = make_response(jsonify({"message": 'Content-Type not supported!'}))
            response.status_code = 400
            return response
    except Exception as error:
        response = make_response(jsonify({"message": repr(error)}))
        response.status_code = 500
        return response

@app.route("/newFile", methods=["POST"])
def newFile():
    try:
        content_type = request.headers.get('Content-Type')
        if content_type == 'application/json':
            json = request.json
            if json["fileName"] == "" or json["fileName"] is None or json["userId"] == "" or json["userId"] is None or json["dateCreated"] == "" or json["dateCreated"] is None:
                response = make_response(jsonify({"message": 'Invalid Data'}))
                response.status_code = 400
                return response
            else:
                result = newFileDoc(json["userId"], json["fileName"], json["dateCreated"])
                return jsonify(result["body"]), result["status_code"]
        else:
            response = make_response(jsonify({"message": 'Content-Type not supported!'}))
            response.status_code = 400
            return response
    except Exception as error:
        response = make_response(jsonify({"message": repr(error)}))
        response.status_code = 500
        return response

@app.route("/saveDocumentContent", methods=["POST"])
def saveDocumentContent():
    try:
        content_type = request.headers.get('Content-Type')
        if content_type == 'application/json':
            json = request.json
            if json["fileId"] == "" or json["fileId"] is None or json["userId"] == "" or json["userId"] is None or json["content"] is None:
                response = make_response(jsonify({"message": 'Invalid Data'}))
                response.status_code = 400
                return response
            else:
                # Encrypt the document content before saving
                result = saveDoContent(json["userId"], json["fileId"], json["content"])
                return jsonify(result["body"]), result["status_code"]
        else:
            response = make_response(jsonify({"message": 'Content-Type not supported!'}))
            response.status_code = 400
            return response
    except Exception as error:
        response = make_response(jsonify({"message": repr(error)}))
        response.status_code = 500
        return response

@app.route("/logout", methods=["POST"])
def logout():
    try:
        content_type = request.headers.get('Content-Type')
        if content_type == 'application/json':
            json = request.json
            identifier = json["user"]
            if identifier:
                result = logout_user(identifier)
                return jsonify(result["body"]), result["status_code"]
            else:
                response = make_response(jsonify({"message": "User not found"}))
                response.status_code = 401
                return response
        else:
            response = make_response(jsonify({"message": 'Content-Type not supported!'}))
            response.status_code = 400
            return response
    except Exception as error:
        response = make_response(jsonify({"message": repr(error)}))
        response.status_code = 500
        return response

if __name__ == "__main__":
    app.run(debug=True)
