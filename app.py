from time import sleep, time
from json import dumps, loads
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
import logging
import boto3
import botocore.exceptions
import hmac
import hashlib
import base64
import sqlite3
import json
import os
from dotenv import load_dotenv
import sqlite3

class NewUser(BaseModel):
    username: str
    email: str 
    password: str
    name: str

class ConfirmUser(BaseModel):
    username: str
    code: str

class ResendVerification(BaseModel):
    username: str

class LoginUser(BaseModel):
    username: str
    password: str

class RefreshUser(BaseModel):
    username: str

load_dotenv()
app = FastAPI()
client = boto3.client(
    'cognito-idp'
    , region_name='us-east-1'
    , aws_access_key_id=os.getenv('ACCESS_ID')
    , aws_secret_access_key=os.getenv('ACCESS_KEY')
    , aws_session_token=os.getenv('ACCESS_TOKEN')
    )    
connection = sqlite3.connect("sessions.db", check_same_thread=False) #TODO: mejorar
cursor = connection.cursor()

USER_POOL_ID = os.getenv('USER_POOL_ID')
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')

def get_secret_hash(username):
    msg = username + CLIENT_ID
    dig = hmac.new(str(CLIENT_SECRET).encode('utf-8'), 
    msg = str(msg).encode('utf-8'), digestmod=hashlib.sha256).digest()
    d2 = base64.b64encode(dig).decode()
    return d2

def sign_up(newUser: NewUser):    

    username = newUser.username
    email = newUser.email
    password = newUser.password
    name = newUser.name 
    
    try:
        resp = client.sign_up(
            ClientId=CLIENT_ID,
            SecretHash=get_secret_hash(username),
            Username=username,
            Password=password, 
            UserAttributes=[ 
                { 'Name': "name", 'Value': name},
                { 'Name': "email", 'Value': email}
            ],
            ValidationData=[
                { 'Name': "email", 'Value': email},
                { 'Name': "custom:username", 'Value': username }
            ])
    except client.exceptions.UsernameExistsException as e:
        return {"error": False, "success": True, "message": "This username already exists", "data": None}    
    except client.exceptions.InvalidPasswordException as e: 
        return {"error": False, "success": True, "message": "Password should have Caps, Special chars, Numbers", "data": None}    
    except client.exceptions.UserLambdaValidationException as e:
        return {"error": False, "success": True, "message": "Email already exists", "data": None}
    except Exception as e:
        return {"error": False, "success": True, "message": str(e), "data": None}
    return {"error": False, "success": True, "message": "Please confirm your signup, check Email for validation code", "data": None}

def confirm_signup(confirmUser: ConfirmUser):
    try:
        username = confirmUser.username
        # password = confirmUser.password
        code = confirmUser.code

        response = client.confirm_sign_up(
            ClientId=CLIENT_ID,
            SecretHash=get_secret_hash(username),
            Username=username,
            ConfirmationCode=code,
            ForceAliasCreation=False,       
        )
    except client.exceptions.UserNotFoundException:
        # return {"error": True, "success": False, "message": "Username doesnt exists"}
        return {}    
    except client.exceptions.CodeMismatchException:
        return {"error": True, "success": False, "message": "Invalid Verification code"}
        
    except client.exceptions.NotAuthorizedException:
        return {"error": True, "success": False, "message": "User is already confirmed"}
    
    except Exception as e:
        return {"error": True, "success": False, "message": f"Unknown error {e.__str__()} "}
      
    return response

def resend_verification(resend: ResendVerification):
    username = resend.username
    try:
        client.resend_confirmation_code(
            ClientId=CLIENT_ID,
            SecretHash=get_secret_hash(username),
            Username=username,
        )
    except client.exceptions.UserNotFoundException:
        return {"error": True, "success": False, "message":   "Username doesnt exists"}
        
    except client.exceptions.InvalidParameterException:
        return {"error": True, "success": False, "message": "User is already confirmed"}
    
    except Exception as e:
        return {"error": True, "success": False, "message": f"Unknown error {e.__str__()} "}
      
    return  {"error": False, "success": True}


## LOGIN


def store_session(username: str, response):
    cursor.execute("""
        INSERT OR REPLACE INTO sessions(username, refresh_token, access_token, id_token)
        VALUES (?, ?, ?, ?)
        """
        , (
            username
            , response["AuthenticationResult"]["RefreshToken"]
            , response["AuthenticationResult"]["AccessToken"]
            , response["AuthenticationResult"]["IdToken"]
        )
    )
    connection.commit()

def update_session(username: str, response):
    cursor.execute("""
        UPDATE sessions
        SET 
            access_token = ?
            , id_token = ?
        WHERE username = ?
        """
        , (
            response["AuthenticationResult"]["AccessToken"]
            , response["AuthenticationResult"]["IdToken"]
            , username
        )
    )
    connection.commit()

def internal_login(username, password):
    try:
        resp = client.admin_initiate_auth(
            UserPoolId=USER_POOL_ID,
            ClientId=CLIENT_ID,
            AuthFlow='ADMIN_NO_SRP_AUTH',
            AuthParameters={
                'USERNAME': username,
                'SECRET_HASH': get_secret_hash(username),
                'PASSWORD': password,
            },
            ClientMetadata={
                'username': username,
                'password': password,              
        })    
        store_session(username, resp)
    except client.exceptions.NotAuthorizedException:
        return None, "The username or password is incorrect"
    except client.exceptions.UserNotConfirmedException:
        return None, "User is not confirmed"
    except Exception as e:
        return None, e.__str__()
    return resp, None

def internal_refresh(username: str):
    cursor.execute("""
            SELECT refresh_token 
            FROM sessions
            WHERE username = ?
            """, (username, )
        )
    token = cursor.fetchone()[0]

    try:
        resp = client.admin_initiate_auth(
            UserPoolId=USER_POOL_ID,
            ClientId=CLIENT_ID,
            AuthFlow='REFRESH_TOKEN',
            AuthParameters={
                'SECRET_HASH': get_secret_hash(username),
                'REFRESH_TOKEN': token,
            }
        )  
        update_session(username, resp)
    except client.exceptions.NotAuthorizedException:
        return None, "The username or password is incorrect"
    except client.exceptions.UserNotConfirmedException:
        return None, "User is not confirmed"
    except Exception as e:
        return None, e.__str__()
    return resp, None


def login(loginUser: LoginUser):

    username = loginUser.username
    password = loginUser.password

    resp, msg = internal_login(username, password)
    if msg != None:
        return {'message': msg, "error": True, "success": False, "data": None}   
   
    if resp.get("AuthenticationResult"):
        return {'message': "success", 
            "error": False, 
            "success": True, 
            "data": {
                "id_token": resp["AuthenticationResult"]["IdToken"],
                "refresh_token": resp["AuthenticationResult"]["RefreshToken"],
                "access_token": resp["AuthenticationResult"]["AccessToken"],
                "expires_in": resp["AuthenticationResult"]["ExpiresIn"],
                "token_type": resp["AuthenticationResult"]["TokenType"]
            }
        }
    else: #this code block is relevant only when MFA is enabled
        return {"error": True, "success": False, "data": None, "message": None}

def refresh(refreshUser: RefreshUser):

    username = refreshUser.username

    resp, msg = internal_refresh(username)
    if msg != None:
        return {'message': msg, "error": True, "success": False, "data": None}   
   
    if resp.get("AuthenticationResult"):
        return {'message': "success", 
            "error": False, 
            "success": True, 
            "data": {
                "id_token": resp["AuthenticationResult"]["IdToken"],
                "access_token": resp["AuthenticationResult"]["AccessToken"],
                "expires_in": resp["AuthenticationResult"]["ExpiresIn"],
                "token_type": resp["AuthenticationResult"]["TokenType"]
            }
        }
    else: #this code block is relevant only when MFA is enabled
        return {"error": True, "success": False, "data": None, "message": None}


@app.post("/signup/")
def signup_handler(newUser: NewUser):
    return sign_up(newUser)

@app.post("/signup/confirm/")
def confirm_handler(confirmUser: ConfirmUser):
    return confirm_signup(confirmUser)

@app.post("/signup/resend/")
def resend_handler(resend: ResendVerification):
    return resend_verification(resend)

@app.post("/login/")
def login_handler(loginUser: LoginUser):
    return login(loginUser)

@app.post("/refresh/")
def refresh_handler(refreshUser: RefreshUser):
    return refresh(refreshUser)
    

if __name__ == '__main__':
    logging.getLogger("uvicorn").handlers.clear()
    uvicorn.run(app, host="0.0.0.0", port=8000)

