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
import json

class NewUser(BaseModel):
    username: str
    email: str 
    password: str
    name: str

class ConfirmUser(BaseModel):
    username: str
    code: str

class LoginUser(BaseModel):
    username: str
    password: str

app = FastAPI()
client = boto3.client('cognito-idp', region_name='us-east-1')    

@app.post("/signup/")
def signup(newUser: NewUser):
    print(newUser)
    return sign_up(newUser)

@app.post("/signup/confirm/")
def confirm_signup(confirmUser: ConfirmUser):
    print(confirmUser)
    return confirm_signup(confirmUser)

@app.post("/login/")
def login(loginUser: LoginUser):
    print(loginUser)
    return login(loginUser)
    


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


def initiate_auth(username, password):
    secret_hash = get_secret_hash(username)
    try:
      resp = client.admin_initiate_auth(
        UserPoolId=USER_POOL_ID,
        ClientId=CLIENT_ID,
        AuthFlow='ADMIN_NO_SRP_AUTH',
        AuthParameters={
            'USERNAME': username,
            'SECRET_HASH': secret_hash,
            'PASSWORD': password,
        },
        ClientMetadata={
            'username': username,
            'password': password,              
        })    
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

    resp, msg = initiate_auth(username, password)
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


if __name__ == '__main__':
    logging.getLogger("uvicorn").handlers.clear()
    uvicorn.run(app, host="0.0.0.0", port=8000)

