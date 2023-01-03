from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, status, APIRouter

from schema import User, InitiateAuth, ResetPassword, ConfirmationCode
from cognito import CognitoBoto3Auth

app = FastAPI()
router = APIRouter()

@app.post("/sign_up" )
async def sign_up(body: User):
    print("body", body)
    cognito_auth = CognitoBoto3Auth()
    cognito_auth.sign_up(username=body.username, password=body.password, email=body.email)
    return {"Success": "True"}

@app.post("/confirmation_code" )
async def confirmation_code(body: ConfirmationCode):
    print("body", body)
    cognito_auth = CognitoBoto3Auth()
    cognito_auth.resend_confirmation_code(username=body.username)
    return {"Success": "True"}

@app.post("/reset_password" )
async def reset_password(body: ResetPassword):
    print("body", body)
    cognito_auth = CognitoBoto3Auth()
    cognito_auth.reset_user_password(username=body.username)
    return {"Success": "True"}

@app.post("/initiate_auth" )
async def initiate_auth(body: InitiateAuth):
    print("body", body)
    cognito_auth = CognitoBoto3Auth()
    result = cognito_auth.custom_initiate_auth(username=body.username, password=body.password)
    print("result", result)
    result2 = cognito_auth.password_verifier_respond_to_auth_challenge(
        body.username,
        body.password,
        result["Session"],
        result["ChallengeParameters"]
        )
    print("result2", result2)

    # result3 = cognito_auth.respond_to_auth_challenge(
    #     body.username,
    #     body.password,
    #     result2["Session"])
    # print(result3)
    return result

