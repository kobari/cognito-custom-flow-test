import base64
import binascii
import datetime
import hashlib
import hmac
import logging
import os
import re

import boto3
import six
from dotenv import load_dotenv
load_dotenv()

logger = logging.getLogger(__name__)

COGNITO_USER_POOL_ID = os.getenv('COGNITO_USER_POOL_ID')
COGNITO_CLIENT_ID =  os.getenv('COGNITO_CLIENT_ID')
COGNITO_SECRET_KEY = os.getenv('COGNITO_SECRET_KEY')
COGNITO_REGION = os.getenv('COGNITO_REGION')
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY =os.getenv('AWS_SECRET_ACCESS_KEY')


class CognitoBoto3Auth:
    """
    boto3使用したcognitoの操作を行うクラス
    """

    # https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L22
    n_hex = (
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        + "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
        + "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
        + "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
        + "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
        + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
        + "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
    )
    # https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L49
    g_hex = "2"
    info_bits = bytearray("Caldera Derived Key", "utf-8")

    def __init__(self):
        self.cognito_user_pool_id = COGNITO_USER_POOL_ID
        self.app_client_id = COGNITO_CLIENT_ID
        self.secret_key = COGNITO_SECRET_KEY
        self.aws_client = boto3.client(
            "cognito-idp",
            region_name=COGNITO_REGION,
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        )
        self.big_n = self._hex_to_long(self.n_hex)
        self.g = self._hex_to_long(self.g_hex)
        self.k = self._hex_to_long(self._hex_hash("00" + self.n_hex + "0" + self.g_hex))
        self.small_a_value = self._generate_random_small_a()
        self.large_a_value = self._calculate_a()

    def _pad_hex(self, long_int):
        """
        Converts a Long integer (or hex string) to hex format padded with zeroes for hashing
        :param {Long integer|String} long_int Number or string to pad.
        :return {String} Padded hex string.
        """
        if not isinstance(long_int, six.string_types):
            hash_str = self._long_to_hex(long_int)
        else:
            hash_str = long_int
        if len(hash_str) % 2 == 1:
            hash_str = "0%s" % hash_str
        elif hash_str[0] in "89ABCDEFabcdef":
            hash_str = "00%s" % hash_str
        return hash_str

    def _hash_sha256(self, buf):
        """
        AuthenticationHelper.hash
        以下の関数はURLを元にしている
        refs: https://github.com/capless/warrant/blob/master/warrant/aws_srp.py
        """
        a = hashlib.sha256(buf).hexdigest()
        return (64 - len(a)) * "0" + a

    def _hex_hash(self, hex_string):
        return self._hash_sha256(bytearray.fromhex(hex_string))

    def _hex_to_long(self, hex_string):
        return int(hex_string, 16)

    def _long_to_hex(self, long_num):
        return "%x" % long_num

    def _get_random(self, nbytes):
        random_hex = binascii.hexlify(os.urandom(nbytes))
        return self._hex_to_long(random_hex)

    def _generate_random_small_a(self):
        """
        helper function to generate a random big integer
        :return {Long integer} a random value.
         refs: https://github.com/capless/warrant/blob/master/warrant/aws_srp.py
        """
        random_long_int = self._get_random(128)
        return random_long_int % self.big_n

    def _calculate_a(self):
        """
        Calculate the client's public value A = g^a%N
        with the generated random number a
        :param {Long integer} a Randomly generated small A.
        :return {Long integer} Computed large A.
        refs: https://github.com/capless/warrant/blob/master/warrant/aws_srp.py
        """
        big_a = pow(self.g, self.small_a_value, self.big_n)
        # safety check
        if (big_a % self.big_n) == 0:
            raise ValueError("Safety check for A failed")
        return big_a

    def _compute_hkdf(self, ikm, salt):
        """
        Standard hkdf algorithm
        :param {Buffer} ikm Input key material.
        :param {Buffer} salt Salt value.
        :return {Buffer} Strong key material.
        @private
        """
        prk = hmac.new(salt, ikm, hashlib.sha256).digest()
        info_bits_update = self.info_bits + bytearray(chr(1), "utf-8")
        hmac_hash = hmac.new(prk, info_bits_update, hashlib.sha256).digest()
        return hmac_hash[:16]

    def _calculate_u(self, big_a, big_b):
        """
        Calculate the client's value U which is the hash of A and B
        :param {Long integer} big_a Large A value.
        :param {Long integer} big_b Server B value.
        :return {Long integer} Computed U value.
        """
        u_hex_hash = self._hex_hash(self._pad_hex(big_a) + self._pad_hex(big_b))
        return self._hex_to_long(u_hex_hash)

    def _get_password_authentication_key(self, username, password, server_b_value, salt):
        """
        Calculates the final hkdf based on computed S value, and computed U value and the key
        :param {String} username Username.
        :param {String} password Password.
        :param {Long integer} server_b_value Server B value.
        :param {Long integer} salt Generated salt.
        :return {Buffer} Computed HKDF value.
        """
        u_value = self._calculate_u(self.large_a_value, server_b_value)
        if u_value == 0:
            raise ValueError("U cannot be zero.")
        username_password = "%s%s:%s" % (
            self.cognito_user_pool_id.split("_")[1],
            username,
            password,
        )
        username_password_hash = self._hash_sha256(username_password.encode("utf-8"))

        x_value = self._hex_to_long(self._hex_hash(self._pad_hex(salt) + username_password_hash))
        g_mod_pow_xn = pow(self.g, x_value, self.big_n)
        int_value2 = server_b_value - self.k * g_mod_pow_xn
        s_value = pow(int_value2, self.small_a_value + u_value * x_value, self.big_n)
        hkdf = self._compute_hkdf(
            bytearray.fromhex(self._pad_hex(s_value)),
            bytearray.fromhex(self._pad_hex(self._long_to_hex(u_value))),
        )
        return hkdf

    def _process_challenge(self, username, password, challenge_parameters):
        """
        SRP認証の返却値からauth challengeを行う
        refs: https://github.com/capless/warrant/blob/master/warrant/aws_srp.py

        """
        user_id_for_srp = challenge_parameters["USER_ID_FOR_SRP"]
        salt_hex = challenge_parameters["SALT"]
        srp_b_hex = challenge_parameters["SRP_B"]
        secret_block_b64 = challenge_parameters["SECRET_BLOCK"]
        # re strips leading zero from a day number (required by AWS Cognito)
        timestamp = re.sub(
            r" 0(\d) ", r" \1 ", datetime.datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y")
        )
        hkdf = self._get_password_authentication_key(
            user_id_for_srp, password, self._hex_to_long(srp_b_hex), salt_hex
        )
        secret_block_bytes = base64.standard_b64decode(secret_block_b64)
        msg = (
            bytearray(self.cognito_user_pool_id.split("_")[1], "utf-8")
            + bytearray(user_id_for_srp, "utf-8")
            + bytearray(secret_block_bytes)
            + bytearray(timestamp, "utf-8")
        )
        hmac_obj = hmac.new(hkdf, msg, digestmod=hashlib.sha256)
        signature_string = base64.standard_b64encode(hmac_obj.digest())
        response = {
            "TIMESTAMP": timestamp,
            "USERNAME": user_id_for_srp,
            "PASSWORD_CLAIM_SECRET_BLOCK": secret_block_b64,
            "PASSWORD_CLAIM_SIGNATURE": signature_string.decode("utf-8"),
            "SECRET_HASH": self._get_client_secret(username),
        }
        return response

    def sign_up(self, username: str, password: str, email:str) -> dict:
        """
        cognitoユーザのsignupを行う
        refs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html#CognitoIdentityProvider.Client.sign_up
        """
        return self.aws_client.sign_up(
            ClientId=self.app_client_id,
            SecretHash=self._get_client_secret(username),
            Username=username,
            Password=password,
            UserAttributes=[
                {
                    "Name": "email",
                    "Value": email,
                },
            ],
        )

    def confirm_sign_up(self, username: str, confirmation_code: str) -> dict:
        """
        cognitoユーザの確認コードを使用しユーザ登録を行う
        refs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html#CognitoIdentityProvider.Client.confirm_sign_up
        """
        return self.aws_client.confirm_sign_up(
            ClientId=self.app_client_id,
            SecretHash=self._get_client_secret(username),
            Username=username,
            ConfirmationCode=confirmation_code,
        )

    def initiate_auth(self, username: str, password: str) -> dict:
        """
        cognitoユーザの認証フロー開始を行う
        refs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html#CognitoIdentityProvider.Client.initiate_auth
        """
        return self.aws_client.initiate_auth(
            ClientId=self.app_client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password,
                "SECRET_HASH": self._get_client_secret(username),
            },
        )

    def custom_initiate_auth(self, username: str, password: str) -> dict:
        """
        cognitoユーザの認証フロー開始を行う
        refs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html#CognitoIdentityProvider.Client.initiate_auth
        """
        return self.aws_client.initiate_auth(
            ClientId=self.app_client_id,
            AuthFlow="CUSTOM_AUTH",
            # AuthFlow="USER_SRP_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password,
                "CHALLENGE_NAME": "SRP_A",
                #"CHALLENGE_NAME": "CUSTOM_CHALLENGE",
                "SRP_A": self._long_to_hex(self.large_a_value),
                "SECRET_HASH": self._get_client_secret(username),
            },
        )

    def refresh_token(self, username: str, token: str) -> dict:
        """
        新しいToken返却をする
        refs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html#CognitoIdentityProvider.Client.initiate_auth
        """
        return self.aws_client.initiate_auth(
            ClientId=self.app_client_id,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={
                "REFRESH_TOKEN": token,
                "SECRET_HASH": self._get_client_secret(username),
            },
        )

    def respond_to_auth_challenge(self, username: str, new_password: str, session: str) -> dict:
        """
        initiate_authの情報をもとに初回認証時のパスワード変更をする
        refs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html#CognitoIdentityProvider.Client.respond_to_auth_challenge
        """
        return self.aws_client.respond_to_auth_challenge(
            ClientId=self.app_client_id,
            ChallengeName="NEW_PASSWORD_REQUIRED",
            ChallengeResponses={
                "USERNAME": username,
                "NEW_PASSWORD": new_password,
                "SECRET_HASH": self._get_client_secret(username),
            },
            Session=session,
        )

    def password_verifier_respond_to_auth_challenge(
        self, username: str, password: str, session: str, challenge_parameters: dict
    ) -> dict:
        """
        initiate_authの情報をもとに初回認証時のパスワード変更をする
        refs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html#CognitoIdentityProvider.Client.respond_to_auth_challenge
        """
        return self.aws_client.respond_to_auth_challenge(
            ClientId=self.app_client_id,
            ChallengeName="PASSWORD_VERIFIER",
             Session=session,
            ChallengeResponses=self._process_challenge(username, password, challenge_parameters),
            
        )

    def custom_respond_to_auth_challenge(self, username: str, new_password: str, session: str) -> dict:
        """
        initiate_authの情報をもとに初回認証時のパスワード変更をする
        refs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html#CognitoIdentityProvider.Client.respond_to_auth_challenge
        """
        return self.aws_client.respond_to_auth_challenge(
            ClientId=self.app_client_id,
            ChallengeName="CUSTOM_CHALLENGE",
            ChallengeResponses={
                "USERNAME": username,
                "NEW_PASSWORD": new_password,
                "SECRET_HASH": self._get_client_secret(username),
            },
            Session=session,
        )

    def reset_user_password(self, username: str) -> dict:
        """
        パスワードリセットをする
        refs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html#CognitoIdentityProvider.Client.admin_reset_user_password
        """
        return self.aws_client.admin_reset_user_password(
            UserPoolId=self.cognito_user_pool_id,
            Username=username,
        )

    def confirm_forgot_password(
        self, username: str, password: str, confirmation_code: str
    ) -> dict:
        """
        パスワード再設定をする
        refs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html#CognitoIdentityProvider.Client.confirm_forgot_password
        """
        return self.aws_client.confirm_forgot_password(
            ClientId=self.app_client_id,
            SecretHash=self._get_client_secret(username),
            Username=username,
            ConfirmationCode=confirmation_code,
            Password=password,
        )

    def resend_confirmation_code(self, username: str) -> dict:
        """
        確認コードを再送信する
        refs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html#CognitoIdentityProvider.Client.resend_confirmation_code
        """
        return self.aws_client.resend_confirmation_code(
            ClientId=self.app_client_id,
            SecretHash=self._get_client_secret(username),
            Username=username,
        )

    def update_user_attributes(
        self, access_token: str, phone: str, email: str, user_type: str
    ) -> dict:
        """
        user attributeを更新する
        refs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html#CognitoIdentityProvider.Client.update_user_attributes
        """
        attributes = [
            {
                "Name": "phone_number",
                "Value": phone,
            },
            {
                "Name": "email",
                "Value": email,
            },
            {
                "Name": "custom:user_type",
                "Value": user_type,
            },
        ]
        return self.aws_client.update_user_attributes(
            UserAttributes=attributes,
            AccessToken=access_token,
        )

    def get_user_attribute_verification_code(self, access_token: str) -> dict:
        """
        user attributeを更新する
        refs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html#CognitoIdentityProvider.Client.update_user_attributes
        """
        return self.aws_client.get_user_attribute_verification_code(
            AttributeName="email",
            AccessToken=access_token,
        )

    def verify_user_attribute(self, access_token: str, confirmation_code: str) -> dict:
        """
        user_attributeを認証する
        refs: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html#CognitoIdentityProvider.Client.verify_user_attribute
        """
        return self.aws_client.verify_user_attribute(
            AccessToken=access_token,
            AttributeName="email",
            Code=confirmation_code,
        )

    def _get_client_secret(self, username: str) -> str:
        """
        SecretHash 値を返却
        """
        message = bytes(username + self.app_client_id, "utf-8")
        key = bytes(self.secret_key, "utf-8")
        secret_hash = base64.b64encode(
            hmac.new(key, message, digestmod=hashlib.sha256).digest()
        ).decode()
        return secret_hash
