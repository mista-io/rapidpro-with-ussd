from django.conf import settings
from django.contrib.auth.backends import ModelBackend
import requests
from temba.orgs.models import User, Org, OrgRole
from django_redis import get_redis_connection
import logging
import jwt
import json
import redis
from jwt.exceptions import InvalidTokenError

logger = logging.getLogger(__name__)


class AuthenticationBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            url = "https://api.mista.io/sms/auth/authy"
            data = {"email": username, "password": password}
            headers = {"Authorization": "Bearer " + settings.MISTA_ADMIN_TOKEN}
            response = requests.post(url, headers=headers, json=data)
            
            if response.status_code == 200:
                # Authentication was successful
                access_token = response.json().get('access_token')
                
                if access_token:
                    payload = decode_jwt_token(access_token)
                    print(payload)
                    email = payload['account']['email']
                    try:
                        user = User.objects.get(username__iexact=email)
                    except User.DoesNotExist:
                        # create account from API
                        logger.info("User does not exist, registering one")
                        print("User does not exist, registering one")
                        email = payload['account']['email']
                        first_name = payload['account']['firstname']
                        last_name = payload['account']['lastname']
                        organization = payload['account']['organization']
                        user = User.objects.create_user(
                            username=email,
                            first_name=first_name,
                            last_name=last_name,
                            password=None  # Password is handled by the authentication service
                        )
                        logger.info("New user created after call from auth service")
                        # create the Organization
                        anonymous = User.objects.get(pk=1)  # the default anonymous user
                        org_data = dict(name=organization, created_by=anonymous, modified_by=anonymous, timezone=settings.USER_TIME_ZONE)

                        org = Org.objects.create(**org_data)
                        org.add_user(user, OrgRole.ADMINISTRATOR)
                        logger.info("New user added to an organization")
                    return user
                else:
                    return None
        except User.DoesNotExist:
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a non-existing user (#20760).
            User().set_password(password)

    def get_user(self, user_id):
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:  # pragma: no cover
            return None
        return user if self.user_can_authenticate(user) else None


def decode_jwt_token(token: str):
    secret = settings.MISTA_JWT_SECRET

    stripped_bearer_token = strip_bearer_token(token)

    try:
        payload = jwt.decode(stripped_bearer_token, secret, algorithms=['HS256'])
        print(f"check this###########{payload}",payload)
        return payload
    except InvalidTokenError:
        raise Exception("Invalid authentication credentials")


def strip_bearer_token(token):
    """
    Strips the "Bearer " text from a JWT token and returns only the token.

    Args:
        token (str): The JWT token with or without the "Bearer " text.

    Returns:
        str: The JWT token without the "Bearer " text.
    """
    if token.startswith("Bearer "):
        return token[7:]
    else:
        return token


class MyAuthBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        url = "http://localhost:4000/user/auth/login"
        data = {"email": username, "password": password}
        response = requests.post(url, json=data)

        if response.status_code == 200:
            # Authentication was successful
            access_token = response.json().get('access_token')

            if access_token:
                payload = decode_jwt_token(access_token)

                try:
                    user = User.objects.get(email=payload['payload']['account']['email'])

                except User.DoesNotExist:
                    # User doesn't exist, create a new one
                    email = payload['payload']['account']['email']
                    first_name = payload['payload']['account']['firstname']
                    last_name = payload['payload']['account']['lastname']
                    organization = payload['payload']['account']['org']
                    user = User.objects.create_user(
                        email=email,
                        first_name=first_name,
                        last_name=last_name,
                        password=None,  # Password is handled by the authentication service
                        organization=organization
                    )
                return user
            else:
                raise Exception("No access token found in response")
        elif response.status_code == 401:
            # Invalid credentials
            return None
        else:
            # Something went wrong
            raise Exception("Authentication failed: {}".format(response.status_code))