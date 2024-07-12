import streamlit as st
import json
import requests
from requests_oauthlib import OAuth2Session

# Google OAuth2 credentials
client_id = st.secrets["CLIENT_ID"]
client_secret = st.secrets["CLIENT_SECRET"]
redirect_uri = "https://azratrysignin.streamlit.app/"

# OAuth endpoints
authorization_base_url = "https://accounts.google.com/o/oauth2/auth"
token_url = "https://oauth2.googleapis.com/token"

# Scopes
scope = ["https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"]

def exchange_code_for_token(code):
    token_url = 'https://oauth2.googleapis.com/token'
    # Prepare the data for the token request
    data = {
        'code': code,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code'
    }
    # Make a POST request to the token endpoint
    response = requests.post(token_url, data=data)
    response_data = response.json()
    print(response_data)
    # Handle possible errors
    if response.status_code != 200:
        raise Exception("Failed to retrieve token: " + response_data.get('error_description', ''))
    return response_data['access_token']


def get_user_info(access_token):
    user_info_url = 'https://www.googleapis.com/oauth2/v3/userinfo'
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(user_info_url, headers=headers)
    user_info = response.json()
    # Handle possible errors
    if response.status_code != 200:
        raise Exception("Failed to retrieve user info: " + user_info.get('error_description', ''))
    return user_info

if 'oauth_state' not in st.session_state:
    st.session_state.oauth_state = None

if 'oauth_token' not in st.session_state:
    st.session_state.oauth_token = None

if st.session_state.oauth_token:
    oauth2_session = OAuth2Session(client_id, token=st.session_state.oauth_token)
    response = oauth2_session.get('https://www.googleapis.com/oauth2/v1/userinfo')
    user_info = response.json()
    st.write(f"Welcome {user_info['name']}!")
    st.write("Your email:", user_info['email'])
    if st.button("Logout"):
        st.session_state.oauth_token = None
else:
    oauth2_session = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
    authorization_url, state = oauth2_session.authorization_url(authorization_base_url, access_type="offline")

    if st.session_state.oauth_state is None:
        st.session_state.oauth_state = state

    st.markdown(f"[Login with Google]({authorization_url})")

    authorization_response = st.experimental_get_query_params()
    st.write(authorization_response)
    if 'code' in authorization_response:
        st.write(authorization_response['code'][0])

    if 'code' in authorization_response:
        st.session_state.oauth_token = exchange_code_for_token(authorization_response['code'])
        st.write(get_user_info(st.session_state.oauth_token))
