import os
from flask import Flask, redirect, render_template, request, url_for
import oauth2 as oauth
import urllib.request
import urllib.parse
import urllib.error
import json
import base64

app = Flask(__name__)

app.debug = False

request_token_url = 'https://api.twitter.com/oauth/request_token'
access_token_url = 'https://api.twitter.com/oauth/access_token'
authorize_url = 'https://api.twitter.com/oauth/authorize'
show_user_url = 'https://api.twitter.com/1.1/users/show.json'
update_profile_url = 'https://api.x.com/1.1/account/update_profile.json'
update_profile_image_url = 'https://api.x.com/1.1/account/update_profile_image.json'
# Support keys from environme
# Support keys from environment vars (Heroku).
app.config['APP_CONSUMER_KEY'] = os.environ.get("API_KEY")
app.config['APP_CONSUMER_SECRET'] = os.environ.get("API_SECRET")

# alternatively, add your key and secret to config.cfg
# config.cfg should look like:
# APP_CONSUMER_KEY = 'API_Key_from_Twitter'
# APP_CONSUMER_SECRET = 'API_Secret_from_Twitter

oauth_store = {}


@app.route('/')
def start():
    print("inside start")
    # note that the external callback URL must be added to the whitelist on
    # the developer.twitter.com portal, inside the app settings
    app_callback_url = os.environ.get("REDIRECT_URI")

    tstr=urllib.parse.urlencode({"oauth_callback": app_callback_url})
    print(tstr)
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
    starturi=""+f'{authorize_url}?oauth_token={oauth_token}'
    print(starturi)
    return redirect(starturi)
    #gresp, gcontent = client.request(starturi,"GET")
    #return gcontent
    #return render_template('start.html', authorize_url=authorize_url, oauth_token=oauth_token, request_token_url=request_token_url
'''
def create_multipart_data(file_path, field_name='image'):
    # Guess the MIME type
    content_type, _ = mimetypes.guess_type(file_path)
    
    # Read the file in binary mode
    with open(file_path, 'rb') as file:
        file_data = file.read()
    
    # Generate a boundary
    boundary = '---------------------------' + ''.join([str(random.randint(0, 9)) for _ in range(16)])
    
    # Construct multipart data
    multipart_data = (
        f'--{boundary}\r\n'
        f'Content-Disposition: form-data; name="{field_name}"; filename="{file_path.split("/")[-1]}"\r\n'
        f'Content-Type: {content_type}\r\n'
        f'\r\n'
    ).encode()

    # Append binary data and closing boundary
    multipart_data += file_data + f'\r\n--{boundary}--'.encode()

    return multipart_data, boundary

# Example usage
def update_profile_image(client):
    file_path = 'meiminass.png'
    data, boundary = create_multipart_data(file_path)
'''
# If you need to use this with requests:
# headers = {'Content-Type': f'multipart/form-data; boundary={boundary}'}
# response = requests.post('your_url', headers=headers, data=data)
def update_profile_image(client):
    with open("meiminass.png", "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read())
        params=urllib.parse.urlencode({"image":encoded_string.decode("utf-8")})
        #print(params)
        furi=update_profile_image_url+"?"+params
        print(furi)
        #furi=update_profile_image_url+"?image="+encoded_string.decode("utf-8")
        #print(furi)
        resp,content=client.request(furi,"POST")
        if resp['status'] != '200':
            print( "ERROR "+resp['status'])
            return
        print(content)
        return

def update_profile(client,name,url,location,description):
    #params=urllib.parse.urlencode({"name":name,"url":url,"location":location,"description":description})
    params=urllib.parse.urlencode({"description":description,"url":url,"location":location})
    print(params)
    furi=update_profile_url+"?"+params
    print(furi)
    resp, content = client.request(furi, "POST")
    if resp['status'] != '200':
        print( "ERROR "+resp['status'])
        return
    print(content)
    return
   

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
            del oauth_store[oauth_denied]
        return "the OAuth request was denied by this user"

    if not oauth_token or not oauth_verifier:
        return "callback param(s) missing"

    # unless oauth_token is still stored locally, return error
    if oauth_token not in oauth_store:
        return "oauth_token not found locally"

    oauth_token_secret = oauth_store[oauth_token]

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

    print("Now we are ready")
    print(real_oauth_token)
    print(real_oauth_token_secret)

    # Call api.twitter.com/1.1/users/show.json?user_id={user_id}
    real_token = oauth.Token(real_oauth_token, real_oauth_token_secret)
    
    real_client = oauth.Client(consumer, real_token)
    update_profile(real_client,"a","a.com","a","a")
    update_profile_image(client)
    '''
    real_resp, real_content = real_client.request(
        show_user_url + '?user_id=' + user_id, "GET")

    if real_resp['status'] != '200':
        error_message = "Invalid response from Twitter API GET users/show: {status}".format(
            status=real_resp['status'])
        return render_template('error.html', error_message=error_message)

    response = json.loads(real_content.decode('utf-8'))

    friends_count = response['friends_count']
    statuses_count = response['statuses_count']
    followers_count = response['followers_count']
    name = response['name']

    # don't keep this token and secret in memory any longer
    del oauth_store[oauth_token]

    return render_template('callback-success.html', screen_name=screen_name, user_id=user_id, name=name,
                           friends_count=friends_count, statuses_count=statuses_count, followers_count=followers_count, access_token_url=access_token_url)
'''
    return "MEIMINA$$ OWNS YOU"
