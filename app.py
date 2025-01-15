from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello_world():
    print("Testing logging - Meiminass owns me")
    return 'Hello, World!'
