from flask import Flask, make_response, request

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Dang Vulnerable Page</title>
    <style>
        body { font-family: sans-serif; padding: 20px; }
        h1 { text-align: center; }
        .btn { 
            background: #ff4444; color: white; padding: 15px 30px; 
            font-size: 20px; border: none; cursor: pointer; 
        }
        .btn.confirm { background: #ff8800; }
        .success { color: green; display: none; margin-top: 20px; text-align: center; }
        
        #deleteBtn { 
            position: absolute;
            top: 30%;
            left: 50%;
            transform: translate(-50%, -50%);
        }
        #confirmBtn { 
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            display: none;
        }
    </style>
    <script>
        function armDelete() {
            document.getElementById('deleteBtn').style.display = 'none';
            document.getElementById('confirmBtn').style.display = 'block';
        }

        function confirmDelete() {
            document.getElementById('msg').style.display = 'block';
            document.getElementById('confirmBtn').disabled = true;
            console.log('Account deleted!');
        }
    </script>
</head>
<body>
    <h1>The Delete Account Site</h1>
    <p style="text-align: center;">XFO? CSP? Nope.</p>
    
    <button id="deleteBtn" class="btn" onclick="armDelete()">DELETE ACCOUNT</button>
    <button id="confirmBtn" class="btn confirm" onclick="confirmDelete()">CONFIRM DELETE</button>
    
    <div id="msg" class="success">Successfully Deleted!</div>
</body>
</html>
"""

@app.route('/')
def home():
    resp = make_response(HTML_TEMPLATE)
    resp.headers.pop('X-Frame-Options', None)
    resp.set_cookie('session_id', '12345-admin', samesite='None', secure=True)
    return resp

if __name__ == '__main__':
    print("[*] Starting Vulnerable Server on http://localhost:5000")
    print("[*] Run your Clickjack tool against this URL.")
    app.run(port=5000)