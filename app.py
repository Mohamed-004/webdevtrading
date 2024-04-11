from authlib.integrations.flask_client import OAuth
import firebase_admin
from firebase_admin import credentials, auth, db, firestore
from flask import Flask, render_template, send_from_directory, jsonify, request, url_for, redirect, session
from urllib.parse import quote_plus, urlencode
import requests
import stripe 

stripe.api_key = 'sk_test_51Oyi2xP649Efo4kCYt2kWsW0hPJjptfuWapRJB8ZMCHvhfI4HJF0FuAdEaNJ6JzbQVp0pj1BBOsMEQwf4XJvQSRA00ELDbyNAC'

app = Flask(__name__)
app.secret_key = '1799d3118e5549432de9b191ba8003c8826585499ebba1974de60d36c8c2c2e6'
app.config['DEBUG'] = True

endpoint_secret = 'whsec_5943b6c6ce120203812d73889dcc757cd73be09a7d93150736be55b115ca5d68'

cred = credentials.Certificate('static/prop-patrol24-firebase-adminsdk-i50kg-5fe571bc7b.json')
firebase_admin.initialize_app(cred)
db = firestore.client()

oauth = OAuth(app)
conf_url = 'https://dev-ct0rwl0778orlwvk.us.auth0.com/.well-known/openid-configuration'
oauth.register(
    name='proppatrol',
    client_id='qA5AwBA91VxeHowQQu6MDKOBYHWbWbmx',
    client_secret='7FckIXvKm00XxFch0RDB9iGiATPnKZ_RqnL83Um_BILE4_gQyL7fYLi7MfW431hn',
    server_metadata_url=conf_url,
    client_kwargs={'scope': 'openid profile email'},
)

@app.route("/callback", methods=["GET", "POST"])
def callback():
    try:
        token = oauth.proppatrol.authorize_access_token()
    except Exception as err:
        return "Please validate your email"
    
    user_info = {
    "email": token["userinfo"]["email"],
    "email_verified": str(token["userinfo"]["email_verified"])
}

# Store the extracted user information in the session
    session["user"] = user_info
    user = oauth.proppatrol.parse_id_token(token,nonce=session.get("nonce"))
 
    try:
        firebase_user = auth.get_user_by_email(user['email'])
    except auth.UserNotFoundError:
        # User not found in Firebase Authentication, create new user
        user_ref = db.collection('users').document(user['email'])
        user_ref.set({
        'uid': user['sub'],  # Assuming sub field contains UID
        'name': user.get('name', ''),
        'email': user['email'],
        # Add other user information as needed
    })
    
    return redirect(url_for('dashboard'))



@app.route("/login")
def login():
    return oauth.proppatrol.authorize_redirect(
        redirect_uri=url_for("callback", _external=True),
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://dev-ct0rwl0778orlwvk.us.auth0.com/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": 'qA5AwBA91VxeHowQQu6MDKOBYHWbWbmx',
            },
            quote_via=quote_plus,
        )
    )

@app.route("/dashboard")
def dashboard():
    # Check if user is authenticated
    user_info = False
    user_data = False
    user_validated_email = 0
    user_info = session.get("user")
    user_email = 0
    # token = oauth.proppatrol.authorize_access_token()
    # user_info_full = token
    try:
        user_email = user_info['email']
        user_validated_email = user_info["email_verified"]
        user_data= db.collection("users").where(field_path="email", op_string="==", value=user_email).get()
        if not user_info or not user_data:
        # Redirect to login page if user is not authenticated or email is not verified
            
            return redirect(url_for("login"))
    except:
        
        pass
    # print(user_data + " the value for user data came")
    
    if  user_validated_email == "False":
        return render_template("dashboard.html", session=user_info, unverified_email=True)
        
    # firebase_user_data = list(user_data.values())[0]
    
    return render_template("dashboard.html", session=user_info, user_email=user_email)


@app.route('/webhook', methods=['POST'])
def webhook():
    event = None
    payload = request.data
    sig_header = request.headers['STRIPE_SIGNATURE']

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        # Invalid payload
        raise e
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        raise e

    # Handle the event
    if event['type'] == 'checkout.session.async_payment_succeeded':
      session = event['data']['object']
      print(session)
    elif event['type'] == 'payment_intent.succeeded':
      payment_intent = event['data']['object']
      print(payment_intent)
    # ... handle other event types
    else:
      print('Unhandled event type {}'.format(event['type']))

    return jsonify(success=True)

@app.route('/robots.txt')
def static_from_root():
    return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/')
def home():
    return render_template('index.html')



@app.route('/report-payout')
def report_payout():
    return render_template('report_payout.html')

@app.route('/featured-firms')
def featured_firms():
    return render_template('featured-firms.html')

@app.route('/terms-of-service')
def tos():
    return render_template('terms-of-service.html')



@app.route('/reports/dei-20a')
def dei_20a():
    return render_template('dei_case_20a.html')

@app.route('/reports/fast-forex-funding-30a')
def fff_30a():
    return render_template('fff_case_30a.html')

@app.route('/reports/bespoke-funding-40a')
def bsp_40a():
    return render_template('bsp_case_40a.html')

@app.route('/reports/uwm-60a')
def uwm_60a():
    return render_template('uwm_case_60a.html')

@app.route('/reports/kortana-70a')
def kortana_70a():
    return render_template('kor_case_70a.html')

@app.route('/reports/mff-90a')
def mff_90a():
    return render_template('mff_case_90a.html')



# @app.route('/reports')
# def report_preview():
#     return render_template('report_section.html')

@app.route('/reports-unresolved-closed')
def report_preview_unresolved():
    return render_template('reports-unresolved-closed.html')

@app.route('/reports-unresolved-open')
def report_preview_unresolved_open():
    return render_template('reports-unresolved-open.html')

@app.route('/reports-resolved')
def report_preview_resolved():
    return render_template('reports-resolved.html')

@app.route('/view-reports')
def view_firm_reports():
    return render_template('reports-stats.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)