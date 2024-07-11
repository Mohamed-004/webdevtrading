from authlib.integrations.flask_client import OAuth
from authlib.integrations.base_client.errors import OAuthError
import firebase_admin
from firebase_admin import credentials, auth, db, firestore
from flask import Flask, render_template, send_from_directory, jsonify, request, url_for, redirect, session, flash, abort, current_app
from flask_wtf.csrf import CSRFProtect, validate_csrf
# from wtforms import ValidationError
from urllib.parse import quote_plus, urlencode
import stripe 
import sparkpost
import requests
from datetime import datetime, timedelta
import hmac
import hashlib

# email api key e0292a01d4005f36ecc119c1ea1cf1dd04ea111c
spark_api = 'e0292a01d4005f36ecc119c1ea1cf1dd04ea111c'

# stripe api key for test
stripe.api_key = 'sk_test_51Oyi2xP649Efo4kCYt2kWsW0hPJjptfuWapRJB8ZMCHvhfI4HJF0FuAdEaNJ6JzbQVp0pj1BBOsMEQwf4XJvQSRA00ELDbyNAC'

# endpoint secret for live stripe
# endpoint_secret = 'whsec_qlg8ZykAnynXuzW4T0KpvLYaDrqnpDYe'

# end point secret local host stripe
endpoint_secret = 'whsec_5943b6c6ce120203812d73889dcc757cd73be09a7d93150736be55b115ca5d68'

app = Flask(__name__)
app.secret_key = '1799d3118e5549432de9b191ba8003c8826585499ebba1974de60d36c8c2c2e6'
app.config['WTF_CSRF_SECRET_KEY'] =   'Dv1vKfzX6Eo5h_C9cSbX4Q'
app.config['DEBUG'] = True

# only for the live account
# app.config['PREFERRED_URL_SCHEME'] = 'https'
# app.config['SERVER_NAME'] = 'www.proppatrol.net'

csrf = CSRFProtect(app)

cred_dict = {
    "type": "service_account",
    "project_id": "prop-patrol24",
    "private_key_id": "5fe571bc7bceb6d25d48694e08a83c61485f8a71",
    "private_key": """-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCrZ45/6jcJC5U9
ZDFVsyVJGNWbV4qK7n0bSA1s26aAq7cZLMwfBJH8KL9lCxnN4SRpTuiYjlymtuId
LbfPsnT+rySOn6vocuY+oXCFD7s9WacEbD+RllOYWx+IrDPcp4AnrtmYopyEN1JS
Fx282KDRRijS7cjlEmv5q9UZR/XhM5RJQGXn8aoQOiLfQc5hqCp9vpEWSbYP/ubj
zyQTCMLNooW/dP5J4vYDpYWadrtGscH8FqnEaE6P8zht4Yj75vSpdqBOZCr2jKA5
t3HuLzJdAGlH6trd6R3KQRCllK6JPQGJ3v5Nrmk8qBE48VhNaoQmgTCUcssl1coY
P5v6eu+dAgMBAAECggEAA3U94eUYQiWf16gPT2gjVEOyKjBMb7wa/bNo7e11K6W1
4RtPF5XF2jKk6zAbpP8p9w6Wpl6XjkIknVZq8xTpw6pF5bNhSk8THRKwYfGCI103
1ODYMXg5FzBIxRRFoZR8LeYa/AzVH90RMJhzIE212jL8/NsQ5qowpSNV08I+ECfW
jx9JlMVhjW28hfygMQ1zUzb4ZvxtCUYtpxg8QYzvvFtyvet/O92fCXhss9gJOgBI
D02ezPLX/DkM4WeUUw2X5hh06g14/afNEs3V3o2Ucf+5EH8zaputI8DgE8SzjZd/
apxml4WDVQJEng5WeSNFBi3QxFt3KXzU0JnGnh6qAQKBgQDrnROvZMXbrkcOV6k4
dy9qMJ/GpEdarwl1NF9yVYcllQBM7H9w171Xzus/pGzJOJ4+3vzjFf2vYVU/YkZ8
L49lTpU5q23rCGN54zOl9eoPQxbtfd/4bnLGbOsiGP9sWhxWsM6yrET89v1iWjjj
MHr1o48qeStNhreTG9QSGt9mnQKBgQC6PDoATZwbzbVjhC3EzWajlLw/PWjgEU51
qo2Kef3tpXpZWIMHIaDggOzW7oGGhfVsq2CvoIMo9pbJ8IGkJwFPlawvc96FzYsk
emrA9HjVmuVfelkf2bXVXH5mNjTF0oCKbXII+aaSN70mRZMVNeXw6dqjbEPO4xzd
i8d/sj7dAQKBgQDKfeDhKHZzasBerzAb+zKgzNFEYwOACFbUiAJPvPm9buUnN0n/
rSppQMglliZ4eVRnLDWi5M913uzo4Ik7SZSvuG2/dnmtOTRlGMLWqxZRr5MQ4NGQ
LTwvFISwdVNvx7H7P1EldbCEx7DUyj2B47SJT9xG4IQ6yMEUiSIlvTqqcQKBgQCc
n/wztxG8PGP5vvdzFT/mATfUg8QI9eUjhn2lYXWSgOIF9C+2Nq0DQsps9IeQaGcA
rp0Q95B3SfOFADU3peovUXRPMEaMB1KnKiFQCAr7slqH0vDTnZiUSUawlZQKbz/V
q7gFHljdje0RG+BYLU0mMLbFTE821sC2/lCY74J5AQKBgQCut7XyrNguiwfm2wiK
AfcpbW3keKd5HqS7UXBWUodkjQqlnAmhvOSjF15U1S/spjajMd/YBpw4vRrXWzdM
d38Zqi+huq3YD5l9pUKuaxd+LRg3z8LOiW9yIHkDNTOmuMzA2TDo2HPvt74EKlky
XDB5FNJYelRHxHgG1ObSKInhiw==
-----END PRIVATE KEY-----""",
    "client_email": "firebase-adminsdk-i50kg@prop-patrol24.iam.gserviceaccount.com",
    "client_id": "102303481058183810627",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-i50kg%40prop-patrol24.iam.gserviceaccount.com"
}

firebase_admin_credential = credentials.Certificate(cred_dict)
firebase_app = firebase_admin.initialize_app(firebase_admin_credential)
db = firestore.client()

oauth = OAuth(app)
# # Updated URL with custom domain for live | dont use
# conf_url = 'https://auth.proppatrol.net/.well-known/openid-configuration'

conf_url = 'https://dev-ct0rwl0778orlwvk.us.auth0.com/.well-known/openid-configuration'
oauth.register(

    # for development or testing app | default app
    "auth0",
    client_id= ("sX97fU3VZlMQhuV4aoqaH4lAMNLtJ2rP"),
    client_secret= ("boC7oeG8C_3MEH0xMnqgDhOjiQj_813QBxRx52sXVFsCNud0ujin-gDuMTE8RYfS"),
    client_kwargs={
        "scope": "openid  email",
    },
    server_metadata_url='https://dev-ct0rwl0778orlwvk.us.auth0.com/.well-known/openid-configuration',


    # the following is for the real app
    # name='proppatrol',
    # client_id='qA5AwBA91VxeHowQQu6MDKOBYHWbWbmx',
    # client_secret='7FckIXvKm00XxFch0RDB9iGiATPnKZ_RqnL83Um_BILE4_gQyL7fYLi7MfW431hn',
    # server_metadata_url=conf_url,
    # client_kwargs={'scope': 'openid  email'},
)

# add_on_1 to show yes or no
add_on_1_allowed_base = False



def send_email(recipient, template_id, substitution_data):
    url = "https://api.sparkpost.com/api/v1/transmissions"
    headers = {
        "Authorization": spark_api,
        "Content-Type": "application/json"
    }
    payload = {
        "options": {
            "sandbox": False
        },
        "content": {
            "template_id": template_id,
            "use_draft_template": False
        },
        "recipients": [{
            "address": recipient,
            "substitution_data": substitution_data
        }]
    }
    # example of sub data
    # substitution_data = {
#     "first_name": "John",
#     "last_name": "Doe"
# }

    response = requests.post(url, json=payload, headers=headers)
    return response.json()

@app.route('/propsurance-application')
def propsurance_application():
    return render_template('home-main/propsurance_application.html')

@app.errorhandler(404)
def not_found(error):
    return render_template('home-main/404.html'), 404
    
@app.route('/dashboard/process_payment/', methods=['POST'])
@app.route('/dashboard/process_payment', methods=['POST'])
def process_payment():
    firm = request.form.get('firm')
    phase = request.form.get('phase')
    account_size = int(request.form.get('accountSize'))

    # Define payment URLs for each firm and phase
    urls = {
        'FTMO': {
            #  50k, 100k, 200k links
            'phase1': ['https://buy.stripe.com/test_eVa14meX6abj9ry4gi', 'https://buy.stripe.com/test_eVadR85mw5V31Z66ot', 'https://ftmo.com/phase1/200k'],
            'phase2': ['https://buy.stripe.com/test_28ofZg16g0AJgU0bIJ', 'https://buy.stripe.com/test_dR65kC02c97fcDK7sw', 'https://ftmo.com/phase2/200k'],
            'live': ['https://buy.stripe.com/test_8wM7sKg1a4QZavC6or', 'https://ftmo.com/live/100k', 'https://ftmo.com/live/200k']
        },
        '5ers': {
            'phase1': ['https://5ers.com/phase1/50k', 'https://5ers.com/phase1/100k', 'https://5ers.com/phase1/200k'],
            'phase2': ['https://5ers.com/phase2/50k', 'https://5ers.com/phase2/100k', 'https://5ers.com/phase2/200k'],
            'live': ['https://5ers.com/live/50k', 'https://5ers.com/live/100k', 'https://5ers.com/live/200k']
        },
        'LuxTrading': {
            'phase1': ['https://luxtrading.com/phase1/50k', 'https://luxtrading.com/phase1/100k', 'https://luxtrading.com/phase1/200k'],
            'phase2': ['https://luxtrading.com/phase2/50k', 'https://luxtrading.com/phase2/100k', 'https://luxtrading.com/phase2/200k'],
            'live': ['https://luxtrading.com/live/50k', 'https://luxtrading.com/live/100k', 'https://luxtrading.com/live/200k']
        }
    }

    redirect_url = urls[firm][phase][account_size - 1]  # Subtract 1 because list indices start at 0
    # print(redirect_url)
    return redirect(redirect_url)

@app.route("/callback", methods=["GET", "POST"])
def callback():
    try:
        # for development this is the following code:
        token = oauth.auth0.authorize_access_token()

        # for live this is the following code
        # token = oauth.proppatrol.authorize_access_token()
        
        user_info = {
            "email": token["userinfo"]["email"],
            "email_verified": token["userinfo"]["email_verified"]
        }

        # for development
        user = oauth.auth0.parse_id_token(token, nonce=session.get("nonce"))
        
        # for live
        # user = oauth.proppatrol.parse_id_token(token, nonce=session.get("nonce"))
        
        # Check if the user's email is in the allowed_users collection
        allowed_user_ref = db.collection('allowed_users').document(user['email'])
        allowed_user_doc = allowed_user_ref.get()
        allowed_user_doc_info = allowed_user_doc.to_dict()

        

        
        if allowed_user_doc.exists:
            # User is allowed, proceed with session creation and saving to users collection
            session["user"] = user_info
            coupon_code = allowed_user_doc_info.get('coupon_code', 'none')
            
            
            user_ref = db.collection('users').document(user['email'])
            user_check_exist = user_ref.get()
            
            if not user_check_exist.exists:
                # Create a new document in the 'users' collection if it does not exist
                user_ref.set({
                    'uid': user['sub'],  # Assuming 'sub' field contains UID
                    'email': user['email'],
                    'coupon_code': coupon_code,
                    'redeemed_coupon': False,
                    # Add other necessary user information as needed
                })
            
            return redirect(url_for('dashboard'))
        
        else:
            
            # check if affiliate exists
            allowed_affiliates_ref = db.collection('allowed_affiliates').document(user['email'])
            allowed_affiliates_doc =  allowed_affiliates_ref.get()
            allowed_affiliates_doc_info = allowed_affiliates_doc.to_dict()

            


            if allowed_affiliates_doc.exists:
                
                # affiliate is in database allowed_affiliates
                user_info_affiliate = {
            "email": token["userinfo"]["email"],
            "email_verified": token["userinfo"]["email_verified"],
            'is_affiliate': 'True'
        }
                session["user"] = user_info_affiliate
                

                affiliate_ref = db.collection('affiliates').document(user['email'])
                affiliate_check_exist = affiliate_ref.get()

                # user has never logged in so add his uid info
                if not affiliate_check_exist.exists:
                    affiliate_ref.set({
                         'uid': user['sub'],
                          'email': user['email'],
                          'coupon_code': allowed_affiliates_doc_info.get('coupon_code', ''),
                        'deposited_profit': 0,
                        'trade_shield_bronze_profit': 0,
                        'trade_shield_silver_profit': 0,
                        'trade_shield_gold_profit': 0,
                        'paypal_email': allowed_affiliates_doc_info.get('paypal_email', ''),
                        'country': allowed_affiliates_doc_info.get('country', ''),
                        'phone_number': allowed_affiliates_doc_info.get('phone_number', ''),
                        'users_who_added_coupon_via_dashboard': 0,
                        'is_valid': True,
                        'full_name': allowed_affiliates_doc_info.get('full_name', '')
                    })
                    return redirect(url_for("affiliate_login"))
                else:
                    return redirect(url_for("affiliate_login"))






            
            # If the user is not allowed, do not store in session or 'users' collection
            flash('You are not authorized to access this page.', 'error')
            return render_template('propsurance-dashboard/noaccess.html', error='You did not complete your PropSurance application, please contact us at support@proppatrol.net') # Redirect to a generic page or a denial information page

    except OAuthError as e:
        if 'access_denied' in str(e):
            # Handle specific case where access was denied
            return render_template('propsurance-dashboard/noaccess.html', error='You do not have access to PropSurance, please contact us at support@proppatrol.net'), 403
        else:
            # Handle other OAuth errors
            return render_template('propsurance-dashboard/noaccess.html', error='You do not have access to PropSurance, please contact us at support@proppatrol.net'), 403
        

@app.route("/affiliate-center/account-info")
@app.route("/affiliate-center/account-info/")
def affiliate_login_info():
    if 'user' not in session:
        return redirect(url_for("login"))
    
    else:

        user = session['user']
        is_affiliate = user.get('is_affiliate', False)
        affiliate_email = user['email']
        affiliate_data_site = {}

        if is_affiliate == 'True':
            # affiliate page so show form and user info

            try:
                affiliate_data = db.collection('affiliates').document(affiliate_email).get()
                # affiliate_data_info = db.collection('users').document(affiliate_email)

                if affiliate_data.exists:
                    temp_affiliate_data = affiliate_data.to_dict()
                    

                    affiliate_data_site = {
                    'full_name' : temp_affiliate_data.get('full_name', 'N/A'),
                    'country' : temp_affiliate_data.get('country', 'N/A'),
                    'paypal_email' : temp_affiliate_data.get('paypal_email', 'N/A'),
                    'user_email' : temp_affiliate_data.get('email', 'N/A')
                    }
            
            except Exception as err:
                pass
                # raise err

            return render_template('affiliate-dashboard/affiliate-info-showcase.html', dashboard_nav=True, affiliate_data_site=affiliate_data_site)


        else:
            return redirect(url_for("dashboard"))
    


@app.route("/affiliate-center/<affiliate_email_admin>")
@app.route("/affiliate-center/")
@app.route("/affiliate-center")
def affiliate_login(affiliate_email_admin=None):
    if 'user' not in session:
        return redirect(url_for("login"))

    else:
        user_info_affiliate = session.get("user")

        is_admin = False

        if user_info_affiliate['email'] == 'vortextemplates@gmail.com':
            is_admin = True

        if is_admin and not affiliate_email_admin == None:
            affiliate_email = affiliate_email_admin
        else:
            affiliate_email = user_info_affiliate['email']


        user = session['user']
        is_affiliate = user.get('is_affiliate', False)

        if is_affiliate == 'True' or is_admin:
            # this is the affilaite dashboard so stay here

            trade_shield_bronze_withdrawls = 0.00
            trade_shield_bronze_referrals = 0
            trade_shield_bronze_percentage = 0

            trade_shield_silver_withdrawls = 0.00
            trade_shield_silver_referrals = 0
            trade_shield_silver_percentage = 0


            trade_shield_gold_withdrawls = 0.00
            trade_shield_gold_referrals = 0
            trade_shield_gold_percentage = 0

            trade_shield_total_withdrawls = 0.00
            wallet_pending_withdrawls = 0.00
            
            affiliate_coupon_code = ''

            referral_count = 0
            has_referrals = False
            referrals_info = []
            current_referral_stage = 0

            hash_code = ''
            user_id = ''


            # affiliate_email = user.get('email')

            try:
                affiliate_data = db.collection('affiliates').document(affiliate_email).get()
                # affiliate_data_info = db.collection('users').document(affiliate_email)

                

                if affiliate_data.exists:
                    temp_affiliate_data = affiliate_data.to_dict()

                    hash_code = hmac.new(
  b'O7zzlQjAFoiHvWq2Hh6ORxbRR2O7CUH3H7pl6qh1', # an Identity Verification secret key (web)
  bytes(temp_affiliate_data['uid'], encoding='utf-8'), # a UUID to identify your user
  digestmod=hashlib.sha256 # hash function
).hexdigest()
            
                    user_id = temp_affiliate_data['uid']


                    affiliate_coupon_code =  temp_affiliate_data.get('coupon_code', 'none')
                    referral_count = temp_affiliate_data.get('referral_count', 0)

                    current_referral_stage = return_referral_stage(referral_count)


                    product_name_site = ''

                    if referral_count > 0:
                        has_referrals = True
                        purchases_ref = db.collection('affiliates').document(affiliate_email).collection('purchases')
                        purchases = purchases_ref.stream()

                        

                        for purchase in purchases:             
                            purchase_data = purchase.to_dict()
                            # print(purchase_data)
                            purchase_data = purchase.to_dict()
                            # print(purchase_data)  # Print the purchase data to verify

                            # Check for the trade shield type and count up the withdrawals
                            purchase_amount = float(purchase_data.get('referral_commission_amount', 0.00))

                            if not purchase_data.get('user_refunded', True):
                                if purchase_data.get('affiliate_paid', False):
                                    trade_shield_total_withdrawls += purchase_amount
                                else:
                                    # affiliate not paid so put in balance
                                    wallet_pending_withdrawls += purchase_amount

                            product_name = purchase_data.get('product_name', '')
                            if product_name == 'trade-shield-bronze':
                                if not purchase_data.get('user_refunded', True):
                                    if purchase_data.get('affiliate_paid', False):
                                        trade_shield_bronze_withdrawls += purchase_amount
                                
                                product_name_site = 'Trade-Shield Bronze'
                                trade_shield_bronze_referrals += 1


                            elif product_name == 'trade-shield-silver':
                                if not purchase_data.get('user_refunded', True):
                                    if purchase_data.get('affiliate_paid', False):
                                        trade_shield_silver_withdrawls += purchase_amount

                                
                                product_name_site = 'Trade-Shield Silver'
                                trade_shield_silver_referrals += 1

                            elif product_name == 'trade-shield-gold':
                                if not purchase_data.get('user_refunded', True):
                                    if purchase_data.get('affiliate_paid', False):
                                        trade_shield_gold_withdrawls += purchase_amount
                                
                                product_name_site = 'Trade-Shield Gold'
                                trade_shield_gold_referrals += 1

                            purchase_id = purchase_data.get('purchase_id', '')
                            formatted_purchase_id = '*' * (len(purchase_id) - 7) + purchase_id[-7:]

                            referral_info = {
                        'two_weeks_after_purchase_date': purchase_data.get('2_weeks_after_purchase_date', ''),
                        'current_referral_count': purchase_data.get('current_referral_count', 0),
                        'affiliate_paid': purchase_data.get('affiliate_paid', False),
                        'referral_commission_amount': f"{purchase_amount:.2f}",
                        'product_name': product_name_site,
                        'purchase_id': formatted_purchase_id,
                       'user_refunded': purchase_data.get('user_refunded', True)
                    }
                            referrals_info.append(referral_info)

                        trade_shield_bronze_percentage = round((trade_shield_bronze_referrals / referral_count) * 100)
                        trade_shield_silver_percentage = round((trade_shield_silver_referrals / referral_count) * 100)
                        trade_shield_gold_percentage = round((trade_shield_gold_referrals / referral_count) * 100)

    
            except Exception as err:
                raise err
                # pass

            

            

            affiliate_account_info = {
                'trade_shield_bronze_withdrawls': trade_shield_bronze_withdrawls,
                'trade_shield_bronze_percentage': trade_shield_bronze_percentage,
                'trade_shield_bronze_referrals': trade_shield_bronze_referrals,

                'trade_shield_silver_withdrawls': trade_shield_silver_withdrawls,
                'trade_shield_silver_percentage': trade_shield_silver_percentage,
                'trade_shield_silver_referrals': trade_shield_silver_referrals,


                'trade_shield_gold_withdrawls': trade_shield_gold_withdrawls,
                'trade_shield_gold_percentage': trade_shield_gold_percentage,
                'trade_shield_gold_referrals': trade_shield_gold_referrals,

                'trade_shield_total_withdrawls': trade_shield_total_withdrawls,
                'wallet_pending_withdrawls': wallet_pending_withdrawls,

                'referral_count': referral_count,
                'current_referral_stage': current_referral_stage,

                'has_referrals': has_referrals,

                'affiliate_coupon_code': affiliate_coupon_code,

                'referrals_data': referrals_info
            }           

            
            return render_template('affiliate-dashboard/affiliate-dashboard.html', dashboard_nav=True, affiliate_account_info=affiliate_account_info, hash_code=hash_code, user_id=user_id, affiliate_email=affiliate_email )
        
        

        else:
            return redirect(url_for("dashboard"))


@app.route("/login")
def login():
     # live  mode
    # return oauth.proppatrol.authorize_redirect(
    #    
        
    #     redirect_uri=url_for("https://www.proppatrol.net/callback")

    # )


    return oauth.auth0.authorize_redirect(
        # local host for development
        redirect_uri=url_for("callback", _external=True)
    )
    
# for all auth routes make it direct url
@app.route("/logout")
def logout():
    session.clear()
    # for live mode
    # return redirect(
    #     "https://dev-ct0rwl0778orlwvk.us.auth0.com/v2/logout?"
    #     + urlencode(
    #         {
    #             # for development make it local host
    #             "returnTo": ("https://www.proppatrol.net/"),
    #             "client_id": 'qA5AwBA91VxeHowQQu6MDKOBYHWbWbmx',
    #         },
    #         quote_via=quote_plus,
    #     )
    # )

    # for development

    return redirect(
            "https://dev-ct0rwl0778orlwvk.us.auth0.com/v2/logout?"
            + urlencode(
                {
                    # for development is the following
                    "returnTo": url_for("home", _external=True),
                    "client_id": 'sX97fU3VZlMQhuV4aoqaH4lAMNLtJ2rP',
                },
                quote_via=quote_plus,
            )
        )

@app.route('/dashboard/faq/', methods=['GET'])
@app.route('/dashboard/faq', methods=['GET'])
def dashboard_faq():
    if 'user' not in session:
        return redirect(url_for("login"))
    else:
        user = session['user']
        is_affiliate = user.get('is_affiliate', False)

        if is_affiliate == 'True':
            # redirect to affiliate page
            return redirect(url_for("affiliate_login"))
        
        return render_template("propsurance-dashboard/faq-dashboard.html",dashboard_nav=True)

    
        
    


@app.route('/dashboard/terms-of-service/', methods=['GET'])
@app.route('/dashboard/terms-of-service', methods=['GET'])
def propsurance_service():
    if 'user' not in session:
        return redirect(url_for("login"))
    else:
        user = session['user']
        is_affiliate = user.get('is_affiliate', False)

        if is_affiliate == 'True':
            # redirect to affiliate page
            return redirect(url_for("affiliate_login"))
        
        return render_template("propsurance-dashboard/terms-propsurance.html",dashboard_nav=True)

   
        

@app.route('/dashboard/privacy-policy/', methods=['GET'])
@app.route('/dashboard/privacy-policy', methods=['GET'])
def propsurance_terms():
    if 'user' not in session:
        return redirect(url_for("login"))
    else:
        user = session['user']
        is_affiliate = user.get('is_affiliate', False)

        if is_affiliate == 'True':
            # redirect to affiliate page
            return redirect(url_for("affiliate_login"))
        
        return render_template("propsurance-dashboard/privacy-propsurance.html",dashboard_nav=True)

    
        
 

@app.route('/dashboard/raise-ticket/<int:account_count>', methods=['GET'])
def access_ticket_handler(account_count):
    if 'user' not in session:
        return redirect(url_for("login"))
    else:
        user = session['user']
        is_affiliate = user.get('is_affiliate', False)

        if is_affiliate == 'True':
            # redirect to affiliate page
            return redirect(url_for("affiliate_login"))
    
    user_info = session.get("user")
    user_email = user_info['email']
    user_data = db.collection('users').document(user_email).get()
    first_name = ''
    account = {}

    hash_code = 0
    user_id = 0

    try:
        user_email = user_info['email']
        # user_validated_email = user_info["email_verified"]
        user_data = db.collection('users').document(user_email).get()
        user_data_info = db.collection('users').document(user_email)
        accounts_collection = ''
        if user_data.exists:

            user_data_dict = user_data.to_dict()
            customer_name = user_data_dict['user_name']
            accounts_collection = db.collection('users').document(user_email).collection('accounts_info')

            hash_code = hmac.new(
  b'O7zzlQjAFoiHvWq2Hh6ORxbRR2O7CUH3H7pl6qh1', # an Identity Verification secret key (web)
  bytes(user_data_dict['uid'], encoding='utf-8'), # a UUID to identify your user
  digestmod=hashlib.sha256 # hash function
).hexdigest()
            
            user_id = user_data_dict['uid']

        # Fetch all documents within the accounts_info subcollection
            accounts_documents = accounts_collection.document(f'account_info_{str(account_count)}').get()
            # for account_doc in accounts_documents:
            account_info = accounts_documents.to_dict()
            
            account_id = account_info['propsurance_count']
            
            account_stage = ''

            trader_info_collection = user_data_info.collection('trader_info')
            
                            
            account_info_data =  account_info
            current_index = account_info_data['propsurance_count']
        
            trader_info_data = trader_info_collection.document(f"trader_account_{account_count}").get()
            trader_info_data_parsed = trader_info_data.to_dict()
            
            if trader_info_data_parsed.get('account_status', '') == 'phase1':
                account_stage = 'Phase 1'
            elif trader_info_data_parsed.get('account_status', '') == 'phase2':
                account_stage = 'Phase 2'
            elif trader_info_data_parsed.get('account_status', '') == 'phase3':
                account_stage = 'Phase 2'    
            else:
                account_stage = 'Live'
            
            account_access_url = url_for('submit_mt_account', account=current_index)

            account = {
                'id': str(current_index),
                'name': trader_info_data_parsed.get('prop_firm_name'),
                'investor_id': trader_info_data_parsed.get('investor_id', ''),
                'investor_password': trader_info_data_parsed.get('investor_password', ''),
                'status': account_info.get('status', ''),
                'account_size': str(trader_info_data_parsed.get('account_size', '')),
                'server': account_info.get('server', ''),
                'server_type': account_info.get('trading_account_type', ''),
                'account_stage': account_stage,
                'account_access_url': account_access_url,
                'current_rate': account_info.get('current_rate', '40%'),
                'customer_name' : customer_name,
                'email': user_email
            }

            # print(accounts)
                                    
    except Exception  as err:
        # user has no account
        # pass
        raise err

    return render_template("propsurance-dashboard/ticket_handler.html", account_info=account, prop_count=account_count,dashboard_nav=True, hash_code=hash_code,user_id=user_id)

#  add coupon to user if they do not have one
@app.route('/dashboard/add-coupon', methods=['GET', 'POST'])
@app.route('/dashboard/add-coupon/', methods=['GET', 'POST'])
def create_coupon():
    if 'user' not in session:
        return redirect(url_for("login"))
    else:
        user = session['user']
        is_affiliate = user.get('is_affiliate', False)

        if is_affiliate == 'True':
            # redirect to affiliate page
            return redirect(url_for("affiliate_login"))

    allowed_to_add= True
    allowed_to_redeem = ''
    coupon_code = ''
    user_info = session.get("user")
    user_email = user_info['email']
    user_data = db.collection('users').document(user_email).get()
    

    try:
        user_email = user_info['email']
        # user_validated_email = user_info["email_verified"]
        user_data = db.collection('users').document(user_email).get()

        if user_data.exists:
            user_data_dict = user_data.to_dict()

            coupon_code  =  user_data_dict.get('coupon_code', 'none')
            allowed_to_redeem = not user_data_dict['redeemed_coupon']


            if coupon_code != 'none':
                allowed_to_add = True

        
    except Exception  as err:
        # user has no account
        pass
    
    if request.method == 'POST':

        updated_coupon_code = request.form.get('coupon_code')
        updated_coupon_code = updated_coupon_code.upper()

        # coupon_data = db.collection('affiliates').document(updated_coupon_code).get()
        coupon_data_ref = db.collection("affiliates").where("coupon_code", "==", updated_coupon_code).get()
        current_user_email = request.form.get('user_email')
        if not coupon_data_ref:
            flash("Invalid coupon code", "error")

        else:
   
            
            affiliate_data = coupon_data_ref[0].to_dict()
            # update affiliate tracking

            amount_of_traders_who_added_coupon = affiliate_data['users_who_added_coupon_via_dashboard']
            amount_of_traders_who_added_coupon_new = amount_of_traders_who_added_coupon + 1
            coupon_code_is_valid = affiliate_data['is_valid']
            affiliate_email = affiliate_data['email']

            if not coupon_code_is_valid:
                flash("Invalid coupon code", "error")
                return render_template("propsurance-dashboard/create_coupon.html", coupon_code=coupon_code, allowed_to_redeem=allowed_to_redeem, allowed_to_add=allowed_to_add, dashboard_nav=True )
            
            else:
                db.collection('affiliates').document(affiliate_email).update({
        'users_who_added_coupon_via_dashboard': amount_of_traders_who_added_coupon_new
    })
                db.collection('users').document(user_email).update({
        'coupon_code': updated_coupon_code
    })
                flash("Coupon code applied successfully!", "success")
                return redirect(url_for('create_coupon'))
            

    return render_template("propsurance-dashboard/create_coupon.html", user_email=user_email, coupon_code=coupon_code, allowed_to_redeem=allowed_to_redeem, allowed_to_add=allowed_to_add, dashboard_nav=True )




# process the payment to a custom session
@app.route('/dashboard/verify-payment', methods=['POST'])
def verify_payment():
    # print(request.form)
    
    drawdown_coverage_add_on_silver = request.form.get('add-on-silver', False)
    drawdown_coverage_add_on_gold= request.form.get('add-on-gold', False)
    current_phase =  request.form.get('current_phase', '')
    email = request.form.get('user_email')
    plan_type = request.form.get('plan_type')
    firm_name = request.form.get('firm', 'none')
    coupon_code = request.form.get('coupon_code', 'none')
    price_plan = ''
    price_firm = ''
    price_num = 0
    plan_name = ''
    service_type = ''
    price_id = ''
    account_size = request.form.get('account_size', '')
    account_platform = request.form.get('account_type', '')
    promotion_valid = False
    got_add_on_0 = False
    allowed_to_redeem = False


    if not coupon_code  == 'none':
        promotion_valid = True
    
    if drawdown_coverage_add_on_silver == 'on' and current_phase == 'phase2':
        return jsonify(status='error', message=f"Please try again!"), 500
    if drawdown_coverage_add_on_gold == 'on' and current_phase == 'phase2':
        return jsonify(status='error', message=f"Please try again!"), 500
        
    
    if plan_type == 'trade-shield-bronze':
        if firm_name == 'ftmo':
            price_firm = 'FTMO' 
        elif firm_name == 'alpha_capital':
            price_firm = 'Alpha Capital Group'
        else:
            return jsonify(status='error', message=f"Please try again!"), 500
        

        if current_phase == 'phase1':
            # test id
            price_id = 'price_1PFPnVP649Efo4kC3NkEvBfr'
            price_num = '79'
        elif current_phase == 'phase2':
            # test price id
            price_id = 'price_1PDNMWP649Efo4kCfQL0w9RM'
            price_num = '89'
        else:
            return jsonify(status='error', message=f"Please try again!"), 500
        
        
        service_type = 'one-time'
    
    elif plan_type == 'trade-shield-silver':
        if firm_name == 'ftmo':
            price_firm = 'FTMO' 
        elif firm_name == 'alpha_capital':
            price_firm = 'Alpha Capital Group'
        else:
            return jsonify(status='error', message=f"Please try again!"), 500
        
        if current_phase == 'phase1' and drawdown_coverage_add_on_silver == 'on':
            # for phase 1 but with add on for test
            price_id = 'price_1PFQpnP649Efo4kCVWXF1FIR'
            price_num = '269'    
            # got_add_on_0 = True

        elif current_phase == 'phase1' and not drawdown_coverage_add_on_silver:
            # for phase 1 with no add on 
            price_id = 'price_1PFQpnP649Efo4kCQLWfb0WM'
            price_num = '179'
        
        elif current_phase == 'phase2':
            # for phase 1 and 
            price_id = 'price_1PFQpnP649Efo4kCOJK3kK7y'
            price_num = '209'
        else:
            return jsonify(status='error', message=f"Please try again!"), 500
         

        price_num = '179'
        service_type = 'one-time'

    elif plan_type == 'trade-shield-gold':
        if firm_name == 'ftmo':
            price_firm = 'FTMO' 
        elif firm_name == 'alpha_capital':
            price_firm = 'Alpha Capital Group'
        else:
            return jsonify(status='error', message=f"Please try again!"), 500
        
        if current_phase == 'phase1' and drawdown_coverage_add_on_gold == 'on':
            # for phase 1 but with add on for test
            price_id = 'price_1PGDrOP649Efo4kCNYHSej2F'
            price_num = '509'    
            # got_add_on_0 = True

        elif current_phase == 'phase1' and not drawdown_coverage_add_on_gold:
            # for phase 1 with no add on 
            price_id = 'price_1PGDnyP649Efo4kCV3wLr3wp'
            price_num = '399'

        elif current_phase == 'phase2':
            # for phase 1 and 
            price_id = 'price_1PGDsSP649Efo4kCUbSRCxxd'
            price_num = '459'
        
        else:
            return jsonify(status='error', message=f"Please try again!"), 500
        

        price_num = '399'
        service_type = 'one-time'

    else:
        return jsonify(status='error', message=f"Please try again!"), 500
    
    

    try:
        # Create a new Checkout Session for the order
        # For demonstration purposes, we use a hard-coded amount and currency
        
        user_data = db.collection('users').document(email).get()
        

        if user_data.exists:

            user_data = user_data.to_dict()

            allowed_to_redeem = not user_data['redeemed_coupon']
            # coupon_code  =  user_data.get('coupon_code', 'none')


        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='payment',
              # Enable the use of promotion codes
            billing_address_collection='required',  # Require a billing address
            success_url=url_for('success_payment', _external=True),
            cancel_url=url_for('cancel_payment', _external=True),
            automatic_tax={'enabled': True},
            discounts= [{'coupon': 'UNnQzyHW'}] if allowed_to_redeem and promotion_valid else [],
            customer_email = email,
           
             metadata={
                'customer_email': email,  # Custom data
                'coupon_code' : coupon_code,
                'allowed_to_redeem' : allowed_to_redeem,
                'firm_name': price_firm,
                'phase': 'phase1',
                'price': price_num,
                'plan_name': plan_type,
                'account_size': account_size,
                'plan_type': 'paid',
                'trading_platform': account_platform,
                'got_add_on0': got_add_on_0,
                'promotion_valid': promotion_valid
            },
            phone_number_collection={'enabled': True}
        )
        
    except Exception as e:
        return jsonify(status='error', message=f"Please try again!"), 500
    
    
    return   jsonify(status='success', redirect_url=session.url), 303

@app.route('/successful-payment')
def success_payment():
    # return payment work and return to dashboard
    return 'payment worked'

@app.route('/canceled-payment')
def cancel_payment():
    # payment was canceled return to dashboard
    return 'cancel payment'

    

@app.route('/dashboard/user/<int:account_count>', methods=['GET'])
def access_account_dashboard(account_count):
    if 'user' not in session:
        return redirect(url_for("login"))
    else:
        user = session['user']
        is_affiliate = user.get('is_affiliate', False)

        if is_affiliate == 'True':
            # redirect to affiliate page
            return redirect(url_for("affiliate_login"))
    
    user_info = session.get("user")
    user_email = user_info['email']
    user_data = db.collection('users').document(user_email).get()
    first_name = ''
    account = {}
    product_name = ''
    plan_is_not_free = True
    add_on_1_allowed = add_on_1_allowed_base

    try:
        user_email = user_info['email']
        user_validated_email = user_info["email_verified"]
        user_data = db.collection('users').document(user_email).get()
        user_data_info = db.collection('users').document(user_email)
        accounts_collection = ''
        if user_data.exists:

            user_data_dict = user_data.to_dict()
            name = user_data_dict['user_name']
            first_name = user_data_dict['first_name']
            accounts_collection = db.collection('users').document(user_email).collection('accounts_info')

        # Fetch all documents within the accounts_info subcollection
            accounts_documents = accounts_collection.document(f'account_info_{str(account_count)}').get()
            # for account_doc in accounts_documents:
            account_info = accounts_documents.to_dict()
            
            account_id = account_info['propsurance_count']
            
            account_stage = ''

            trader_info_collection = user_data_info.collection('trader_info')
            
                            
            account_info_data =  account_info
            current_index = account_info_data['propsurance_count']
        
            trader_info_data = trader_info_collection.document(f"trader_account_{account_count}").get()
            trader_info_data_parsed = trader_info_data.to_dict()
            
            if trader_info_data_parsed.get('account_status', '') == 'phase1':
                account_stage = 'Phase 1'
            elif trader_info_data_parsed.get('account_status', '') == 'phase2':
                account_stage = 'Phase 2'
            elif trader_info_data_parsed.get('account_status', '') == 'phase3':
                account_stage = 'Phase 2'    
            else:
                account_stage = 'Live'

            plan_type = trader_info_data_parsed.get('product_name', '')
            
            trade_status = ''
            insured_date = account_info_data.get('insured_date')
            failed_account = trader_info_data_parsed.get('failed_account', '')

            got_add_on0 = trader_info_data_parsed.get('got_add_on0', False)
            

            # add 1 week for the refund date
            temp_date = datetime.strptime(insured_date, "%Y-%m-%d")

            new_date = temp_date + timedelta(days=7)

            new_refund_date_string = new_date.strftime("%Y-%m-%d")

            if trader_info_data_parsed.get('product_name', '') == 'trade-shield-bronze':
                product_name = 'Trade-Shield Bronze'
                
            elif trader_info_data_parsed.get('product_name', '') == 'trade-shield-silver':
                product_name = 'Trade-Shield Silver'
                
            elif trader_info_data_parsed.get('product_name', '') == 'trade-shield-gold':
                product_name = 'Trade-Shield Gold'
            elif trader_info_data_parsed.get('product_name', '') == 'Denied Payout Coverage':
                product_name = 'Denied Payout Coverage'
                plan_is_not_free = False

            
            account_access_url = url_for('submit_mt_account', account=current_index)

            account = {
                'id': str(current_index),
                'name': trader_info_data_parsed.get('prop_firm_name'),
                'investor_id': trader_info_data_parsed.get('investor_id', ''),
                'investor_password': trader_info_data_parsed.get('investor_password', ''),
                'status': account_info.get('status', ''),
                'account_size': str(trader_info_data_parsed.get('account_size', '')),
                'server': account_info.get('server', ''),
                'server_type': account_info.get('trading_account_type', ''),
                'invoice_url' : account_info_data.get('invoice_url', ''),
                'account_stage': account_stage,
                 'failed_account' : failed_account,
                'account_access_url': account_access_url,
                'product_name': product_name,
                'current_rate': account_info.get('current_rate', '40%'), 
                'insured_date': trader_info_data_parsed.get('insured_date', ''),
                'plan_is_not_free': plan_is_not_free,
                 'got_add_on0': got_add_on0,
                 'plan_type_check': account_info_data.get('plan_type', ''),
                 'current_payouts': trader_info_data_parsed.get('current_payouts', 0)
            }

            # print(accounts)
                                    
    except Exception  as err:
        pass
        # raise err

    return render_template("propsurance-dashboard/user_dashboard.html", account_info=account, prop_count=account_count, has_first_name=True, first_name=first_name, dashboard_nav=True, add_on_1_allowed=add_on_1_allowed)

@app.route('/dashboard/new-coverage-free', methods=['GET', 'POST'])
@app.route('/dashboard/new-coverage-free/', methods=['GET', 'POST'])
def submit_mt_account_free():
    if 'user' not in session:
        return redirect(url_for("login"))
    else:
        user = session['user']
        is_affiliate = user.get('is_affiliate', False)

        if is_affiliate == 'True':
            # redirect to affiliate page
            return redirect(url_for("affiliate_login"))
    
    
    user_info = session.get("user")
    user_email = user_info['email']
    user_name = ''
    user_name_valid = False
    account_percentage = 0
    account_size = 0
    remaining_size = 50000
    hash_code = 0
    user_id = 0

    try:
        user_data = db.collection('users').document(user_email).get()
        user_data_info = db.collection('users').document(user_email) 
        
        if user_data.exists:
            user_data_dict = user_data.to_dict()
            user_has_name = user_data_dict.get('user_name')

            

            hash_code = hmac.new(
  b'O7zzlQjAFoiHvWq2Hh6ORxbRR2O7CUH3H7pl6qh1', # an Identity Verification secret key (web)
  bytes(user_data_dict['uid'], encoding='utf-8'), # a UUID to identify your user
  digestmod=hashlib.sha256 # hash function
).hexdigest()
            
            user_id = user_data_dict['uid']
            
            

            if user_has_name:
                user_name_valid = True
                user_name = user_has_name
            
            
                accounts_collection = user_data_info.collection('accounts_info').get()
                trader_info_collection = user_data_info.collection('trader_info') 
                # # print(accounts_collection)
                if accounts_collection:
                    # # print( 'here 270')
                    for account in accounts_collection:
                        # # print('here line 270')
                        product_name = ''
                        show_percent = ''
                        
                        account_info_data =  account.to_dict()
                        current_index = account_info_data['propsurance_count']
                        
                        trader_info_data = trader_info_collection.document(f"trader_account_{current_index}").get()
                        trader_info_data_parsed = trader_info_data.to_dict()
                        plan_type = account_info_data.get('plan_type', '')
                        if  plan_type == 'free':
                            
                            account_size += trader_info_data_parsed.get('account_size')
                                
                            
                           
                            

                    
                    account_percentage = int((account_size / 50000) * 100)
                    remaining_size = 50000 - account_size        

            
                    
        
    except Exception  as err:
        raise err
    
    if request.method == 'POST':
        accounts_count = free_coverage_update_trader_info(request.form['user_email'], request.form['user_name'], request.form)
        free_coverage_update_accounts_info(request.form['user_email'], request.form['user_name'], request.form)
        send_email('support@proppatrol.net',  'live-account-connection', {"user_email":request.form['user_email'] } )

        return redirect(url_for('submit_mt_account',account=accounts_count))


    
    return render_template('product-templates/new-free-coverage.html', user_email=user_email, user_name_valid=user_name_valid, user_name=user_name, dashboard_nav=True ,remaining_size= remaining_size, hash_code=hash_code, user_id=user_id)
    
            
        
            

@app.route('/dashboard/validate/<int:account>', methods=['GET', 'POST'])
def submit_mt_account(account):
    # Check if user is authenticated
    if 'user' not in session:
        return redirect(url_for("login"))
    else:
        user = session['user']
        is_affiliate = user.get('is_affiliate', False)

        if is_affiliate == 'True':
            # redirect to affiliate page
            return redirect(url_for("affiliate_login"))
    
    user_info = session.get("user")
    user_email = user_info['email']
    user_data = db.collection('users').document(user_email).get()
    accounts = {}
    hash_code = ''
    user_id = ''

    try:
        user_email = user_info['email']
        user_validated_email = user_info["email_verified"]
        user_data = db.collection('users').document(user_email).get()
        user_data_info = db.collection('users').document(user_email)
        accounts_collection = ''

        

        if user_data.exists:
            user_data_dict = user_data.to_dict()
            accounts_collection = db.collection('users').document(user_email).collection('accounts_info')
            customer_name = user_data_dict['user_name']
        # Fetch all documents within the accounts_info subcollection
            accounts_documents = accounts_collection.document(f'account_info_{str(account)}').get()
            # for account_doc in accounts_documents:
            account_info = accounts_documents.to_dict()

            hash_code = hmac.new(
  b'O7zzlQjAFoiHvWq2Hh6ORxbRR2O7CUH3H7pl6qh1', # an Identity Verification secret key (web)
  bytes(user_data_dict['uid'], encoding='utf-8'), # a UUID to identify your user
  digestmod=hashlib.sha256 # hash function
).hexdigest()
            
            user_id = user_data_dict['uid']

           
            current_free_coverage = False
            
            account_id = account_info['propsurance_count']

            
            account_stage = ''

            trader_info_collection = user_data_info.collection('trader_info')
            
                            
            account_info_data =  account_info
            current_index = account_info_data['propsurance_count']
        
            trader_info_data = trader_info_collection.document(f"trader_account_{account}").get()
            trader_info_data_parsed = trader_info_data.to_dict()
            
            if trader_info_data_parsed.get('account_status', '') == 'phase1':
                account_stage = 'Phase 1'
            elif trader_info_data_parsed.get('account_status', '') == 'phase2':
                account_stage = 'Phase 2'
            else:
                account_stage = 'Live'

            if account_info['plan_type'] == 'free':
                current_free_coverage = True
                
            
            

            accounts = {
                'id': str(current_index),
                'name': trader_info_data_parsed.get('prop_firm_name'),
                'investor_id': trader_info_data_parsed.get('investor_id', ''),
                'investor_password': trader_info_data_parsed.get('investor_password', ''),
                'status': account_info.get('status', ''),
                'account_size': str(trader_info_data_parsed.get('account_size', '')),
                'server': account_info.get('server', ''),
                'server_type': trader_info_data_parsed.get('trading_platform', ''),
                'account_stage': account_stage,
                'customer_name': customer_name ,
                'date': trader_info_data_parsed.get('insured_date', ''),
                'current_free_coverage': current_free_coverage
            }

            # print(accounts)
                                    
    except Exception  as err:
        pass
        # raise err

    # POST request handling
    if request.method == 'POST':
        try:
            # Extract data from form
            mt_account = request.form['server_type']
            password = request.form['password']
            server = request.form['server']
            investor_id = request.form['mt_account']
            # prop_count = request.form['prop_count']

            

            trader_collection = db.collection('users').document(user_email).collection('trader_info')
            trader_ref = trader_collection.document(f'trader_account_{str(account)}')
            
            
            # Get a reference to the specific account document
            account_ref = db.collection('users').document(user_email).collection('accounts_info').document(f'account_info_{account}')
            account_info = account_ref.get()

            
            
            if account_info.exists:
                account_data = account_info.to_dict()
                # Only update if the current status is 'pending'\
                
                if account_data.get('status') == 'pending':
                    update_data = {
                        'status': 'needs_validation',  # Update status to needs validation
                        'server': server,              # Update server information
                    }
                    trader_data = {
                         'investor_id': investor_id,
                         'investor_password': password
                    }

                    account_ref.update(update_data)
                    trader_ref.update(trader_data)
                    send_email(user_email,  'validation-confirmation', {} )
                    flash('Account updated successfully and is awaiting validation.')
                else:
                    flash('Account is not in a pending state and cannot be updated.')
            else:
                flash('Account information could not be found.')

        except Exception as err:
            # Provide a generic error message to the user
            pass
            # raise err
            # flash('Error updating account information. Please try again.')
            # Log the specific error internally
            # print(f"Error updating account information: {err}")

        # Redirect back to the same page to potentially show updated data or messages
        return redirect(url_for('submit_mt_account', account=account))

    return render_template("propsurance-dashboard/validate_trader_info.html", accounts=accounts, prop_count=account, dashboard_nav=True, hash_code=hash_code, user_id=user_id)




@app.route("/dashboard/")
@app.route("/dashboard")
@app.route("/dashboard/<url_email>")
def dashboard(url_email=None):
    # Check if user is authenticated
    if 'user' not in session:
        return redirect(url_for("login"))
    else:
        user = session['user']
        is_affiliate = user.get('is_affiliate', False)

        if is_affiliate == 'True':
            # redirect to affiliate page
            return redirect(url_for("affiliate_login"))
    

    user_info = False
    user_data = False
    user_validated_email = 0
    user_info = session.get("user")
    is_admin = False

    if user_info['email'] == 'vortextemplates@gmail.com':
        is_admin = True



    uid = 0
    # user info
    user_email = 0
    user_name = 0
    num_of_accounts = 0
    account_size =0
    account_percentage = 0
    remaining_size = ''
    insured_accounts = []
    hash_code = 0
    user_id = 0
    allowed_to_redeem = ''
    coupon_code = ''
    add_on_1_allowed = add_on_1_allowed_base

    

    account_insured = False

    # for live  keep uncommented
    # token = oauth.proppatrol.authorize_access_token()
    #  only for live
    # user_info_full = token



    try:
        if is_admin and not url_email == None:
            user_email = url_email
        else:
            user_email = user_info['email']

        
        
        user_validated_email = user_info["email_verified"]
        user_data = db.collection('users').document(user_email).get()
        user_data_info = db.collection('users').document(user_email)

        if user_data.exists:

            user_data = user_data.to_dict()

            allowed_to_redeem = not user_data['redeemed_coupon']
            coupon_code  =  user_data.get('coupon_code', 'none')
            updated_coupon_code = coupon_code.upper()

            # coupon_data = db.collection('affiliates').document(updated_coupon_code).get()
            
            
            if allowed_to_redeem:
                coupon_data_ref = db.collection("affiliates").where("coupon_code", "==", updated_coupon_code).get()
                current_user_email =user_email

                if not coupon_data_ref:
                    # affiliate doesnt exist
                    db.collection('users').document(current_user_email).update({
                'coupon_code': 'none'
            })

                else:
        
                    
                    affiliate_data = coupon_data_ref[0].to_dict()
                    # update affiliate tracking

                    
                    coupon_code_is_valid = affiliate_data['is_valid']
                    affiliate_email = affiliate_data['email']
                    
                    if not coupon_code_is_valid:
                        db.collection('users').document(current_user_email).update({
                'coupon_code': 'none'
            })
                    
                    
            

            hash_code = hmac.new(
  b'O7zzlQjAFoiHvWq2Hh6ORxbRR2O7CUH3H7pl6qh1', # an Identity Verification secret key (web)
  bytes(user_data['uid'], encoding='utf-8'), # a UUID to identify your user
  digestmod=hashlib.sha256 # hash function
).hexdigest()
            
            user_id = user_data['uid']

            # check here that if user has coupon_code, then verify if coupon_code is valid if its not then make it 'none
            if int(user_data.get('accounts_info_count')) >= 0:
                    accounts_collection = user_data_info.collection('accounts_info').get()
                    trader_info_collection = user_data_info.collection('trader_info')
                    num_of_accounts = user_data['accounts_info_count'] + 1
                    first_name = user_data['first_name']
                    account_insured = True   
                    # # print(accounts_collection)
                    if accounts_collection:
                        # # print( 'here 270')
                        for account in accounts_collection:
                            # # print('here line 270')
                            product_name = ''
                            show_percent = ''
                            
                            account_info_data =  account.to_dict()
                            current_index = account_info_data['propsurance_count']
                            
                            trader_info_data = trader_info_collection.document(f"trader_account_{current_index}").get()
                            trader_info_data_parsed = trader_info_data.to_dict()
                            # # print('line 275', account_info_data)
                            plan_type = trader_info_data_parsed.get('product_name', '')
                            if  plan_type == 'Denied Payout Coverage':
                                account_size += trader_info_data_parsed.get('account_size')
                            trade_status = ''
                            insured_date = account_info_data.get('insured_date')
                            failed_account = trader_info_data_parsed.get('failed_account', '')

                            got_add_on0 = trader_info_data_parsed.get('got_add_on0', False)
                           

                            # add 1 week for the refund date
                            temp_date = datetime.strptime(insured_date, "%Y-%m-%d")

                            new_date = temp_date + timedelta(days=7)

                            new_refund_date_string = new_date.strftime("%Y-%m-%d")

                            if trader_info_data_parsed.get('product_name', '') == 'trade-shield-bronze':
                                product_name = 'Trade-Shield Bronze'
                                show_percent = False
                            elif trader_info_data_parsed.get('product_name', '') == 'trade-shield-silver':
                                product_name = 'Trade-Shield Silver'
                                show_percent = False
                            elif trader_info_data_parsed.get('product_name', '') == 'trade-shield-gold':
                                product_name = 'Trade-Shield Gold'
                                show_percent = False
                            elif trader_info_data_parsed.get('product_name', '') == 'Denied Payout Coverage':
                                product_name = 'Denied Payout Coverage'
                                show_percent = True

                            
                            


                            if trader_info_data_parsed.get('account_status') == 'phase2':
                                trade_status = 'Phase 2'
                            elif trader_info_data_parsed.get('account_status') == 'phase1':
                                trade_status = 'Phase 1'
                            else:
                                trade_status = 'Live Account'
                            
                            # # print(trader_info_data_parsed.get('prop_firm_name'), 'line 286')
                            prop_firm_info = {
                            'name': trader_info_data_parsed['prop_firm_name'],
                            'account_size' : trader_info_data_parsed['account_size'],
                            'invoice_url' : account_info_data.get('invoice_url', ''),
                            'account_url_fix' : str(current_index),
                            'account_status':  account_info_data.get('status'),
                            'phase_status' : trade_status,
                            'current_percentage': int((trader_info_data_parsed['account_size'] / 50000) * 100),
                            'current_size': trader_info_data_parsed['account_size'],
                            'refund_date': new_refund_date_string,
                            'failed_account' : failed_account,
                            'product_name': product_name,
                            'show_percent': show_percent,
                            'got_add_on0': got_add_on0,
                            'insured_date': trader_info_data_parsed.get('insured_date', ''),
                            'plan_type_check': account_info_data.get('plan_type', '')
                            }
                            

                            # print(account_info_data)

                            insured_accounts.append(prop_firm_info)

                    
                    account_percentage = int((account_size / 50000) * 100)
                    remaining_size = 50000 - account_size        

            else: 
                return render_template("propsurance-dashboard/dashboard.html", session=user_info, user_email=user_email, user_validated_email=user_validated_email, dashboard_nav=True, remaining_size=50000, hash_code=hash_code, user_id=user_id, allowed_to_redeem=allowed_to_redeem, coupon_code=coupon_code, add_on_1_allowed=add_on_1_allowed)        
                    
    

        # for user_doc in user_data:
        #     # Check if the document exists
        #     user_info = user_doc.to_dict() 
        #     user_data_dict = user_doc.to_dict() 
            

        #     # print(user_data_dict)
            
        
        if not user_email or not user_data:
        # Redirect to login page if user is not authenticated or email is not verified
            return redirect(url_for("login"))
        
    except Exception as err:
        pass
        # raise err 
        
        # if not user_email or not user_data:
        # # Redirect to login page if user is not authenticated or email is not verified
        #     return redirect(url_for("login"))
        # else:
        #     raise Exception
        # return redirect(url_for("login")) 
        

    if account_insured:
        return render_template("propsurance-dashboard/dashboard.html", session=user_info, user_email=user_email, user_name=user_name, account_insured=True, num_of_accounts = num_of_accounts, insured_accounts =insured_accounts, account_percentage=account_percentage, remaining_size=remaining_size, account_size=account_size, has_first_name=True,first_name=first_name, dashboard_nav=True, hash_code=hash_code, user_id=user_id, coupon_code=coupon_code, allowed_to_redeem=allowed_to_redeem,  add_on_1_allowed=add_on_1_allowed)
    # # print(user_data + " the value for user data came")
    
        
    # firebase_user_data = list(user_data.values())[0]
    
    
    return render_template("propsurance-dashboard/dashboard.html", session=user_info, user_email=user_email, user_validated_email=user_validated_email, dashboard_nav=True, remaining_size=200000, user_id=user_id, hash_code=hash_code,coupon_code=coupon_code, allowed_to_redeem=allowed_to_redeem,  add_on_1_allowed=add_on_1_allowed)






@app.route('/webhook/aurt5dfte63462asfd33', methods=['POST'])
@csrf.exempt
def webhook():

    event = None
    payload = request.data
    sig_header = request.headers['STRIPE_SIGNATURE']
    check_for_count = True
    prop_count = 0
    template_id = 'payment-confirmation'
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except Exception as e:
        raise Exception
    except ValueError as e:
        # Invalid payload
        raise e
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        raise e
    


    # Handle the event



    if event['type'] == 'charge.succeeded':
        payment_intent = event['data']['object']  # The payment intent object
        customer_email = payment_intent.get('billing_details', {}).get('email')
        customer_name = payment_intent.get('billing_details', {}).get('name')
        receipt_url = payment_intent.get('receipt_url')
        purchase_id = payment_intent.get('payment_intent')

        client_reference_id_email  = customer_email
        user_ref = db.collection('users').document(customer_email)
        users_query = user_ref.get()
        
        if users_query.exists:
            user_info = users_query.to_dict()
            uid = user_info.get('uid', 0)
            sub_type = ''
            

            

            current_date = datetime.now()
            formatted_date_string = current_date.strftime('%Y-%m-%d')

            # Get the next account index
            accounts_collection = user_ref.collection('accounts_info')
            # Count the documents to generate the next unique document ID
            accounts_docs = accounts_collection.stream()  # Get all documents to count them
            account_count = sum(1 for _ in accounts_docs)  # Count documents and prepare the next index
            account_doc_id = f"account_info_{account_count}"
            first_name = customer_name.split()[0]

            

            account_info = {
                'propsurance_count': account_count,
                'invoice_url': receipt_url,
                # 'account_size': account_size,
                # 'prop_firm_name': prop_firm_name,
                'status': 'pending',
                'server': '',
                'trading_account_type': '',
                'insured_date': formatted_date_string,
                'customer-purchase-id': purchase_id,
                # 'sub_type' : sub_type,
                # 'current_rate': '40%',
                'plan_type': 'paid',
                'customer_name': customer_name,
                'first_name' : first_name
            }

            # Add to sub-collection
            # print('charge done')
            # print(account_info)
            accounts_ref = accounts_collection.document(account_doc_id).set(account_info)

            # Update user's basic information if necessary
            user_ref.update({
                'user_name': customer_name,
                'customer_email': customer_email,
                'accounts_info_count' : account_count,
                'first_name' : first_name
            })



         

    if event['type'] == 'checkout.session.completed':
        payment_intent = event['data']['object']  # The payment intent object
        customer_email = payment_intent.get('customer_details', {}).get('email')
        customer_name = payment_intent.get('customer_details', {}).get('name')
        purchase_id = payment_intent.get('payment_intent')
        customer_phone = payment_intent.get('billing_details', {}).get('phone')
        # Fetch the customer details from Stripe

        

        # Query Firestore for the user document by email
        user_ref = db.collection('users').document(customer_email)
        users_query = user_ref.get()

        if users_query.exists:
            user_info = users_query.to_dict()
            uid = user_info.get('uid', 0)
            account_size = ''
            prop_firm_name = ''

            # Retrieve the current number of accounts to create a unique identifier for the new account
            accounts_collection = user_ref.collection('trader_info')
            accounts_docs = accounts_collection.stream()  # Get all documents to count them
            accounts_count = sum(1 for _ in accounts_docs)  # Count documents
            first_name = customer_name.split()[0]

            # Extract custom field values
            trader_account_info = payment_intent['metadata']
            account_size = int(trader_account_info['account_size'])
            prop_firm_name =  trader_account_info['firm_name']
            # sub_type = trader_account_info['service']
            product_name = trader_account_info['plan_name']
            current_phase = trader_account_info['phase']
            purchase_cost = trader_account_info['price']
            allowed_to_redeem = trader_account_info['allowed_to_redeem']
            coupon_code = trader_account_info['coupon_code']
            account_platform = trader_account_info['trading_platform']
            got_add_on0 = trader_account_info['got_add_on0']

            # phase_value = payment_intent.get("custom_fields", [{}])[0].get("dropdown", {}).get("value", "")
            # mt4mt5_investor_id = payment_intent.get("custom_fields", [{}])[0].get("text", {}).get("value", "")
            # mt4mt5_investor_password = ''
            mt4mt5_investor_id = ''
            mt4mt5_investor_password = ''



            
            email_product_name = ''
                

            if product_name == 'trade-shield-bronze':
                email_product_name = 'Trade Shield Bronze'
            elif product_name == 'trade-shield-silver':
                email_product_name = 'Trade Shield Silver'
            elif product_name == 'trade-shield-gold':
                email_product_name = 'Trade Shield Gold'

            affiliate_data = handle_purchase(coupon_code, customer_email, product_name,allowed_to_redeem,accounts_count,purchase_id)


                

            sub_data = {
                'customer_name': first_name,
                'customer_purchase_id': account_size,
                'prop_firm_name': prop_firm_name,
                'signup_url': url_for('submit_mt_account', account=accounts_count, _external=True),
                'dashboard_url' : url_for('dashboard', _external=True),
                'faq_url' : url_for('dashboard_faq', _external=True),
                'url_privacy': url_for('propsurance_terms', _external=True),
                'email_product_name': email_product_name
            }

            send_email(customer_email , template_id, sub_data )


            if affiliate_data:
                trader_account_info = {
                'propsurance_count': accounts_count,  # Dynamic count based on the number of documents
                'account_status': current_phase,
                'account_size': account_size,
                'product_name': product_name,
                # 'sub-type': sub_type,
                'prop_firm_name': prop_firm_name,
                'investor_id': mt4mt5_investor_id,
                'trading_platform': account_platform,
                'investor_password': mt4mt5_investor_password,
                'insured_date': datetime.now().strftime('%Y-%m-%d'),
                'customer-purchase-id': purchase_id ,
                'price_cost': purchase_cost,
                'customer_phone': customer_phone,
                'failed_account': False,
                'current_payouts': 0,
                'got_add_on0': got_add_on0,
                'affiliate_email': affiliate_data.get('affiliate_email', ''),
                'affiliate_referral_count': affiliate_data.get('purchase_referral_count', '')
            }
            else:
                trader_account_info = {
                    'propsurance_count': accounts_count,  # Dynamic count based on the number of documents
                    'account_status': current_phase,
                    'account_size': account_size,
                    'product_name': product_name,
                    # 'sub-type': sub_type,
                    'prop_firm_name': prop_firm_name,
                    'investor_id': mt4mt5_investor_id,
                    'trading_platform': account_platform,
                    'investor_password': mt4mt5_investor_password,
                    'insured_date': datetime.now().strftime('%Y-%m-%d'),
                    'customer-purchase-id': purchase_id ,
                    'price_cost': purchase_cost,
                    'customer_phone': customer_phone,
                    'failed_account': False,
                    'current_payouts': 0,
                    'got_add_on0': got_add_on0
                }

        

            # Add a new document to the sub-collection

            accounts_collection.document(f"trader_account_{accounts_count}").set(trader_account_info)

            # Optionally update user's basic info
       
    else:
        return jsonify({'status': 'error', 'message': f'Unhandled event type {event["type"]}'}), 400

    return jsonify(success=True)


@app.route('/robots.txt')
def static_from_root():
    return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/')
def home():
    return render_template('home-main/index.html')


@app.route('/report-payout/')
@app.route('/report-payout')
def report_payout():
    return render_template('home-main/report_payout.html', remove_hero_css=True)

@app.route('/PropPatrol-leaderboard/')
@app.route('/PropPatrol-leaderboard')
def proppatrol_leaderboard():
    
    collection_ref = db.collection('proppatrol_leaderboard').document('main_leaderboard').collection('firm_list')

    # Retrieve the documents
    docs = collection_ref.stream()
    firm_list = []

    main_leaderboard_ref = db.collection('proppatrol_leaderboard').document('main_leaderboard')

    # Retrieve the main leaderboard document
    main_leaderboard_doc = main_leaderboard_ref.get()
    main_leaderboard_data = main_leaderboard_doc.to_dict()

    show_prop_score = main_leaderboard_data.get('show_prop_score', False)

    # Iterate through the documents
    for doc in docs:
        firm = doc.to_dict()
        firm_name = firm.get('name', '')
        prop_score = firm.get('propscore', '')
        image_id = firm.get('image_id', '')
        reports = firm.get('reports', '')
        bg_color = firm.get('bg_color', '')
        denied_payouts = firm.get('denied_payouts', '')
        date_from_data = firm.get('last_update', '')
        formatted_date = date_from_data.strftime('%d %B')
        display_img = firm.get('display_img', True)
        
        stars = 0
        status_alert = ''
        status_css = ''

        if prop_score >= 85:
            stars = 5
            status_alert = "Excellent"
            status_css = 'no-warnings'
        elif prop_score >= 70:
            stars = 4
            status_alert = "Good"
            status_css = 'fine'
        elif prop_score >= 55:
            stars = 3
            status_alert = "Moderate Risk"
            status_css = 'take-caution'
        elif prop_score >= 40:
            stars = 2
            status_alert = "Elevated Risk"
            status_css = "unrecommended"
        elif prop_score >= 25:
            stars = 1
            status_alert = "High Risk"
            status_css = 'careful'
        else:
            stars = 0
            status_alert = "Critical Risk"
            status_css = 'blacklisted'
        
        firm_data = {
            'firm_name': firm_name,
            'prop_score': prop_score,
            'image_id': image_id,
            'reports': reports,
            'bg_color': bg_color,
            'denied_payouts': denied_payouts,
            'last_update': formatted_date,
            'stars': stars,
            'status_alert': status_alert,
            'status_css': status_css,
            'display_img': display_img
        }

        firm_list.append(firm_data)

        # print(f'{doc.id} => {doc.to_dict()}')
    
    sorted_firm_list = sorted(firm_list, key=lambda x: x['prop_score'], reverse=True)

    return render_template('home-main/proppatrol-leaderboard.html' , remove_hero_css=True, firm_list=sorted_firm_list, show_prop_score=show_prop_score)

@app.route('/featured-firms/')
@app.route('/featured-firms')
def featured_firms():
    return render_template('home-main/featured-firms.html' , remove_hero_css=True)


@app.route('/terms-of-service/')
@app.route('/terms-of-service')
def tos():
    return render_template('home-main/terms-of-service.html', remove_hero_css=True)


@app.route('/reports/dei-20a/')
@app.route('/reports/dei-20a')
def dei_20a():
    return render_template('cases/dei_case_20a.html', remove_hero_css=True)

@app.route('/reports/fast-forex-funding-30a/')
@app.route('/reports/fast-forex-funding-30a')
def fff_30a():
    return render_template('cases/fff_case_30a.html', remove_hero_css=True)


@app.route('/reports/bespoke-funding-40a/')
@app.route('/reports/bespoke-funding-40a')
def bsp_40a():
    return render_template('cases/bsp_case_40a.html', remove_hero_css=True)

@app.route('/reports/uwm-60a/')
@app.route('/reports/uwm-60a')
def uwm_60a():
    return render_template('cases/uwm_case_60a.html', remove_hero_css=True)


@app.route('/reports/kortana-70a/')
@app.route('/reports/kortana-70a')
def kortana_70a():
    return render_template('cases/kor_case_70a.html', remove_hero_css=True)


@app.route('/reports/mff-90a/')
@app.route('/reports/mff-90a')
def mff_90a():
    return render_template('cases/mff_case_90a.html', remove_hero_css=True)



# @app.route('/reports')
# def report_preview():
#     return render_template('report_section.html')


@app.route('/reports-unresolved-closed/')
@app.route('/reports-unresolved-closed')
def report_preview_unresolved():
    return render_template('reports/reports-unresolved-closed.html', remove_hero_css=True)

@app.route('/reports-unresolved-open/')
@app.route('/reports-unresolved-open')
def report_preview_unresolved_open():
    return render_template('reports/reports-unresolved-open.html', remove_hero_css=True)

@app.route('/reports-resolved/')
@app.route('/reports-resolved')
def report_preview_resolved():
    return render_template('reports/reports-resolved.html', remove_hero_css=True)

@app.route('/view-reports/')
@app.route('/view-reports')
def view_firm_reports():
    return render_template('reports/reports-stats.html', remove_hero_css=True)


def free_coverage_update_accounts_info(customer_email, customer_name, form_data):
        user_ref = db.collection('users').document(customer_email)
        users_query = user_ref.get()
        if users_query.exists:
            user_info = users_query.to_dict()
            uid = user_info.get('uid', 0)
            sub_type = ''
            

            # # print('Metadata', payment_intent['metadata'])

            # if 'ftmo50' in payment_intent["lines"]["data"][0]["price"]["nickname"]:
            #     account_size = 50000
            #     prop_firm_name = 'FTMO'
            #     sub_type = 'one-time'

            current_date = datetime.now()
            formatted_date_string = current_date.strftime('%Y-%m-%d')

            # Get the next account index
            accounts_collection = user_ref.collection('accounts_info')
            # Count the documents to generate the next unique document ID
            accounts_docs = accounts_collection.stream()  # Get all documents to count them
            account_count = sum(1 for _ in accounts_docs)  # Count documents and prepare the next index
            account_doc_id = f"account_info_{account_count}"
            first_name = customer_name.split()[0]

            

            account_info = {
                'propsurance_count': account_count,
                'invoice_url': 'none',
                # 'account_size': account_size,
                # 'prop_firm_name': prop_firm_name,
                'status': 'needs_validation',
                'server': form_data['server'],
                'trading_account_type': form_data['trading_platform'],
                'insured_date': formatted_date_string,
                'customer-purchase-id': 'none',
                # 'sub_type' : sub_type,
                # 'current_rate': '40%',
                'plan_type': 'free',
                'customer_name': customer_name,
                'first_name' : first_name
            }

            # Add to sub-collection
            
            accounts_ref = accounts_collection.document(account_doc_id).set(account_info)

            # Update user's basic information if necessary
            user_ref.update({
                'user_name': customer_name,
                'customer_email': customer_email,
                'accounts_info_count' : account_count,
                'first_name' : first_name
            })

def free_coverage_update_trader_info(customer_email, customer_name, form_data):
        user_ref = db.collection('users').document(customer_email)
        users_query = user_ref.get()

        if users_query.exists:
            user_info = users_query.to_dict()
            uid = user_info.get('uid', 0)
            account_size = ''
            prop_firm_name = ''

            # Retrieve the current number of accounts to create a unique identifier for the new account
            accounts_collection = user_ref.collection('trader_info')
            accounts_docs = accounts_collection.stream()  # Get all documents to count them
            accounts_count = sum(1 for _ in accounts_docs)  # Count documents
            

            # Extract custom field values
            trader_account_info = form_data


            account_size = int(trader_account_info['account_size'])
            prop_firm_name =  trader_account_info['firm']
            # sub_type = trader_account_info['service']
            product_name = 'Denied Payout Coverage'
            current_phase = 'live'
            account_platform = trader_account_info['trading_platform']
            add_ons = 'none'

            
            mt4mt5_investor_id =  trader_account_info['mt_account']
            mt4mt5_investor_password = trader_account_info['password']

            
            

            trader_account_info = {
                'propsurance_count': accounts_count,  # Dynamic count based on the number of documents
                'account_status': current_phase,
                'account_size': account_size,
                'product_name': product_name,
                # 'sub-type': sub_type,
                'prop_firm_name': prop_firm_name,
                'investor_id': mt4mt5_investor_id,
                'trading_platform': account_platform,
                'investor_password': mt4mt5_investor_password,
                'insured_date': datetime.now().strftime('%Y-%m-%d'),
                'customer-purchase-id': 'none' ,
                'price_cost': 0,
                'plan_type': 'free',
                'failed_account': False,
                'current_payouts': 0
            }

            accounts_collection.document(f"trader_account_{accounts_count}").set(trader_account_info)

            return accounts_count
    
def calculate_commission(referrals, product):
    if product == 'trade-shield-bronze':
        if referrals < 20:
            # 10%
            return 8
        elif referrals <= 50:
            # 11.5 %
            return 9
        elif referrals <= 75:
            # 12.5 %
            return 10
        else:  # Referrals are more than 75
            # 15%
            return 12  # You can adjust this value as needed
    elif product == 'trade-shield-silver':
        # Add specific logic for silver product if needed
        if referrals < 20:
            # 10%
            return 18
        elif referrals <= 50:
            # 11.5 %
            return 20
        elif referrals <= 75:
            # 12.5 %
            return 22
        else:  # Referrals are more than 75
            # 15%
            return 27  # You can adjust this value as needed
    elif product == 'trade-shield-gold':
        # Add specific logic for gold product if needed
        if referrals < 20:
            # 10%
            return 40
        elif referrals <= 50:
            # 11.5 %
            return 46
        elif referrals <= 75:
            # 12.5 %
            return 50
        else:  # Referrals are more than 75
            # 15%
            return 60  # You can adjust this value as needed
    return 0

def return_referral_stage(referrals):
    if referrals < 20:
            # 10%
            return 1
    elif referrals <= 50:
        # 11.5 %
        return 2
    elif referrals <= 75:
        # 12.5 %
        return 3
    else:  # Referrals are more than 75
        # 15%
        return 4  # You can adjust this value as needed


def handle_purchase(coupon_code, user_email, product_name, allowed_to_redeem, user_purchase_count, purchase_id):
    if coupon_code != 'none' and allowed_to_redeem:
        # User used an affiliate code, find the code and update both user info and affiliate data
        coupon_data_ref = db.collection("affiliates").where("coupon_code", "==", coupon_code).get()
        if not coupon_data_ref:
            # Coupon code is invalid
            pass
        else:
            # Coupon code is valid, add affiliate data and update user redeemed info
            affiliate_data = coupon_data_ref[0].to_dict()
            affiliate_email = affiliate_data['email']

            # Update the affiliate's referral count
            referral_count = affiliate_data.get('referral_count', 0) + 1

            # Calculate the commission based on the product and referral count
            commission = calculate_commission(referral_count, product_name)

            # Get the next sequential purchase referral count
            purchase_referral_count = affiliate_data.get('purchase_referral_count', 0) + 1

            current_date = datetime.now()
            formatted_date_string = current_date.strftime('%Y-%m-%d')

            

            # Get the current date
            current__new_date = datetime.now()

            # Add 2 weeks to the current date
            new__updated_date = current__new_date + timedelta(weeks=2)

            # Format the new date
            formatted_date_string_2_weeks = new__updated_date.strftime('%Y-%m-%d')



            # Create a new subcollection for the purchase information
            purchase_ref = db.collection("affiliates").document(coupon_data_ref[0].id).collection("purchases").document(f"purchase_{purchase_referral_count}")
            purchase_data = {
                'user_email': user_email,
                'product_name': product_name,
                'date_purchased': formatted_date_string,
                '2_weeks_after_purchase_date': formatted_date_string_2_weeks,
                'user_purchase_count': user_purchase_count,
                'referral_commission_amount' : commission,
                'user_refunded': False,
                'affiliate_paid': False,
                'current_referral_count': purchase_referral_count,
                'purchase_id': purchase_id
            }
            purchase_ref.set(purchase_data)

            # Update the affiliate's data in the Firestore
            db.collection("affiliates").document(coupon_data_ref[0].id).update({
                'referral_count': referral_count,
            })

            # Update the user's redeemed status for the specific product
            db.collection("users").document(user_email).update({
                f"redeemed_coupon": True
            })

            return {'affiliate_email' : affiliate_email, 'purchase_referral_count': purchase_referral_count }

    else:
        # User did not use an affiliate code
        return None

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)