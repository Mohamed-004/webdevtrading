from authlib.integrations.flask_client import OAuth
from authlib.integrations.base_client.errors import OAuthError
import firebase_admin
from firebase_admin import credentials, auth, db, firestore
from flask import Flask, render_template, send_from_directory, jsonify, request, url_for, redirect, session, flash, abort, current_app
from flask_wtf.csrf import CSRFProtect, validate_csrf
from wtforms import ValidationError
from urllib.parse import quote_plus, urlencode
import stripe 
import requests
from datetime import datetime

# email api key e0292a01d4005f36ecc119c1ea1cf1dd04ea111c

stripe.api_key = 'sk_test_51Oyi2xP649Efo4kCYt2kWsW0hPJjptfuWapRJB8ZMCHvhfI4HJF0FuAdEaNJ6JzbQVp0pj1BBOsMEQwf4XJvQSRA00ELDbyNAC'

endpoint_secret = 'whsec_5943b6c6ce120203812d73889dcc757cd73be09a7d93150736be55b115ca5d68'

app = Flask(__name__)
app.secret_key = '1799d3118e5549432de9b191ba8003c8826585499ebba1974de60d36c8c2c2e6'
app.config['WTF_CSRF_SECRET_KEY'] =   'Dv1vKfzX6Eo5h_C9cSbX4Q'
app.config['DEBUG'] = True
csrf = CSRFProtect(app)


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
    client_kwargs={'scope': 'openid  email'},
)



@app.route("/callback", methods=["GET", "POST"])
def callback():
    try:
        token = oauth.proppatrol.authorize_access_token()
        
        user_info = {
        "email": token["userinfo"]["email"],
        "email_verified": token["userinfo"]["email_verified"]
    }

    # Store the extracted user information in the session
        session["user"] = user_info
        user = oauth.proppatrol.parse_id_token(token,nonce=session.get("nonce"))

        
        user_ref = db.collection('users').document(user['email'])
        user_check_exist = db.collection('users').document(user['email']).get()
        if not user_check_exist.exists:
            user_ref.set({
                'uid': user['sub'],  # Assuming sub field contains UID
                'name': user.get('name', ''),
                'email': user['email'],
                # Add other user information as needed
            })
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('dashboard'))
    except OAuthError as e:
        if 'access_denied' in str(e):
            # Here you can handle the specific case where access was denied
            
            return 'you ddint provide consent', 403 
    

    





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


@app.route('/dashboard/validate/', methods=['GET', 'POST'])
def submit_mt_account():
    # Check if user is authenticated
    
    if 'user' not in session:
        return redirect(url_for("login"))
    user_info = session.get("user")
    user_email = user_info['email']
    
    user_data = db.collection('users').document(user_email).get()
    account_info_user = 0
    account_more_info_user = 0
    user_name = 0
    num_of_accounts = 0
    account_insured = 0
    propsurance_count = 0
    prop_name = 0
    accounts = []

    if user_data.exists:
        user_data = user_data.to_dict()
        user_name = user_data.get('user_name', '')
        num_of_accounts = int(user_data.get('propsurance_count', 0)) + 1

        for i in range(num_of_accounts):
            account_key = f'account{i}'
            account_more_info_key = f'account{i}.account_info'
            if account_key in user_data:
                account_info = user_data[account_key]
                account_more_info_ = user_data[account_more_info_key]
                account_stage_value =   ''
                if account_more_info_.get('account_status') == 'phase1':
                    account_stage_value = 'Phase 1'
                elif account_more_info_.get('account_status') == 'phase2':
                    account_stage_value = 'Phase 2'
                elif account_more_info_.get('account_status') == 'live':
                    account_stage_value = 'Live'
                # print(account_info)
                # Assuming account_info includes 'status', 'investor_id', 'prop_firm_name'
                if account_info.get('status') == 'needs_validation' or account_info.get('status') == 'validated' or account_info.get('status') == 'invalid':
                    accounts.append({
                    'id': i,
                    'name': account_info.get('prop_firm_name', f'Account {i}'),
                    'investor_id': account_more_info_.get('investor_id', ''),
                    'investor_password': account_more_info_.get('investor_password', ''),
                    'status': account_info.get('status'),
                    'account_size': account_info.get('account_size', ''),
                    'server': account_info.get('server', ''),
                    'server_type':   account_info.get('trading_account_type'),
                    'account_stage' : account_stage_value
                })


                elif account_info.get('status') == 'pending':    
                    accounts.append({
                        'id': i,
                        'name': account_info.get('prop_firm_name', f'Account {i}'),
                        'investor_id': account_more_info_.get('investor_id', ''),
                        'investor_password': account_more_info_.get('investor_password', ''),
                        'status': account_info.get('status'),
                        'account_size': account_info.get('account_size', ''),
                        'account_stage' : account_stage_value
                    })
    

    # POST request handling
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
        except  ValidationError:
            # Handle the CSRF validation failure
            abort(400, description='CSRF token error')

        mt_account = request.form['server_type']
        password = request.form['password']
        server = request.form['server']
        prop_count = request.form['prop_count']
        user_email = session['user']['email']
        
    
    # Update user data in database
        try:
            user_ref = db.collection('users').document(user_email)
            
            account_current_data = user_ref.get()
            account_current_dict = account_current_data.to_dict()
            account_key = f'account{prop_count}'
            account_key_status = f'account_{prop_count}.status'
            trader_account_key = f'account_{prop_count}.account_info'
            
            
            account_status = account_current_dict.get(account_key).get('status')
            if account_status == 'pending':
# Specify the fields you want to update using dot notation
                update_data = {
                    f'{account_key}.status': 'needs_validation',  # Replace 'new_status' with the actual status value
                    # If updating the mt_account, password, and server as well:
                    f'{account_key}.server': server,
                    
                    f'{account_key}.trading_account_type': mt_account 
                }
                user_ref.update(update_data)
            else:
                return redirect(url_for('submit_mt_account'))


            # user_ref.update(update_data)

            flash('Awaiting Validation.')
        except Exception as err:
            # pass
            flash('Error updating MT account information.')
            print(err)  # Consider logging the error

        return redirect(url_for('submit_mt_account'))

    return render_template("validate_trader_info.html", accounts=accounts)





@app.route("/dashboard")
def dashboard():
    # Check if user is authenticated
    if 'user' not in session:
        return redirect(url_for("login"))
    user_info = False
    user_data = False
    user_validated_email = 0
    user_info = session.get("user")
    uid = 0
    # user info
    user_email = 0
    user_name = 0
    num_of_accounts = 0
    account_size =0
    account_percentage = 0
    remaining_size = 0
    insured_accounts = []

    account_insured = False
    # token = oauth.proppatrol.authorize_access_token()
    # user_info_full = token
    try:
        user_email = user_info['email']
        user_validated_email = user_info["email_verified"]
        user_data = db.collection('users').document(user_email).get()

        if user_data.exists:
            user_data = user_data.to_dict()

            if user_data['propsurance_count']:

                if int(user_data['propsurance_count']) >= 0 :
                    user_name = user_data['user_name']
                    num_of_accounts = int(user_data['propsurance_count']) + 1
                    
                    account_insured = True               

                    for i in range(0, int(user_data['propsurance_count']) + 1):
                        account_info = user_data['account' +  str(i) ]
                        account_more_info = user_data['account' +  str(i) + '.account_info' ]
                        account_size += account_info['account_size']
                        trade_status = ''
                        
                        if account_more_info['account_status'] == 'phase2':
                            trade_status = 'Phase 2'
                        elif account_more_info['account_status'] == 'phase1':
                            trade_status = 'Phase 1'
                        else:
                            trade_status = 'Live Account'

                    

                        prop_firm_info = {
                            'name': account_info['prop_firm_name'],
                            'account_size' : account_info['account_size'],
                            'account_url_fix' : str( i),
                            'account_status':  account_info['status'],
                            'phase_status' : trade_status
                        }

                        insured_accounts.append(prop_firm_info)

                    account_percentage = int((account_size / 200000) * 100)
                    remaining_size = 200000 - account_size

            else: 
                return render_template("dashboard.html", session=user_info, user_email=user_email, user_validated_email=user_validated_email)        
                    
    

        # for user_doc in user_data:
        #     # Check if the document exists
        #     user_info = user_doc.to_dict() 
        #     user_data_dict = user_doc.to_dict() 
            

        #     print(user_data_dict)
            
        
        if not user_email or not user_data:
        # Redirect to login page if user is not authenticated or email is not verified
            return redirect(url_for("login"))
        
    except Exception as err:
        pass
        # if not user_email or not user_data:
        # # Redirect to login page if user is not authenticated or email is not verified
        #     return redirect(url_for("login"))
        # else:
        #     raise Exception
        # return redirect(url_for("login")) 
        

    if account_insured:
        return render_template("dashboard.html", session=user_info, user_email=user_email, user_name=user_name, account_insured=True, num_of_accounts = num_of_accounts, insured_accounts =insured_accounts, account_percentage=account_percentage, remaining_size=remaining_size, account_size=account_size )
    # print(user_data + " the value for user data came")
    
        
    # firebase_user_data = list(user_data.values())[0]
    
    return render_template("dashboard.html", session=user_info, user_email=user_email, user_validated_email=user_validated_email)






@app.route('/webhook', methods=['POST'])
@csrf.exempt
def webhook():
    event = None
    payload = request.data
    sig_header = request.headers['STRIPE_SIGNATURE']
    check_for_count = True
    prop_count = 0
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
    if event['type'] == 'invoice.payment_succeeded':
        payment_intent = event['data']['object']  # The payment intent object
        customer_id = payment_intent['customer']

        # Fetch the customer details from Stripe
        customer = stripe.Customer.retrieve(customer_id)

        # Query Firestore for the user document by email
        user_ref = db.collection('users').document(customer.email)
        users_query = user_ref.get()
        
        if users_query.exists:
            user_info = users_query.to_dict()
            uid = user_info.get('uid', 0)
            sub_type = ''

            if 'ftmo50' in payment_intent["lines"]["data"][0]["price"]["nickname"]:
                account_size = 50000
                prop_firm_name = 'FTMO'
                sub_type = 'one-time'

            current_date = datetime.now()
            formatted_date_string = current_date.strftime('%Y-%m-%d')

            # Get the next account index
            accounts_collection = user_ref.collection('accounts_info')
            # Count the documents to generate the next unique document ID
            accounts_docs = accounts_collection.stream()  # Get all documents to count them
            account_count = sum(1 for _ in accounts_docs)  # Count documents and prepare the next index
            account_doc_id = f"account_info_{account_count}"

            account_info = {
                'propsurance_count': account_count,
                'invoice_url': payment_intent["hosted_invoice_url"],
                'account_size': account_size,
                'prop_firm_name': prop_firm_name,
                'status': 'pending',
                'server': '',
                'trading_account_type': '',
                'insured_date': formatted_date_string,
                'customer-purchase-id': customer.id,
                'sub_type' : sub_type
            }

            # Add to sub-collection
            accounts_ref = accounts_collection.document(account_doc_id).set(account_info)

            # Update user's basic information if necessary
            user_ref.update({
                'user_name': customer.name,
                'phone_number': customer.phone,
                'accounts_info_count' : account_count
            })

            

            # Optionally update the customer metadata in Stripe
            stripe.Customer.modify(
                customer_id,
                metadata={
                    'uid': uid,
                    'propsurance-count': account_count ,
                }
            )
            

        else:
            print('User not found in database.')
            return jsonify({'status': 'error', 'message': 'User not found in database.'}), 404
            

    if event['type'] == 'checkout.session.completed':
        payment_intent = event['data']['object']  # The payment intent object
        customer_id = payment_intent['customer']

        # Fetch the customer details from Stripe
        customer = stripe.Customer.retrieve(customer_id)

        # Query Firestore for the user document by email
        user_ref = db.collection('users').document(customer.email)
        users_query = user_ref.get()

        if users_query.exists:
            user_info = users_query.to_dict()
            uid = user_info.get('uid', 0)

            # Retrieve the current number of accounts to create a unique identifier for the new account
            accounts_collection = user_ref.collection('trader_info')
            accounts_docs = accounts_collection.stream()  # Get all documents to count them
            accounts_count = sum(1 for _ in accounts_docs)  # Count documents

            # Extract custom field values
            phase_value = payment_intent.get("custom_fields", [{}])[0].get("dropdown", {}).get("value", "")
            mt4mt5_investor_id = payment_intent.get("custom_fields", [{}])[1].get("text", {}).get("value", "")
            mt4mt5_investor_password = payment_intent.get("custom_fields", [{}])[2].get("text", {}).get("value", "")

            trader_account_info = {
                'propsurance_count': accounts_count,  # Dynamic count based on the number of documents
                'account_status': phase_value,
                'investor_id': mt4mt5_investor_id,
                'investor_password': mt4mt5_investor_password,
                'insured_date': datetime.now().strftime('%Y-%m-%d'),
                'customer-purchase-id': customer.id  # Ensure customer.id is passed correctly
            }

            # Add a new document to the sub-collection
            accounts_collection.document(f"trader_account_{accounts_count}").set(trader_account_info)

            # Optionally update user's basic info
            user_ref.update({
                'user_name': customer.name,
                'phone_number': customer.phone,

            })

            

        else:
            return jsonify({'status': 'error', 'message': 'User not found in database.'}), 404
    else:
        return jsonify({'status': 'error', 'message': f'Unhandled event type {event["type"]}'}), 400

    

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