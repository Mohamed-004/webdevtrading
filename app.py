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
from datetime import datetime

# email api key e0292a01d4005f36ecc119c1ea1cf1dd04ea111c
spark_api = 'e0292a01d4005f36ecc119c1ea1cf1dd04ea111c'
stripe.api_key = 'sk_test_51Oyi2xP649Efo4kCYt2kWsW0hPJjptfuWapRJB8ZMCHvhfI4HJF0FuAdEaNJ6JzbQVp0pj1BBOsMEQwf4XJvQSRA00ELDbyNAC'
endpoint_secret = 'whsec_5943b6c6ce120203812d73889dcc757cd73be09a7d93150736be55b115ca5d68'
app = Flask(__name__)
app.secret_key = '1799d3118e5549432de9b191ba8003c8826585499ebba1974de60d36c8c2c2e6'
app.config['WTF_CSRF_SECRET_KEY'] =   'Dv1vKfzX6Eo5h_C9cSbX4Q'
app.config['DEBUG'] = True

# only for the live account
# app.config['PREFERRED_URL_SCHEME'] = 'https'
# app.config['SERVER_NAME'] = 'www.proppatrol.net'
csrf = CSRFProtect(app)


cred = credentials.Certificate('static/prop-patrol24-firebase-adminsdk-i50kg-5fe571bc7b.json')
firebase_admin.initialize_app(cred)
db = firestore.client()

oauth = OAuth(app)
# # Updated URL with custom domain for live
# conf_url = 'https://auth.proppatrol.net/.well-known/openid-configuration'

conf_url = 'https://dev-ct0rwl0778orlwvk.us.auth0.com/.well-known/openid-configuration'
oauth.register(
    name='proppatrol',
    client_id='qA5AwBA91VxeHowQQu6MDKOBYHWbWbmx',
    client_secret='7FckIXvKm00XxFch0RDB9iGiATPnKZ_RqnL83Um_BILE4_gQyL7fYLi7MfW431hn',
    server_metadata_url=conf_url,
    client_kwargs={'scope': 'openid  email'},
)


# old call back
# @app.route("/callback", methods=["GET", "POST"])
# def callback():
#     try:
#         token = oauth.proppatrol.authorize_access_token()
        
#         user_info = {
#         "email": token["userinfo"]["email"],
#         "email_verified": token["userinfo"]["email_verified"]
#     }

#     # Store the extracted user information in the session

#     # check if user email is valid in 
#         # session["user"] = user_info
#         # user = oauth.proppatrol.parse_id_token(token,nonce=session.get("nonce"))

        
#         user_ref = db.collection('users').document(user['email'])
#         user_check_exist = db.collection('users').document(user['email']).get()
#         if not user_check_exist.exists:
#             user_ref.set({
#                 'uid': user['sub'],  # Assuming sub field contains UID
#                 'email': user['email'],
#                 # Add other user information as needed
#             })
#             return redirect(url_for('dashboard'))
#         else:
#             return redirect(url_for('dashboard'))
#     except OAuthError as e:
#         if 'access_denied' in str(e):
#             # Here you can handle the specific case where access was denied
            
#             return 'you didnt provide consent', 403 

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


@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404
    

@app.route("/callback", methods=["GET", "POST"])
def callback():
    try:
        token = oauth.proppatrol.authorize_access_token()
        
        user_info = {
            "email": token["userinfo"]["email"],
            "email_verified": token["userinfo"]["email_verified"]
        }
        
        # Parse the ID token to get the user details
        user = oauth.proppatrol.parse_id_token(token, nonce=session.get("nonce"))
        
        # Check if the user's email is in the allowed_users collection
        allowed_user_ref = db.collection('allowed_users').document(user['email'])
        allowed_user_doc = allowed_user_ref.get()
        
        if allowed_user_doc.exists:
            # User is allowed, proceed with session creation and saving to users collection
            session["user"] = user_info
            
            user_ref = db.collection('users').document(user['email'])
            user_check_exist = user_ref.get()
            
            if not user_check_exist.exists:
                # Create a new document in the 'users' collection if it does not exist
                user_ref.set({
                    'uid': user['sub'],  # Assuming 'sub' field contains UID
                    'email': user['email'],
                    # Add other necessary user information as needed
                })
            
            return redirect(url_for('dashboard'))
        else:
            # If the user is not allowed, do not store in session or 'users' collection
            flash('You are not authorized to access this page.', 'error')
            return 'you are not eligible' # Redirect to a generic page or a denial information page

    except OAuthError as e:
        if 'access_denied' in str(e):
            # Handle specific case where access was denied
            return render_template('noaccess.html', error='You do not have access to PropSurance!'), 403
        else:
            # Handle other OAuth errors
            return render_template('noaccess.html', error='Registration Failed, No access.'), 403





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

@app.route('/dashboard/faq/', methods=['GET'])
@app.route('/dashboard/faq', methods=['GET'])
def dashboard_faq():
    if 'user' not in session:
        return redirect(url_for("login"))

    else:
        return render_template("faq-dashboard.html",dashboard_nav=True)
    


@app.route('/dashboard/terms-of-service/', methods=['GET'])
@app.route('/dashboard/terms-of-service', methods=['GET'])
def propsurance_service():
    if 'user' not in session:
        return redirect(url_for("login"))

    else:
        return render_template("terms-propsurance.html",dashboard_nav=True)

@app.route('/dashboard/privacy-policy/', methods=['GET'])
@app.route('/dashboard/privacy-policy', methods=['GET'])
def propsurance_terms():
    if 'user' not in session:
        return redirect(url_for("login"))

    else:
        return render_template("privacy-propsurance.html",dashboard_nav=True)
 

@app.route('/dashboard/raise-ticket/<int:account_count>', methods=['GET'])
def access_ticket_handler(account_count):
    if 'user' not in session:
        return redirect(url_for("login"))
    
    user_info = session.get("user")
    user_email = user_info['email']
    user_data = db.collection('users').document(user_email).get()
    first_name = ''
    account = {}

    try:
        user_email = user_info['email']
        user_validated_email = user_info["email_verified"]
        user_data = db.collection('users').document(user_email).get()
        user_data_info = db.collection('users').document(user_email)
        accounts_collection = ''
        if user_data.exists:

            user_data_dict = user_data.to_dict()
            customer_name = user_data_dict['user_name']
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
        raise err
        # pass

    return render_template("ticket_handler.html", account_info=account, prop_count=account_count,dashboard_nav=True)

@app.route('/dashboard/user/<int:account_count>', methods=['GET'])
def access_account_dashboard(account_count):
    if 'user' not in session:
        return redirect(url_for("login"))
    
    user_info = session.get("user")
    user_email = user_info['email']
    user_data = db.collection('users').document(user_email).get()
    first_name = ''
    account = {}

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
                
                'current_rate': account_info.get('current_rate', '40%')
            }

            # print(accounts)
                                    
    except Exception  as err:
        raise err
        # pass

    return render_template("user_dashboard.html", account_info=account, prop_count=account_count, has_first_name=True, first_name=first_name, dashboard_nav=True)



@app.route('/dashboard/validate/<int:account>', methods=['GET', 'POST'])
def submit_mt_account(account):
    # Check if user is authenticated
    if 'user' not in session:
        return redirect(url_for("login"))
    
    user_info = session.get("user")
    user_email = user_info['email']
    user_data = db.collection('users').document(user_email).get()

    accounts = {}

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
            
            

            accounts = {
                'id': str(current_index),
                'name': trader_info_data_parsed.get('prop_firm_name'),
                'investor_id': trader_info_data_parsed.get('investor_id', ''),
                'investor_password': trader_info_data_parsed.get('investor_password', ''),
                'status': account_info.get('status', ''),
                'account_size': str(trader_info_data_parsed.get('account_size', '')),
                'server': account_info.get('server', ''),
                'server_type': account_info.get('trading_account_type', ''),
                'account_stage': account_stage,
                'customer_name': customer_name ,
                'date': trader_info_data_parsed.get('insured_date', '')
            }

            # print(accounts)
                                    
    except Exception  as err:
        raise err
        # pass

    # POST request handling
    if request.method == 'POST':
        try:
            # Extract data from form
            mt_account = request.form['server_type']
            password = request.form['password']
            server = request.form['server']
            # prop_count = request.form['prop_count']
            
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
                        'trading_account_type': mt_account  # Update account type information
                    }
                    account_ref.update(update_data)
                    flash('Account updated successfully and is awaiting validation.')
                else:
                    flash('Account is not in a pending state and cannot be updated.')
            else:
                flash('Account information could not be found.')

        except Exception as err:
            # Provide a generic error message to the user
            raise err
            flash('Error updating account information. Please try again.')
            # Log the specific error internally
            # print(f"Error updating account information: {err}")

        # Redirect back to the same page to potentially show updated data or messages
        return redirect(url_for('submit_mt_account', account=account))

    return render_template("validate_trader_info.html", accounts=accounts, prop_count=account, dashboard_nav=True)




@app.route("/dashboard/")
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
        user_data_info = db.collection('users').document(user_email)

        if user_data.exists:

            user_data = user_data.to_dict()
            first_name = user_data['first_name']
            accounts_collection = user_data_info.collection('accounts_info').get()
            trader_info_collection = user_data_info.collection('trader_info')
            num_of_accounts = user_data['accounts_info_count'] + 1

            if int(user_data['accounts_info_count']) >= 0:

                
                    account_insured = True   
                    # # print(accounts_collection)
                    if accounts_collection:
                        # # print( 'here 270')
                        for account in accounts_collection:
                            # # print('here line 270')
                            
                            account_info_data =  account.to_dict()
                            current_index = account_info_data['propsurance_count']
                            
                            trader_info_data = trader_info_collection.document(f"trader_account_{current_index}").get()
                            trader_info_data_parsed = trader_info_data.to_dict()
                            # # print('line 275', account_info_data)
                            account_size += (trader_info_data_parsed.get('account_size'))
                            trade_status = ''


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
                            'invoice_url' : account_info_data['invoice_url'],
                            'account_url_fix' : str(current_index),
                            'account_status':  account_info_data.get('status'),
                            'phase_status' : trade_status,
                            'current_percentage': int((trader_info_data_parsed['account_size'] / 200000) * 100),
                            'current_size': trader_info_data_parsed['account_size']
                            }

                            # print(account_info_data)

                            insured_accounts.append(prop_firm_info)

                    account_percentage = int((account_size / 200000) * 100)
                    remaining_size = 200000 - account_size        

            else: 
                return render_template("dashboard.html", session=user_info, user_email=user_email, user_validated_email=user_validated_email, dashboard_nav=True)        
                    
    

        # for user_doc in user_data:
        #     # Check if the document exists
        #     user_info = user_doc.to_dict() 
        #     user_data_dict = user_doc.to_dict() 
            

        #     # print(user_data_dict)
            
        
        if not user_email or not user_data:
        # Redirect to login page if user is not authenticated or email is not verified
            return redirect(url_for("login"))
        
    except Exception as err:
        # pass
        
        raise err 
        # if not user_email or not user_data:
        # # Redirect to login page if user is not authenticated or email is not verified
        #     return redirect(url_for("login"))
        # else:
        #     raise Exception
        # return redirect(url_for("login")) 
        

    if account_insured:
        return render_template("dashboard.html", session=user_info, user_email=user_email, user_name=user_name, account_insured=True, num_of_accounts = num_of_accounts, insured_accounts =insured_accounts, account_percentage=account_percentage, remaining_size=remaining_size, account_size=account_size, has_first_name=True,first_name=first_name, dashboard_nav=True)
    # # print(user_data + " the value for user data came")
    
        
    # firebase_user_data = list(user_data.values())[0]
    
    return render_template("dashboard.html", session=user_info, user_email=user_email, user_validated_email=user_validated_email, dashboard_nav=True)






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
    if event['type'] == 'invoice.payment_succeeded':
        payment_intent = event['data']['object']  # The payment intent object
        
        
        
        customer_id = payment_intent['customer']

        # Fetch the customer details from Stripe
        customer = stripe.Customer.retrieve(customer_id)
        
          
        

        # Fetch the customer details from Stripe

        # Query Firestore for the user document by email
        client_reference_id_email  = customer.email
        user_ref = db.collection('users').document(client_reference_id_email)
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
            first_name = customer.name.split()[0]

            

            account_info = {
                'propsurance_count': account_count,
                'invoice_url': payment_intent["hosted_invoice_url"],
                # 'account_size': account_size,
                # 'prop_firm_name': prop_firm_name,
                'status': 'pending',
                'server': '',
                'trading_account_type': '',
                'insured_date': formatted_date_string,
                'customer-purchase-id': customer.id,
                'sub_type' : sub_type,
                'current_rate': '40%',
                'customer_name': customer.name,
                'first_name' : first_name
            }

            # Add to sub-collection
            accounts_ref = accounts_collection.document(account_doc_id).set(account_info)

            # Update user's basic information if necessary
            user_ref.update({
                'user_name': customer.name,
                'customer_phone_number': customer.phone,
                'customer_email': client_reference_id_email,
                'accounts_info_count' : account_count,
                'first_name' : first_name
            })

            

            # Optionally update the customer metadata in Stripe
            stripe.Customer.modify(
                customer_id,
                metadata={
                    'uid': uid,
                    'propsurance-count': account_count ,
                    'customer-email': client_reference_id_email
                }
            )
            

        
            

    if event['type'] == 'checkout.session.completed':
        payment_intent = event['data']['object']  # The payment intent object
        customer_id = payment_intent['customer']

        # Fetch the customer details from Stripe
        customer = stripe.Customer.retrieve(customer_id)
        client_reference_id_email  = customer.email
        

        # Query Firestore for the user document by email
        user_ref = db.collection('users').document(client_reference_id_email)
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
            first_name = customer.name.split()[0]

            # Extract custom field values
            trader_account_info = payment_intent['metadata']

            # if 'ftmo50' in payment_intent["lines"]["data"][0]["price"]["nickname"]:
            #     account_size = 50000
            #     prop_firm_name = 'FTMO'
            #     sub_type = 'one-time'

            account_size = int(trader_account_info['account_value'])
            prop_firm_name =  trader_account_info['firm_name']
            sub_type = trader_account_info['service']
            current_phase = trader_account_info['phase']
            purchase_cost = trader_account_info['price']

            # phase_value = payment_intent.get("custom_fields", [{}])[0].get("dropdown", {}).get("value", "")
            mt4mt5_investor_id = payment_intent.get("custom_fields", [{}])[1].get("text", {}).get("value", "")
            mt4mt5_investor_password = payment_intent.get("custom_fields", [{}])[2].get("text", {}).get("value", "")

            sub_data = {
                'customer_name': first_name,
                'customer_purchase_id': account_size,
                'prop_firm_name': prop_firm_name,
                'signup_url': url_for('submit_mt_account', account=accounts_count, _external=True),
                'dashboard_url' : url_for('dashboard', _external=True),
                'faq_url' : url_for('dashboard_faq', _external=True),
                'url_privacy': url_for('propsurance_terms', _external=True)
            }

            # send_email(client_reference_id_email , template_id, sub_data )

            trader_account_info = {
                'propsurance_count': accounts_count,  # Dynamic count based on the number of documents
                'account_status': current_phase,
                'account_size': account_size,
                'sub-type': sub_type,
                'prop_firm_name': prop_firm_name,
                'investor_id': mt4mt5_investor_id,
                'investor_password': mt4mt5_investor_password,
                'insured_date': datetime.now().strftime('%Y-%m-%d'),
                'customer-purchase-id': customer.id ,
                'price_cost': purchase_cost
            }

            # Add a new document to the sub-collection
            accounts_collection.document(f"trader_account_{accounts_count}").set(trader_account_info)

            # Optionally update user's basic info
            

            

        else:
            trader_account_info = payment_intent['metadata']

            # if 'ftmo50' in payment_intent["lines"]["data"][0]["price"]["nickname"]:
            #     account_size = 50000
            #     prop_firm_name = 'FTMO'
            #     sub_type = 'one-time'

            account_size = int(trader_account_info['account_value'])
            prop_firm_name =  trader_account_info['firm_name']
            sub_type = trader_account_info['service']
            user_ref.set({
                                'account_size': account_size,
                'sub-type': sub_type,
                'prop_firm_name': prop_firm_name,
                'user_name': customer.name,
                'phone_number': customer.phone,
                'customer_email': customer.email,
               'customer_purchase_id': payment_intent['payment_intent'],
               'user_description': "purchased with stripe using wrong account: transfer " ,
                'purchase_info' : payment_intent['metadata']
            })
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


@app.route('/report-payout/')
@app.route('/report-payout')
def report_payout():
    return render_template('report_payout.html')



@app.route('/featured-firms/')
@app.route('/featured-firms')
def featured_firms():
    return render_template('featured-firms.html')


@app.route('/terms-of-service/')
@app.route('/terms-of-service')
def tos():
    return render_template('terms-of-service.html')


@app.route('/reports/dei-20a/')
@app.route('/reports/dei-20a')
def dei_20a():
    return render_template('dei_case_20a.html')

@app.route('/reports/fast-forex-funding-30a/')
@app.route('/reports/fast-forex-funding-30a')
def fff_30a():
    return render_template('fff_case_30a.html')


@app.route('/reports/bespoke-funding-40a/')
@app.route('/reports/bespoke-funding-40a')
def bsp_40a():
    return render_template('bsp_case_40a.html')

@app.route('/reports/uwm-60a/')
@app.route('/reports/uwm-60a')
def uwm_60a():
    return render_template('uwm_case_60a.html')


@app.route('/reports/kortana-70a/')
@app.route('/reports/kortana-70a')
def kortana_70a():
    return render_template('kor_case_70a.html')


@app.route('/reports/mff-90a/')
@app.route('/reports/mff-90a')
def mff_90a():
    return render_template('mff_case_90a.html')



# @app.route('/reports')
# def report_preview():
#     return render_template('report_section.html')


@app.route('/reports-unresolved-closed/')
@app.route('/reports-unresolved-closed')
def report_preview_unresolved():
    return render_template('reports-unresolved-closed.html')

@app.route('/reports-unresolved-open/')
@app.route('/reports-unresolved-open')
def report_preview_unresolved_open():
    return render_template('reports-unresolved-open.html')

@app.route('/reports-resolved/')
@app.route('/reports-resolved')
def report_preview_resolved():
    return render_template('reports-resolved.html')

@app.route('/view-reports/')
@app.route('/view-reports')
def view_firm_reports():
    return render_template('reports-stats.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)