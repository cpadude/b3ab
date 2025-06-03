import requests
import random
import urllib3
from bs4 import BeautifulSoup
import re
import base64
import json
import streamlit as st

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
        st.warning(f"Warning: {filename} not found. No proxies will be used.")
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

def make_request(step_number, description, method, url, headers=None, data=None, json_data=None, params=None, cookies=None, allow_redirects=True, print_response_details=False):
    """Makes an HTTP request and prints details."""
    st.subheader(f"--- Step {step_number}: {description} ---")
    st.write(f"Request: {method.upper()} {url}")

    proxy = get_random_proxy()
    if proxy:
        st.write(f"Using proxy: {proxy['http']}")

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
        st.write(f"Status Code: {response.status_code}")

        if print_response_details:
            with st.expander("View Response Headers"):
                st.json(dict(response.headers))
            
            # Try to print JSON response, otherwise print text
            try:
                with st.expander("View Response Body (JSON)"):
                    st.json(response.json())
            except requests.exceptions.JSONDecodeError:
                with st.expander("View Response Body (Text)"):
                    st.text(response.text[:1000] + "..." if len(response.text) > 1000 else response.text)

        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        return response

    except requests.exceptions.RequestException as e:
        st.error(f"Error during request: {e}")
        return None

# --- Main Execution ---
if __name__ == "__main__":
    st.title("cURL Request Processor")

    # --- Read Card Details from URL --- 
    card_details_from_url = None
    raw_card_param = st.query_params.get("card")
    if raw_card_param:
        st.write(f"Received card parameter: {raw_card_param}")
        parts = raw_card_param.split('|')
        if len(parts) == 4:
            cc, mm, yy_or_yyyy, cvv = parts
            year = yy_or_yyyy
            if len(yy_or_yyyy) == 2:
                year = "20" + yy_or_yyyy # Convert yy to yyyy
            
            card_details_from_url = {
                "number": cc,
                "expirationMonth": mm,
                "expirationYear": year,
                "cvv": cvv
            }
            st.success("Successfully parsed card details from URL.")
            st.write("Using the following card details for Step 4:", card_details_from_url)
        else:
            st.error("Invalid format for 'card' URL parameter. Expected cc|mm|yy_or_yyyy|cvv.")
            st.info("Please provide card details in the URL in the format: ?card=NUMBER|MONTH|YEAR|CVV to proceed.")
    # No else here, card_details_from_url remains None if not provided or invalid

    # Example of how to store a value (will be replaced by actual extraction logic)
    # stored_values["example_token"] = "extracted_token_value"

    # --- Request 1 (Removed as per user request) ---
    # headers_step1 = { ... }
    # response_step1 = make_request(...)
    # if response_step1: ...

    # --- Request 2 ---
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
        # Connection header is typically managed by requests library, so often omitted here
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
        params=params_step2,
        print_response_details=False
    )

    if response_step2 and response_step2.text:
        soup = BeautifulSoup(response_step2.text, 'html.parser')
        client_token = None
        # The response is expected to be JavaScript like: actionkit.forms.onContextLoaded({...});
        # We'll use regex on the text content obtained via BeautifulSoup
        script_content = soup.get_text()
        match = re.search(r'"client_token"\s*:\s*"([^"\s]+)"', script_content)
        if match:
            client_token = match.group(1)
            stored_values['client_token'] = client_token
            st.write(f"Extracted client_token: {client_token}")

            # Decode client_token and extract authorizationFingerprint
            try:
                decoded_token_json = base64.b64decode(client_token).decode('utf-8')
                decoded_token_data = json.loads(decoded_token_json)
                
                if 'authorizationFingerprint' in decoded_token_data:
                    auth_fingerprint = decoded_token_data['authorizationFingerprint']
                    stored_values['authorizationFingerprint'] = auth_fingerprint
                    st.write(f"Extracted authorizationFingerprint: {auth_fingerprint}")
                else:
                    st.warning("authorizationFingerprint not found in decoded client_token.")
            except Exception as e:
                st.error(f"Error decoding client_token or extracting authorizationFingerprint: {e}")

        else:
            st.warning("client_token not found in response for Step 2.")
        st.success("Step 2: Processing completed.")
    elif response_step2:
        st.warning("Step 2: Request successful but no text content in response.")
    else:
        st.error("Step 2: Failed.")
    st.markdown("---")

    # --- Request 3 ---
    if 'authorizationFingerprint' in stored_values:
        headers_step3 = {
            'Host': 'payments.braintree-api.com',
            # Content-Length is managed by requests library
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Authorization': f"Bearer {stored_values['authorizationFingerprint']}", # Using stored value
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
            # Connection header is typically managed by requests library
        }

        json_payload_step3 = {
            "clientSdkMetadata": {
                "source": "client",
                "integration": "custom",
                "sessionId": "5cd5ee4d-a4c1-4ca4-a81d-ee23dc44e8b1"
            },
            "query": "query ClientConfiguration {   clientConfiguration {     analyticsUrl     environment     merchantId     assetsUrl     clientApiUrl     creditCard {       supportedCardBrands       challenges       threeDSecureEnabled       threeDSecure {         cardinalAuthenticationJWT       }     }     applePayWeb {       countryCode       currencyCode       merchantIdentifier       supportedCardBrands     }     googlePay {       displayName       supportedCardBrands       environment       googleAuthorization       paypalClientId     }     ideal {       routeId       assetsUrl     }     kount {       merchantId     }     masterpass {       merchantCheckoutId       supportedCardBrands     }     paypal {       displayName       clientId       privacyUrl       userAgreementUrl       assetsUrl       environment       environmentNoNetwork       unvettedMerchant       braintreeClientId       billingAgreementsEnabled       merchantAccountId       currencyCode       payeeEmail     }     unionPay {       merchantAccountId     }     usBankAccount {       routeId       plaidPublicKey     }     venmo {       merchantId       accessToken       environment     }     visaCheckout {       apiKey       externalClientId       supportedCardBrands     }     braintreeApi {       accessToken       url     }     supportedFeatures   } }",
            "operationName": "ClientConfiguration"
        }

        response_step3 = make_request(
            step_number=3,
            description="POST to Braintree GraphQL API for client configuration",
            method="POST",
            url="https://payments.braintree-api.com/graphql",
            headers=headers_step3,
            json_data=json_payload_step3,
            print_response_details=True # Show full response for this step
        )

        if response_step3:
            # Add any value extraction logic here if needed for future steps
            st.success("Step 3: Successfully completed.")
        else:
            st.error("Step 3: Failed.")
    else:
        st.warning("Step 3: Skipped because authorizationFingerprint was not found in stored_values.")
    st.markdown("---")

    # --- Request 4 ---
    if 'authorizationFingerprint' in stored_values:
        if card_details_from_url: # Only proceed if card details were successfully parsed from URL
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
                "query": "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId       }     }   } }",
                "variables": {
                    "input": {
                        "creditCard": card_details_from_url, # Using dynamic card details from URL
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
                json_data=json_payload_step4,
                print_response_details=True 
            )

            if response_step4:
                try:
                    response_json = response_step4.json()
                    tokenized_card_token = response_json.get('data', {}).get('tokenizeCreditCard', {}).get('token')
                    if tokenized_card_token:
                        stored_values['card_token'] = tokenized_card_token
                        st.write(f"Extracted card_token: {tokenized_card_token}")
                    else:
                        st.warning("card_token not found in Step 4 response data.tokenizeCreditCard.token")
                except json.JSONDecodeError:
                    st.error("Error: Step 4 response was not valid JSON, cannot extract card_token.")
                except Exception as e:
                    st.error(f"Error extracting card_token from Step 4 response: {e}")
                st.success("Step 4: Successfully completed.")
            else:
                st.error("Step 4: Failed.")
        else:
            st.warning("Step 4 (Tokenize Card) & 5 (Donate): Skipped. Card details not provided or invalid in URL (?card=NUMBER|MONTH|YEAR|CVV).")
            # Ensure card_token is not in stored_values if this path is taken, to prevent Step 5 trying to run with stale data
            if 'card_token' in stored_values:
                del stored_values['card_token']
    else:
        st.warning("Step 3 (Braintree Config) failed or authorizationFingerprint not found. Steps 4 & 5 skipped.")
    st.markdown("---")

    # --- Request 5 ---
    if 'card_token' in stored_values: # This condition will now correctly reflect if Step 4 was successful
        headers_step5 = {
            'Host': 'act.dsausa.org',
            # Content-Length is managed by requests library
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
            # Connection header is typically managed by requests library
        }

        data_step5 = {
            'page': 'donation',
            'orig_akid': 'None',
            'ak-donate-step': '1',
            'amount_other': '2',
            'donation_type': 'single',
            'first_name': 'Raju',
            'required': 'first_name',
            'last_name': 'Kaka',
            # 'required': 'last_name', # Note: 'required' is listed multiple times in curl, typically last one wins or use a list if server supports
            'address1': '112 Raju St.',
            'city': 'Los Angeles',
            # 'required': 'state', 
            'state': 'CA',
            # 'required': 'zip',
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
            # 'required': 'address1', 
            # 'required': 'city',
            'cookie_prefill': '{"nvtag":"Ro2YD4hJLO9PpFNQCD2zk2P2"}',
            'device_data': '{"device_session_id":"df9979f1032a46e2b64106e04ea20d06","fraud_merchant_id":null,"correlation_id":"40e873dbf2ecd7c15da842895fa7b05f"}',
            'payment_method_nonce': stored_values['card_token'], # Using stored card_token
            'card_prefix': '408911'
        }
        # For keys like 'required' that appear multiple times, requests sends the last one by default when using a dict.
        # If the server expects multiple values for the same key, data should be a list of tuples, e.g., [('required', 'first_name'), ('required', 'last_name')]
        # For now, assuming last 'required' specified (or the way requests handles dicts for form data) is fine.

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
            print_response_details=True # Show full response for this step
        )

        if response_step5:
            # Add any value extraction logic here if needed
            st.success("Step 5: Successfully completed.")
        else:
            st.error("Step 5: Failed.")
    else:
        st.warning("Step 5: Skipped because card_token was not found in stored_values.")
    st.markdown("---")

# --- Request Definitions will be added below --- 
