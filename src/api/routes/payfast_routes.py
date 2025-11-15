# src/api/routes/payfast_routes.py
"""PayFast onsite payment integration routes - DEBUG VERSION"""

import hashlib
import urllib.parse
from flask import request, jsonify
from ..utils import APIResponse, handle_api_errors
import requests


# ============================================================================
# PAYFAST CREDENTIALS
# ============================================================================

USE_SANDBOX = False

# Production credentials
PRODUCTION_MERCHANT_ID = "11544151"
PRODUCTION_MERCHANT_KEY = "pyadvgb0r7wsn"
PRODUCTION_PASSPHRASE = ""  # Empty/blank

# Sandbox credentials
SANDBOX_MERCHANT_ID = "10000100"
SANDBOX_MERCHANT_KEY = "46f0cd694581a"
SANDBOX_PASSPHRASE = "jt7NOE43FZPn"

# ============================================================================


def register_payfast_routes(app, deps):
    """Register PayFast payment routes"""

    def data_to_string(data_array, pass_phrase=""):
        """Convert data to PayFast parameter string - SORTED alphabetically"""
        pf_param_string = ""

        # Sort keys alphabetically
        sorted_keys = sorted(data_array.keys())

        for key in sorted_keys:
            value = str(data_array[key]).replace("+", " ")
            encoded_value = urllib.parse.quote_plus(value)
            pf_param_string += f"{key}={encoded_value}&"

        # Remove last &
        pf_param_string = pf_param_string[:-1]

        # Append passphrase
        if pass_phrase:
            pf_param_string += f"&passphrase={pass_phrase}"

        return pf_param_string

    def generate_signature(data_array, pass_phrase=""):
        """Generate MD5 signature"""
        payload = data_to_string(data_array, pass_phrase)
        return hashlib.md5(payload.encode()).hexdigest()

    @app.route("/api/payfast/generate-payment-data", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def generate_payfast_payment_data():
        """Generate UUID from PayFast for onsite payment"""
        body = request.json

        order_id = body.get("orderId")
        amount = body.get("amount")
        user = body.get("user", {})
        email = user.get("email")

        if not order_id or not amount or not email:
            return APIResponse.bad_request(
                "Missing required fields: orderId, amount, user.email"
            )

        # Select credentials
        if USE_SANDBOX:
            merchant_id = SANDBOX_MERCHANT_ID
            merchant_key = SANDBOX_MERCHANT_KEY
            passphrase = SANDBOX_PASSPHRASE
        else:
            merchant_id = PRODUCTION_MERCHANT_ID
            merchant_key = PRODUCTION_MERCHANT_KEY
            passphrase = PRODUCTION_PASSPHRASE

        formatted_amount = f"{float(amount):.2f}"
        base_url = request.headers.get("Origin") or "https://datablox.co.za"

        # Prepare payment data
        my_data = {
            "merchant_id": merchant_id,
            "merchant_key": merchant_key,
            "return_url": f"{base_url}/order-success?order={order_id}",
            "cancel_url": f"{base_url}/checkout?cancelled=true",
            "notify_url": f"{base_url}/api/payfast/notify",
            "m_payment_id": order_id,
            "amount": formatted_amount,
            "item_name": f"Order #{order_id}",
            "email_address": email,
        }

        # Add optional fields
        if user.get("name_first"):
            my_data["name_first"] = user["name_first"]
        if user.get("name_last"):
            my_data["name_last"] = user["name_last"]
        if user.get("cell_number"):
            my_data["cell_number"] = user["cell_number"]

        deps["logger"].info(f"💳 Generating payment for order {order_id}")
        deps["logger"].info(f"📧 Email: {email}")

        # DEBUG: Log sorted keys
        sorted_keys = sorted(my_data.keys())
        deps["logger"].info(f"🔑 Sorted keys: {sorted_keys}")

        # Generate signature
        my_data["signature"] = generate_signature(my_data, passphrase)

        # DEBUG: Log signature details
        sig_string = data_to_string(my_data, passphrase)
        deps["logger"].info(f"🔐 Signature string: {sig_string[:200]}...")
        deps["logger"].info(f"🔐 Signature: {my_data['signature']}")

        # Convert to parameter string
        pf_param_string = data_to_string(my_data, passphrase)

        deps["logger"].info(f"📤 Calling PayFast...")

        # Call PayFast
        url = "https://www.payfast.co.za/onsite/process"

        try:
            response = requests.post(
                url,
                data=pf_param_string,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
            )

            deps["logger"].info(f"📨 Response status: {response.status_code}")

            if response.status_code == 200:
                response_json = response.json()
                uuid = response_json.get("uuid")

                if uuid:
                    deps["logger"].info(f"✅ UUID: {uuid}")
                    return APIResponse.success(
                        {"uuid": uuid, "orderId": order_id, "sandbox": USE_SANDBOX}
                    )
                else:
                    deps["logger"].error(f"❌ No UUID: {response_json}")
                    return APIResponse.error("No UUID received", 500)
            else:
                error_text = response.text[:500]
                deps["logger"].error(f"❌ PayFast error: {error_text}")

                # Check for specific errors
                if "signature" in error_text.lower():
                    deps["logger"].error("🔴 SIGNATURE MISMATCH DETECTED")
                    deps["logger"].error(f"   Keys we sorted: {sorted_keys}")
                    deps["logger"].error(
                        f"   Passphrase used: {'(empty)' if not passphrase else '(set)'}"
                    )

                return APIResponse.error("PayFast rejected request", 500)

        except Exception as e:
            deps["logger"].error(f"❌ Exception: {str(e)}")
            return APIResponse.error("Request failed", 500)

    @app.route("/api/payfast/notify", methods=["POST"])
    @handle_api_errors(deps["logger"])
    def payfast_notify():
        """Handle PayFast ITN"""
        post_data = request.form.to_dict()

        deps["logger"].info(f"📬 ITN received: {post_data}")

        received_signature = post_data.pop("signature", None)
        if not received_signature:
            return jsonify({"status": "error"}), 200

        passphrase = SANDBOX_PASSPHRASE if USE_SANDBOX else PRODUCTION_PASSPHRASE
        calculated_signature = generate_signature(post_data, passphrase)

        if received_signature != calculated_signature:
            deps["logger"].error("⚠️ ITN Signature mismatch")
            return jsonify({"status": "error"}), 200

        payment_status = post_data.get("payment_status")
        m_payment_id = post_data.get("m_payment_id")
        amount_gross = post_data.get("amount_gross")

        deps["logger"].info(f"💳 {m_payment_id}: {payment_status}, R{amount_gross}")

        if payment_status == "COMPLETE":
            deps["logger"].info(f"✅ Payment complete: {m_payment_id}")

        return jsonify({"status": "received"}), 200
