from flask import Blueprint, request, jsonify

import app
from app.services.detection_service import detect_phishing, whitelist_checker
from app.services.send_notify_service import send_telegram_message

api_v1_blueprint = Blueprint("api_v1", __name__)


@api_v1_blueprint.route("/predict", methods=["POST"])
def predict():
    app.logging.info("Request prediction incoming...")
    data = request.get_json()
    url = data.get("url")
    result = detect_phishing(url)
    
    print(result)

    return jsonify(result)



@api_v1_blueprint.route("/notify", methods=["POST"])
def notify():
    data = request.get_json()
    message = data.get("message", "No message received")
    result = send_telegram_message(message)
    return jsonify({"status": "ok", "telegram_response": result})


@api_v1_blueprint.route("/history", methods=["GET"])
def hsitory():
    # TODO: Get history data from database or other data source
    data = [
        {
            "phishing_percentage": 0.02,
            "safe_percentage": 99.98,
            "url": "https://email-test.vercel.app",
            "timestamp": "2025-05-05 10:00",
        },
        {
            "phishing_percentage": 0.02,
            "safe_percentage": 99.98,
            "url": "https://email-test.vercel.app",
            "timestamp": "2025-05-05 10:00",
        },
        {
            "phishing_percentage": 0.02,
            "safe_percentage": 99.98,
            "url": "https://email-test.vercel.app",
            "timestamp": "2025-05-05 10:00",
        },
        {
            "phishing_percentage": 0.02,
            "safe_percentage": 99.98,
            "url": "https://email-test.vercel.app",
            "timestamp": "2025-05-05 10:00",
        },
        {
            "phishing_percentage": 0.02,
            "safe_percentage": 99.98,
            "url": "https://email-test.vercel.app",
            "timestamp": "2025-05-05 10:00",
        },
        {
            "phishing_percentage": 99.86,
            "safe_percentage": 0.14,
            "url": "http://localhost",
            "timestamp": "2025-05-05 10:00",
        },
        {
            "phishing_percentage": 99.86,
            "safe_percentage": 0.14,
            "url": "http://localhost",
            "timestamp": "2025-05-05 10:00",
        },
        {
            "phishing_percentage": 99.86,
            "safe_percentage": 0.14,
            "url": "http://localhost",
            "timestamp": "2025-05-05 10:00",
        },
    ]
    return jsonify(data)


@api_v1_blueprint.route("/whitelist", methods=["GET"])
def get_whitelist():
    """Get semua domain di whitelist"""
    try:
        whitelist = whitelist_checker.get_whitelist()
        return jsonify({
            "success": True,
            "data": whitelist,
            "count": len(whitelist)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@api_v1_blueprint.route("/whitelist", methods=["POST"])
def add_to_whitelist():
    """Tambah domain ke whitelist"""
    try:
        data = request.get_json()
        domain = data.get("domain")
        description = data.get("description", "Added via API")
        
        if not domain:
            return jsonify({
                "success": False,
                "error": "Domain is required"
            }), 400
        
        success = whitelist_checker.add_domain(domain, description)
        
        return jsonify({
            "success": success,
            "message": f"Domain {domain} {'added to' if success else 'already in'} whitelist"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@api_v1_blueprint.route("/whitelist/<domain>", methods=["DELETE"])
def remove_from_whitelist(domain):
    """Hapus domain dari whitelist"""
    try:
        success = whitelist_checker.remove_domain(domain)
        
        return jsonify({
            "success": success,
            "message": f"Domain {domain} {'removed from' if success else 'not found in'} whitelist"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@api_v1_blueprint.route("/whitelist/reload", methods=["POST"])
def reload_whitelist():
    """Reload whitelist dari file"""
    try:
        whitelist_checker.reload_whitelist()
        return jsonify({
            "success": True,
            "message": "Whitelist reloaded successfully"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500