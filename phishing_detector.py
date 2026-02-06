"""
PhishSense AI Pro – Advanced Phishing Detection System
Enhanced rule-based NLP with ML-inspired features and better accuracy
"""

import re
import string
from urllib.parse import urlparse, unquote
from collections import Counter

# -----------------------------
# 1. Enhanced Text Preprocessing
# -----------------------------
def preprocess_text(text: str) -> str:
    """Clean and normalize text with better handling of special cases"""
    if not text:
        return ""
    
    # Convert to lowercase
    text = text.lower().strip()
    
    # Remove excessive whitespace
    text = re.sub(r'\s+', ' ', text)
    
    # Decode URL-encoded characters
    text = unquote(text)
    
    # Remove excessive punctuation (keep first of consecutive punctuation)
    text = re.sub(r'([!?.]){2,}', r'\1', text)
    
    return text

def extract_urls(text: str) -> list:
    """Extract and normalize URLs from text"""
    url_pattern = r'(https?://\S+|www\.\S+|bit\.ly/\S+|tinyurl\.com/\S+|goo\.gl/\S+)'
    urls = re.findall(url_pattern, text)
    return [url.strip('.,;:()[]{}"\'') for url in urls]

# -----------------------------
# 2. Enhanced Feature Extraction
# -----------------------------
class FeatureExtractor:
    """Advanced feature extraction for phishing detection"""
    
    def __init__(self):
        # Expanded keyword categories with weights
        self.threat_keywords = {
            "urgent": 1.5, "immediate": 1.5, "asap": 1.5, "critical": 1.5,
            "emergency": 1.5, "important": 1.3, "verify": 1.4, "confirm": 1.3,
            "suspended": 1.6, "blocked": 1.6, "locked": 1.6, "terminated": 1.6,
            "expired": 1.4, "warning": 1.3, "alert": 1.3, "attention": 1.2,
            "required": 1.2, "necessary": 1.2, "compulsory": 1.3
        }
        
        self.auth_keywords = {
            "login": 1.4, "password": 1.6, "credentials": 1.6,
            "authenticate": 1.5, "account": 1.4, "security": 1.3,
            "reset": 1.5, "update": 1.3, "verify": 1.4, "confirm": 1.3,
            "username": 1.4, "signin": 1.4, "sign-in": 1.4,
            "two-factor": 1.5, "2fa": 1.5, "multi-factor": 1.5,
            "access": 1.3, "authorize": 1.4, "validation": 1.3
        }
        
        self.financial_keywords = {
            "bank": 1.5, "paypal": 1.6, "credit": 1.4, "payment": 1.4,
            "money": 1.3, "refund": 1.5, "invoice": 1.4, "billing": 1.4,
            "transaction": 1.5, "otp": 1.6, "pin": 1.6, "card": 1.5,
            "wire": 1.4, "transfer": 1.5, "deposit": 1.4, "withdrawal": 1.4,
            "fee": 1.3, "charge": 1.3, "statement": 1.3, "balance": 1.3
        }
        
        self.impersonation_keywords = {
            "irs": 1.6, "microsoft": 1.5, "apple": 1.5, "google": 1.5,
            "amazon": 1.5, "paypal": 1.6, "fedex": 1.4, "ups": 1.4,
            "dhl": 1.4, "usps": 1.4, "government": 1.5, "official": 1.4,
            "support": 1.3, "customer": 1.3, "service": 1.3, "team": 1.2
        }
        
        # Suspicious URL shorteners
        self.url_shorteners = {
            "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
            "adf.ly", "shorte.st", "t.co", "buff.ly", "cutt.ly",
            "shorturl.at", "rb.gy", "bc.vc", "soo.gd", "s2r.co",
            "click.ru", "clck.ru", "tiny.cc", "tr.im", "qr.net"
        }
        
        # Suspicious TLDs
        self.suspicious_tlds = {'.xyz', '.top', '.club', '.work', '.site', '.online', '.click', '.link'}
    
    def extract_features(self, text: str) -> dict:
        """Extract comprehensive phishing features"""
        tokens = set(text.split())
        features = {}
        
        # Keyword-based features with weighted counts
        features["threat_score"] = sum(
            self.threat_keywords[word] 
            for word in tokens & self.threat_keywords.keys()
        )
        features["auth_score"] = sum(
            self.auth_keywords[word]
            for word in tokens & self.auth_keywords.keys()
        )
        features["financial_score"] = sum(
            self.financial_keywords[word]
            for word in tokens & self.financial_keywords.keys()
        )
        features["impersonation_score"] = sum(
            self.impersonation_keywords[word]
            for word in tokens & self.impersonation_keywords.keys()
        )
        
        # URL analysis
        urls = extract_urls(text)
        features["total_urls"] = len(urls)
        features["suspicious_urls"] = 0
        features["suspicious_domains"] = 0
        features["ip_address_urls"] = 0
        
        url_features = []
        for url in urls:
            url_feat = self._analyze_url(url)
            url_features.append(url_feat)
            
            if url_feat["is_shortener"]:
                features["suspicious_urls"] += 1
            if url_feat["has_suspicious_tld"]:
                features["suspicious_domains"] += 1
            if url_feat["is_ip_address"]:
                features["ip_address_urls"] += 1
        
        features["url_details"] = url_features
        
        # Text-based features
        features["exclamation_count"] = text.count('!')
        features["all_caps_ratio"] = self._calculate_caps_ratio(text)
        features["digit_ratio"] = sum(c.isdigit() for c in text) / max(1, len(text))
        features["special_char_ratio"] = sum(c in string.punctuation for c in text) / max(1, len(text))
        
        # Context features
        features["greeting_missing"] = self._check_greeting(text)
        features["sense_of_urgency"] = self._check_urgency_indicators(text)
        features["generic_greeting"] = self._check_generic_greeting(text)
        
        return features
    
    def _analyze_url(self, url: str) -> dict:
        """Analyze individual URL for suspicious characteristics"""
        try:
            parsed = urlparse(url if url.startswith('http') else f'http://{url}')
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            return {
                "original": url,
                "domain": domain,
                "path": path,
                "is_shortener": any(short in domain for short in self.url_shorteners),
                "has_suspicious_tld": any(domain.endswith(tld) for tld in self.suspicious_tlds),
                "is_ip_address": bool(re.match(r'\d+\.\d+\.\d+\.\d+', domain)),
                "has_login_keywords": any(keyword in path for keyword in ['login', 'signin', 'verify', 'secure']),
                "length": len(url)
            }
        except:
            return {"original": url, "error": "parse_failed"}
    
    def _calculate_caps_ratio(self, text: str) -> float:
        """Calculate ratio of uppercase letters"""
        if not text:
            return 0
        letters = [c for c in text if c.isalpha()]
        if not letters:
            return 0
        return sum(1 for c in letters if c.isupper()) / len(letters)
    
    def _check_greeting(self, text: str) -> int:
        """Check if greeting is missing"""
        greetings = {"hi", "hello", "dear", "greetings", "good morning", "good afternoon"}
        first_50 = text[:50].lower()
        return 0 if any(greet in first_50 for greet in greetings) else 1
    
    def _check_urgency_indicators(self, text: str) -> int:
        """Check for urgency indicators"""
        urgency_patterns = [
            r"within \d+ hours?",
            r"within \d+ days?",
            r"immediate action",
            r"act now",
            r"don't delay",
            r"limited time",
            r"expires soon",
            r"last chance"
        ]
        return 1 if any(re.search(pattern, text) for pattern in urgency_patterns) else 0
    
    def _check_generic_greeting(self, text: str) -> int:
        """Check for generic greetings"""
        generic_greetings = ["dear customer", "dear user", "dear account holder", "valued customer"]
        first_100 = text[:100].lower()
        return 1 if any(greet in first_100 for greet in generic_greetings) else 0

# -----------------------------
# 3. Advanced Risk Calculation
# -----------------------------
class RiskCalculator:
    """Machine learning-inspired risk scoring"""
    
    def __init__(self):
        self.weights = {
            # Keyword-based weights
            "threat_score": 0.8,
            "auth_score": 0.7,
            "financial_score": 0.9,
            "impersonation_score": 0.8,
            
            # URL-based weights
            "total_urls": 1.5,
            "suspicious_urls": 2.5,
            "suspicious_domains": 2.0,
            "ip_address_urls": 3.0,
            
            # Text-based weights
            "exclamation_count": 0.3,
            "all_caps_ratio": 0.5,
            "digit_ratio": 0.4,
            "special_char_ratio": 0.3,
            
            # Context weights
            "greeting_missing": 0.6,
            "sense_of_urgency": 1.2,
            "generic_greeting": 0.7
        }
        
        self.thresholds = {
            "high_risk": 7.5,
            "medium_risk": 5.0,
            "low_risk": 3.0
        }
    
    def calculate_score(self, features: dict) -> float:
        """Calculate comprehensive risk score"""
        base_score = 0
        
        # Apply weighted feature scoring
        for feature, value in features.items():
            if feature in self.weights and isinstance(value, (int, float)):
                if feature in ["all_caps_ratio", "digit_ratio", "special_char_ratio"]:
                    # Apply sigmoid-like scaling for ratios
                    scaled_value = 10 * (1 / (1 + 2.718 ** (-10 * (value - 0.3))))
                    base_score += scaled_value * self.weights[feature]
                else:
                    base_score += value * self.weights[feature]
        
        # Apply non-linear scaling
        risk_score = min(10.0, round(self._logistic_scale(base_score), 1))
        
        # Add penalty for multiple suspicious factors
        penalty_factors = [
            features.get("suspicious_urls", 0) > 0,
            features.get("threat_score", 0) > 2,
            features.get("auth_score", 0) > 2,
        ]
        
        if sum(penalty_factors) >= 2:
            risk_score = min(10.0, risk_score + 1.0)
        
        return risk_score
    
    def _logistic_scale(self, x: float) -> float:
        """Apply logistic scaling to smooth score distribution"""
        return 10 / (1 + 2.718 ** (-0.5 * (x - 5)))

# -----------------------------
# 4. Enhanced Classification
# -----------------------------
class PhishingDetector:
    """Main detection class with comprehensive analysis"""
    
    def __init__(self):
        self.extractor = FeatureExtractor()
        self.calculator = RiskCalculator()
    
    def detect(self, text: str) -> dict:
        """Complete phishing detection analysis"""
        if not text or not text.strip():
            return self._error_response("Please enter a message to analyze")
        
        # Preprocess and extract features
        processed_text = preprocess_text(text)
        features = self.extractor.extract_features(processed_text)
        risk_score = self.calculator.calculate_score(features)
        
        # Get detailed classification
        result = self._classify(risk_score, features, text, processed_text)
        
        # Add feature explanations
        result["feature_explanations"] = self._explain_features(features)
        result["recommendations"] = self._generate_recommendations(result["classification"])
        
        return result
    
    def _classify(self, score: float, features: dict, original: str, processed: str) -> dict:
        """Classify based on risk score and features"""
        
        if score >= self.calculator.thresholds["high_risk"]:
            classification = "🔴 High Risk Phishing"
            confidence = "Very High"
            advice = "DO NOT interact. This is highly likely to be a phishing attempt."
            color = "#dc2626"
            severity = "critical"
            
        elif score >= self.calculator.thresholds["medium_risk"]:
            classification = "🟠 Suspicious Message"
            confidence = "Medium-High"
            advice = "Exercise extreme caution. Verify sender through official channels."
            color = "#f97316"
            severity = "high"
            
        elif score >= self.calculator.thresholds["low_risk"]:
            classification = "🟡 Moderate Risk"
            confidence = "Medium"
            advice = "Be cautious. Check for unusual elements before taking action."
            color = "#f59e0b"
            severity = "medium"
            
        else:
            classification = "🟢 Likely Safe"
            confidence = "High"
            advice = "Message appears safe, but remain vigilant."
            color = "#16a34a"
            severity = "low"
        
        # Extract detected keywords from all categories
        keywords = self._extract_detected_keywords(processed)
        
        return {
            "original_text": original,
            "processed_text": processed,
            "features": features,
            "risk_score": score,
            "classification": classification,
            "confidence": confidence,
            "advice": advice,
            "color": color,
            "severity": severity,
            "detected_keywords": keywords,
            "timestamp": self._get_timestamp()
        }
    
    def _extract_detected_keywords(self, text: str) -> dict:
        """Extract detected keywords by category"""
        tokens = set(text.split())
        
        return {
            "threat_keywords": [k for k in self.extractor.threat_keywords if k in tokens],
            "auth_keywords": [k for k in self.extractor.auth_keywords if k in tokens],
            "financial_keywords": [k for k in self.extractor.financial_keywords if k in tokens],
            "impersonation_keywords": [k for k in self.extractor.impersonation_keywords if k in tokens]
        }
    
    def _explain_features(self, features: dict) -> list:
        """Generate human-readable explanations for features"""
        explanations = []
        
        if features.get("threat_score", 0) > 1:
            explanations.append(f"Contains {features['threat_score']:.1f} threat/urgency indicators")
        
        if features.get("auth_score", 0) > 1:
            explanations.append(f"Contains {features['auth_score']:.1f} authentication-related terms")
        
        if features.get("financial_score", 0) > 1:
            explanations.append(f"Contains {features['financial_score']:.1f} financial-related terms")
        
        if features.get("suspicious_urls", 0) > 0:
            explanations.append(f"Contains {features['suspicious_urls']} suspicious shortened URLs")
        
        if features.get("sense_of_urgency", 0) > 0:
            explanations.append("Uses urgency/time pressure tactics")
        
        if features.get("greeting_missing", 0) > 0:
            explanations.append("Missing personalized greeting")
        
        if features.get("exclamation_count", 0) > 3:
            explanations.append(f"Excessive use of exclamation marks ({features['exclamation_count']})")
        
        return explanations
    
    def _generate_recommendations(self, classification: str) -> list:
        """Generate specific recommendations based on classification"""
        recommendations = []
        
        if "High Risk" in classification:
            recommendations.extend([
                "Do not click any links",
                "Do not download attachments",
                "Do not reply with personal information",
                "Report to your IT security team",
                "Delete the message after reporting"
            ])
        elif "Suspicious" in classification:
            recommendations.extend([
                "Verify sender's email address carefully",
                "Contact the organization through official channels",
                "Hover over links to preview destination URLs",
                "Check for spelling and grammar errors",
                "Look for generic greetings"
            ])
        else:
            recommendations.extend([
                "Verify sender identity if unsure",
                "Check URLs before clicking",
                "Enable two-factor authentication",
                "Keep security software updated",
                "Regularly change passwords"
            ])
        
        return recommendations
    
    def _get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def _error_response(self, message: str) -> dict:
        """Generate error response"""
        return {
            "status": "error",
            "message": message,
            "timestamp": self._get_timestamp()
        }

# -----------------------------
# 5. Enhanced Example Messages & Testing
# -----------------------------
def get_example_messages():
    """Get comprehensive example messages for testing"""
    return [
        {
            "title": "🔴 Banking Phishing",
            "text": "URGENT: Your bank account has been SUSPENDED due to suspicious activity. Click http://bit.ly/secure-bank-login to VERIFY your identity immediately or your account will be TERMINATED within 24 hours!",
            "type": "phishing",
            "expected_risk": "high"
        },
        {
            "title": "🔴 PayPal Impersonation",
            "text": "IMPORTANT SECURITY ALERT: Unusual login detected on your PayPal account from new device. Confirm your credentials NOW: https://paypal-secure-verify.xyz/login to prevent account LOCKOUT. OTP required for verification.",
            "type": "phishing", 
            "expected_risk": "high"
        },
        {
            "title": "🟠 Suspicious Microsoft Alert",
            "text": "Dear User, Your Microsoft account needs verification. Please update your security information: http://tinyurl.com/microsoft-account-update. Failure to do so may result in limited access.",
            "type": "suspicious",
            "expected_risk": "medium"
        },
        {
            "title": "🟡 Netflix Account Update",
            "text": "Hello, We're updating our security systems. Please confirm your billing information to continue your Netflix service without interruption.",
            "type": "moderate",
            "expected_risk": "low"
        },
        {
            "title": "🟢 Safe Meeting Reminder",
            "text": "Hi John, just confirming our meeting tomorrow at 2:00 PM in Conference Room B. Please bring the quarterly reports.",
            "type": "safe",
            "expected_risk": "very_low"
        },
        {
            "title": "🔴 IRS Tax Scam",
            "text": "FINAL NOTICE: The IRS has filed a lawsuit against you for tax evasion. Call IMMEDIATELY at 1-800-XXX-XXXX to settle or face legal action. This is your LAST CHANCE!",
            "type": "phishing",
            "expected_risk": "high"
        }
    ]

def run_demo():
    """Run demonstration of the detection system"""
    detector = PhishingDetector()
    examples = get_example_messages()
    
    print("=" * 60)
    print("PhishSense AI Pro - Detection Demo")
    print("=" * 60)
    
    for example in examples:
        print(f"\n{example['title']}")
        print(f"Type: {example['type'].upper()}")
        print(f"Text: {example['text']}")
        
        result = detector.detect(example['text'])
        
        print(f"\nRisk Score: {result['risk_score']}/10")
        print(f"Classification: {result['classification']}")
        print(f"Confidence: {result['confidence']}")
        print(f"Key Features: {', '.join(result['feature_explanations'][:3])}")
        print("-" * 40)

# -----------------------------
# 6. Quick Detection Function (Simple API)
# -----------------------------
def detect_phishing(text: str) -> dict:
    """Simple wrapper for quick phishing detection"""
    detector = PhishingDetector()
    return detector.detect(text)

# -----------------------------
# Main execution
# -----------------------------
if __name__ == "__main__":
    # Run demo when executed directly
    run_demo()