# shadowfox/agents/waf_behavior_classifier.py

import re
import json
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import requests
import time
import logging
from urllib.parse import urljoin, quote

class WAFBehaviorClassifier:
    """
    AI modul koji identifikuje WAF i zaštitne sisteme kroz analizu ponašanja
    bez proboja - samo kroz passive fingerprinting
    """
    
    def __init__(self, operator):
        self.logger = logging.getLogger('WAFClassifier')
        self.session = requests.Session()
        
        # WAF fingerprints - poznati potpisi različitih WAF-ova
        self.waf_signatures = self._load_waf_signatures()
        
        # Test payloads za identifikaciju (bezopasni)
        self.identification_payloads = [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "UNION SELECT 1,2,3--",
            "javascript:alert(1)",
            "${7*7}",
            "{{7*7}}",
            "<img src=x onerror=alert(1)>",
            "' AND 1=1--",
            "1 OR 1=1"
        ]
        
        # Response patterns za različite WAF-ove
        self.response_patterns = {
            'cloudflare': [
                r'cloudflare',
                r'cf-ray',
                r'attention required',
                r'cloudflare.com',
                r'__cfduid'
            ],
            'aws_waf': [
                r'aws',
                r'x-amzn-requestid',
                r'x-amz-',
                r'cloudfront',
                r'amazon'
            ],
            'akamai': [
                r'akamai',
                r'x-akamai',
                r'ghost',
                r'edgescape'
            ],
            'incapsula': [
                r'incapsula',
                r'x-iinfo',
                r'visid_incap',
                r'incap_ses'
            ],
            'sucuri': [
                r'sucuri',
                r'x-sucuri',
                r'sucuri.net'
            ],
            'modsecurity': [
                r'mod_security',
                r'modsecurity',
                r'reference #[0-9]+',
                r'access denied'
            ],
            'barracuda': [
                r'barracuda',
                r'barra',
                r'web application firewall'
            ],
            'f5_bigip': [
                r'f5',
                r'bigip',
                r'x-waf-event',
                r'bigipserver'
            ],
            'imperva': [
                r'imperva',
                r'x-iinfo',
                r'incapsula'
            ],
            'fortinet': [
                r'fortinet',
                r'fortigate',
                r'fortimail'
            ]
        }
        
        # Status code patterns
        self.waf_status_codes = {
            'cloudflare': [403, 503, 520, 521, 522, 523, 524],
            'aws_waf': [403, 429],
            'akamai': [403, 405],
            'incapsula': [403, 406, 501],
            'modsecurity': [403, 406, 501, 999],
            'barracuda': [403, 503],
            'f5_bigip': [403, 406],
            'imperva': [403, 406]
        }
    
    def _load_waf_signatures(self) -> Dict:
        """Učitava WAF potpise - headers, cookies, behavior patterns"""
        return {
            'cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id', 'server: cloudflare'],
                'cookies': ['__cfduid', '__cfuid', 'cf_clearance'],
                'response_headers': ['cf-polished', 'cf-bgj', 'cf-visitor'],
                'body_patterns': ['cloudflare', 'attention required', 'please turn javascript on'],
                'redirect_patterns': ['challenge', 'cdn-cgi']
            },
            'aws_waf': {
                'headers': ['x-amzn-requestid', 'x-amz-cf-id', 'x-amz-cf-pop', 'server: cloudfront'],
                'cookies': ['aws-waf-token'],
                'response_headers': ['x-cache: hit from cloudfront', 'via: cloudfront'],
                'body_patterns': ['aws', 'amazon web services', 'request blocked'],
                'redirect_patterns': []
            },
            'akamai': {
                'headers': ['x-akamai-transformed', 'x-akamai-staging', 'server: akamaighost'],
                'cookies': ['ak_bmsc'],
                'response_headers': ['x-check-cacheable'],
                'body_patterns': ['akamai', 'reference #', 'ghost'],
                'redirect_patterns': []
            },
            'incapsula': {
                'headers': ['x-iinfo', 'x-cdn'],
                'cookies': ['visid_incap', 'incap_ses', 'nlbi'],
                'response_headers': ['x-origin-x', 'x-true-cache-key'],
                'body_patterns': ['incapsula', 'access denied', 'incident id'],
                'redirect_patterns': ['/_Incapsula_Resource']
            },
            'sucuri': {
                'headers': ['x-sucuri-id', 'x-sucuri-cache'],
                'cookies': ['sucuri-'],
                'response_headers': ['server: sucuri/cloudproxy'],
                'body_patterns': ['sucuri website firewall', 'access denied'],
                'redirect_patterns': []
            },
            'modsecurity': {
                'headers': ['server: apache', 'server: nginx'],
                'cookies': [],
                'response_headers': [],
                'body_patterns': ['mod_security', 'modsecurity', 'reference #\\d+', 'access denied'],
                'redirect_patterns': []
            },
            'barracuda': {
                'headers': ['x-barracuda-url', 'x-barracuda-start-time'],
                'cookies': ['barra'],
                'response_headers': [],
                'body_patterns': ['barracuda', 'web application firewall', 'blocked by policy'],
                'redirect_patterns': []
            },
            'f5_bigip': {
                'headers': ['x-waf-event-info', 'server: bigip'],
                'cookies': ['bigipserver', 'f5-'],
                'response_headers': ['x-cnection'],
                'body_patterns': ['f5', 'bigip', 'the requested url was rejected'],
                'redirect_patterns': []
            }
        }
    
    def analyze_waf_behavior(self, target_url: str, mission_id: str = None) -> Dict[str, Any]:
        """
        Glavna funkcija za analizu WAF ponašanja
        """
        if mission_id:
            self.operator.current_mission_id = mission_id
        
        self.logger.info(f"Počinje WAF analiza za: {target_url}")
        
        analysis_result = {
            "target_url": target_url,
            "timestamp": time.time(),
            "detected_wafs": {},
            "confidence_scores": {},
            "behavioral_analysis": {},
            "response_patterns": {},
            "recommendations": [],
            "bypass_hints": []
        }
        
        try:
            # 1. Passive fingerprinting
            passive_results = self._passive_fingerprinting(target_url)
            analysis_result["passive_detection"] = passive_results
            
            # 2. Behavioral testing (bezopasno)
            behavioral_results = self._behavioral_testing(target_url)
            analysis_result["behavioral_analysis"] = behavioral_results
            
            # 3. Response time analysis
            timing_results = self._timing_analysis(target_url)
            analysis_result["timing_analysis"] = timing_results
            
            # 4. Error page fingerprinting
            error_results = self._error_page_analysis(target_url)
            analysis_result["error_analysis"] = error_results
            
            # 5. Kombinuj rezultate i izračunaj confidence
            final_detection = self._combine_results(
                passive_results, behavioral_results, timing_results, error_results
            )
            analysis_result.update(final_detection)
            
            # 6. Generiši preporuke
            analysis_result["recommendations"] = self._generate_recommendations(final_detection)
            
            # Loguj u operator
            self.operator.log_agent_action("WAFClassifier", "waf_analysis_completed", {
                "target": target_url,
                "detected_wafs": list(analysis_result["detected_wafs"].keys()),
                "highest_confidence": max(analysis_result["confidence_scores"].values()) if analysis_result["confidence_scores"] else 0
            })
            
        except Exception as e:
            self.logger.error(f"Greška u WAF analizi: {e}")
            analysis_result["error"] = str(e)
        
        return analysis_result
    
    def _passive_fingerprinting(self, url: str) -> Dict:
        """
        Pasivno prepoznavanje kroz headers, cookies, server responses
        """
        results = {
            "detected_signatures": {},
            "suspicious_headers": [],
            "protection_indicators": []
        }
        
        try:
            # Osnovni zahtev
            response = self.session.get(url, timeout=10, allow_redirects=True)
            
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            cookies = response.cookies
            body = response.text.lower()
            
            # Proveri sve WAF potpise
            for waf_name, signatures in self.waf_signatures.items():
                score = 0
                matches = []
                
                # Header matching
                for header_sig in signatures['headers']:
                    for header_name, header_value in headers.items():
                        if header_sig.lower() in f"{header_name}: {header_value}":
                            score += 3
                            matches.append(f"Header: {header_sig}")
                
                # Cookie matching
                for cookie_sig in signatures['cookies']:
                    for cookie in cookies:
                        if cookie_sig.lower() in cookie.name.lower():
                            score += 2
                            matches.append(f"Cookie: {cookie_sig}")
                
                # Body pattern matching
                for pattern in signatures['body_patterns']:
                    if re.search(pattern.lower(), body):
                        score += 2
                        matches.append(f"Body: {pattern}")
                
                if score > 0:
                    results["detected_signatures"][waf_name] = {
                        "score": score,
                        "matches": matches
                    }
            
            # Sumnjiva zaglavlja
            security_headers = [
                'x-frame-options', 'x-xss-protection', 'x-content-type-options',
                'content-security-policy', 'strict-transport-security'
            ]
            
            for header in security_headers:
                if header in headers:
                    results["suspicious_headers"].append(header)
            
            # Indikatori zaštite
            protection_indicators = []
            if 'server' in headers and any(waf in headers['server'] for waf in ['cloudflare', 'nginx', 'apache']):
                protection_indicators.append(f"Server: {headers['server']}")
            
            if any(header.startswith('x-') for header in headers.keys()):
                protection_indicators.append("Custom X-Headers detected")
            
            results["protection_indicators"] = protection_indicators
            
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _behavioral_testing(self, url: str) -> Dict:
        """
        Testiranje ponašanja kroz bezopasne payloade
        """
        results = {
            "response_variations": {},
            "blocking_patterns": {},
            "rate_limiting": False
        }
        
        try:
            # Baseline zahtev
            baseline = self.session.get(url, timeout=10)
            baseline_time = baseline.elapsed.total_seconds()
            
            # Test različitih payloada
            for i, payload in enumerate(self.identification_payloads[:5]):  # Samo prvih 5 da bude brže
                test_responses = []
                
                # Test kao URL parametar
                test_url = f"{url}?test={quote(payload)}"
                try:
                    response = self.session.get(test_url, timeout=10)
                    test_responses.append({
                        "method": "url_param",
                        "status_code": response.status_code,
                        "response_time": response.elapsed.total_seconds(),
                        "content_length": len(response.content),
                        "headers": dict(response.headers)
                    })
                except:
                    pass
                
                # Test kao User-Agent
                try:
                    headers = {'User-Agent': payload}
                    response = self.session.get(url, headers=headers, timeout=10)
                    test_responses.append({
                        "method": "user_agent",
                        "status_code": response.status_code,
                        "response_time": response.elapsed.total_seconds(),
                        "content_length": len(response.content)
                    })
                except:
                    pass
                
                results["response_variations"][payload] = test_responses
                
                # Rate limiting detection
                if i > 0:
                    time.sleep(0.5)  # Kratka pauza između zahteva
            
            # Analiza blokiranje pattern-a
            blocking_patterns = {}
            for payload, responses in results["response_variations"].items():
                for resp in responses:
                    if resp["status_code"] in [403, 406, 429, 503]:
                        if payload not in blocking_patterns:
                            blocking_patterns[payload] = []
                        blocking_patterns[payload].append(resp["status_code"])
            
            results["blocking_patterns"] = blocking_patterns
            
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _timing_analysis(self, url: str) -> Dict:
        """
        Analiza vremena odgovora za detektovanje WAF-a
        """
        results = {
            "baseline_time": 0,
            "suspicious_delays": [],
            "timing_variance": 0
        }
        
        try:
            times = []
            
            # 5 baseline zahteva
            for _ in range(5):
                start_time = time.time()
                response = self.session.get(url, timeout=15)
                end_time = time.time()
                times.append(end_time - start_time)
                time.sleep(0.2)
            
            baseline_avg = sum(times) / len(times)
            variance = sum((t - baseline_avg) ** 2 for t in times) / len(times)
            
            results["baseline_time"] = baseline_avg
            results["timing_variance"] = variance
            
            # Test sa sumnjivim zahtevima
            suspicious_times = []
            for payload in self.identification_payloads[:3]:
                try:
                    start_time = time.time()
                    test_url = f"{url}?test={quote(payload)}"
                    response = self.session.get(test_url, timeout=15)
                    end_time = time.time()
                    
                    response_time = end_time - start_time
                    suspicious_times.append(response_time)
                    
                    # Ako je značajno sporiji, može biti WAF
                    if response_time > baseline_avg * 2:
                        results["suspicious_delays"].append({
                            "payload": payload,
                            "time": response_time,
                            "baseline_ratio": response_time / baseline_avg
                        })
                except:
                    pass
                
                time.sleep(0.3)
        
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _error_page_analysis(self, url: str) -> Dict:
        """
        Analiza error stranica za WAF fingerprinting
        """
        results = {
            "error_signatures": {},
            "custom_error_pages": False
        }
        
        # Test zahtevi koji će verovatno proizvesti greške
        error_tests = [
            "/non-existent-page-12345",
            "/../../../etc/passwd",
            "/?id=1'",
            "/admin/config.php"
        ]
        
        try:
            for test_path in error_tests:
                test_url = urljoin(url, test_path)
                try:
                    response = self.session.get(test_url, timeout=10)
                    
                    if response.status_code in [403, 404, 406, 503]:
                        error_content = response.text.lower()
                        
                        # Pronađi WAF potpise u error stranicama
                        for waf_name, patterns in self.response_patterns.items():
                            matches = []
                            for pattern in patterns:
                                if re.search(pattern, error_content) or re.search(pattern, str(response.headers).lower()):
                                    matches.append(pattern)
                            
                            if matches:
                                if waf_name not in results["error_signatures"]:
                                    results["error_signatures"][waf_name] = []
                                results["error_signatures"][waf_name].extend(matches)
                        
                        # Custom error page detection
                        if len(error_content) > 1000 or any(keyword in error_content for keyword in ['blocked', 'firewall', 'security', 'denied']):
                            results["custom_error_pages"] = True
                
                except:
                    continue
                
                time.sleep(0.2)
        
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _combine_results(self, passive: Dict, behavioral: Dict, timing: Dict, error: Dict) -> Dict:
        """
        Kombinuje sve rezultate i izračunava finalne confidence score-ove
        """
        waf_scores = defaultdict(float)
        detection_evidence = defaultdict(list)
        
        # Passive detection scores
        if "detected_signatures" in passive:
            for waf_name, data in passive["detected_signatures"].items():
                waf_scores[waf_name] += data["score"] * 0.4  # 40% weight
                detection_evidence[waf_name].extend([f"Passive: {m}" for m in data["matches"]])
        
        # Behavioral analysis scores
        if "blocking_patterns" in behavioral:
            for payload, status_codes in behavioral["blocking_patterns"].items():
                for waf_name, expected_codes in self.waf_status_codes.items():
                    if any(code in expected_codes for code in status_codes):
                        waf_scores[waf_name] += 2.0  # Behavioral evidence
                        detection_evidence[waf_name].append(f"Behavioral: {status_codes} for {payload[:20]}...")
        
        # Timing analysis
        if timing.get("suspicious_delays"):
            for delay_info in timing["suspicious_delays"]:
                if delay_info["baseline_ratio"] > 3:  # Značajno sporiji
                    waf_scores["generic_waf"] += 1.5
                    detection_evidence["generic_waf"].append(f"Timing: {delay_info['baseline_ratio']:.2f}x slower")
        
        # Error page analysis
        if "error_signatures" in error:
            for waf_name, matches in error["error_signatures"].items():
                waf_scores[waf_name] += len(matches) * 1.5
                detection_evidence[waf_name].extend([f"Error: {m}" for m in matches])
        
        # Normalizuj score-ove na 0-100 skalu
        max_possible_score = 20.0  # Približno maksimalan mogući score
        confidence_scores = {}
        for waf_name, score in waf_scores.items():
            confidence_scores[waf_name] = min(100, (score / max_possible_score) * 100)
        
        # Filter samo WAF-ove sa dovoljnim confidence-om
        detected_wafs = {
            waf: {
                "confidence": conf,
                "evidence": detection_evidence[waf]
            }
            for waf, conf in confidence_scores.items() 
            if conf >= 20  # Minimum 20% confidence
        }
        
        return {
            "detected_wafs": detected_wafs,
            "confidence_scores": confidence_scores,
            "all_evidence": dict(detection_evidence)
        }
    
    def _generate_recommendations(self, detection_results: Dict) -> List[str]:
        """
        Generiše preporuke na osnovu detektovanih WAF-ova
        """
        recommendations = []
        detected_wafs = detection_results.get("detected_wafs", {})
        
        if not detected_wafs:
            recommendations.append("No WAF detected - proceed with standard testing approach")
            recommendations.append("Monitor for rate limiting and unusual response patterns")
        else:
            for waf_name, data in detected_wafs.items():
                confidence = data["confidence"]
                
                if waf_name == "cloudflare":
                    recommendations.append(f"Cloudflare detected ({confidence:.1f}% confidence)")
                    recommendations.append("- Use slow, distributed requests to avoid rate limiting")
                    recommendations.append("- Consider real browser automation for JS challenges")
                    recommendations.append("- Test different geographic locations")
                
                elif waf_name == "aws_waf":
                    recommendations.append(f"AWS WAF detected ({confidence:.1f}% confidence)")
                    recommendations.append("- Test with different User-Agents and IP ranges")
                    recommendations.append("- Monitor for AWS-specific rate limiting patterns")
                
                elif waf_name == "modsecurity":
                    recommendations.append(f"ModSecurity detected ({confidence:.1f}% confidence)")
                    recommendations.append("- Focus on evasion techniques for ModSec rules")
                    recommendations.append("- Test with encoded payloads and case variations")
                
                elif waf_name == "incapsula":
                    recommendations.append(f"Incapsula detected ({confidence:.1f}% confidence)")
                    recommendations.append("- Expect aggressive client fingerprinting")
                    recommendations.append("- Use realistic browser behavior patterns")
        
        # Generic preporuke
        if any(conf > 50 for conf in detection_results.get("confidence_scores", {}).values()):
            recommendations.append("High confidence WAF detection - implement stealth techniques")
            recommendations.append("- Randomize request timing and patterns")
            recommendations.append("- Use proxy rotation and different user agents")
        
        return recommendations

# Test funkcionalnosti
if __name__ == "__main__":
    from operator import ShadowFoxOperator
    
    # Test
    op = ShadowFoxOperator()
    classifier = WAFBehaviorClassifier(op)
    
    # Test sa poznatim WAF-om (Cloudflare)
    test_target = "https://httpbin.org"  # Safe test target
    mission_id = op.create_mission(test_target, "WAF test misija")
    
    results = classifier.analyze_waf_behavior(test_target, mission_id)
    
    print("=== WAF Analysis Results ===")
    print(json.dumps(results, indent=2, default=str))

