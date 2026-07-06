#!/usr/bin/env python3
"""
Kubernetes Validating Admission Webhook for Sidecar Injection.
Prevents unauthorized sidecar injection by checking namespace labels.
Only allows injection if the namespace has label 'sidecar-injection: enabled'.
"""

import json
import base64
import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler

ALLOWED_NAMESPACE_LABEL = {"sidecar-injection": "enabled"}

class ValidatingWebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        request = json.loads(body)

        # Extract the AdmissionReview from the request
        admission_review = request
        request_uid = admission_review.get('request', {}).get('uid', '')
        object_to_admit = admission_review.get('request', {}).get('object', {})
        namespace = object_to_admit.get('metadata', {}).get('namespace', '')
        annotations = object_to_admit.get('metadata', {}).get('annotations', {})
        
        # Check if injection annotation is present and set to "true"
        inject_annotation = annotations.get('sidecar.istio.io/inject', 'false')
        
        allowed = True
        message = ""
        if inject_annotation.lower() == 'true':
            # Fetch namespace labels from the request (or in a real webhook, you'd query the cluster)
            # For this example, we assume the request includes namespaceLabels (you'd need to add it to the webhook config)
            namespace_labels = admission_review.get('request', {}).get('namespaceLabels', {})
            if not namespace_labels:
                # In production, you'd fetch from Kubernetes API or use a cached list
                # For demo, we fail closed: reject if we cannot verify namespace labels
                allowed = False
                message = "Namespace label verification failed: cannot determine if sidecar injection is allowed."
            elif not (ALLOWED_NAMESPACE_LABEL.get('sidecar-injection') == namespace_labels.get('sidecar-injection')):
                allowed = False
                message = "Sidecar injection is not allowed in this namespace. Namespace must have label 'sidecar-injection: enabled'."
        
        # Build AdmissionResponse
        admission_response = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": request_uid,
                "allowed": allowed,
                "status": {
                    "message": message
                } if not allowed else {}
            }
        }
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(admission_response).encode())

def run_server():
    server_address = ('', 8443)
    httpd = HTTPServer(server_address, ValidatingWebhookHandler)
    
    # Use TLS (you need to provide cert.pem and key.pem in real deployment)
    httpd.socket = ssl.wrap_socket(httpd.socket,
                                   certfile='cert.pem',
                                   keyfile='key.pem',
                                   server_side=True)
    print('Starting webhook server on port 8443...')
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()
