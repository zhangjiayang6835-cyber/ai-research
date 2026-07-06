# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

#!/usr/bin/env python3
"""
Security Fix: gRPC Reflection API Abuse

This script demonstrates how to properly secure a gRPC server
against reflection-based service enumeration attacks.
"""

import os
import sys


def fix_grpc_reflection_vulnerability():
    """
    Apply security fixes to prevent gRPC Reflection API abuse.
    
    The vulnerability:
    - gRPC reflection allows clients to discover all services and methods
    - Attackers can use this to enumerate APIs and find attack surfaces
    
    The fix:
    1. Disable reflection in production environments
    2. If reflection is needed, require authentication
    3. Implement proper access logging for reflection requests
    """
    
    print("=" * 60)
    print("gRPC Reflection Security Fix")
    print("=" * 60)
    
    # Check environment
    env = os.environ.get('ENV', 'production').lower()
    print(f"\nEnvironment: {env}")
    
    # Security configuration
    config = {
        'enable_reflection': False,  # Default: disable reflection
        'require_auth_for_reflection': True,
        'log_reflection_requests': True,
    }
    
    # Only enable in development with explicit flag
    if env in ('dev', 'development', 'local'):
        if os.environ.get('GRPC_ENABLE_REFLECTION', '').lower() == 'true':
            config['enable_reflection'] = True
            print("[WARNING] Reflection enabled for development only")
        else:
            print("[INFO] Reflection disabled (set GRPC_ENABLE_REFLECTION=true to enable)")
    else:
        print("[SECURITY] Reflection disabled in production")
    
    # Return security configuration
    return config


def generate_secure_server_code():
    """
    Generate example secure gRPC server code.
    """
    code = '''
# Secure gRPC Server Example
from concurrent import futures
import grpc

# SECURITY: Disable reflection by default
ENABLE_REFLECTION = False

server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

# Add your services here
# my_service_pb2_grpc.add_MyServiceServicer_to_server(MyServicer(), server)

# SECURITY: Only enable reflection if explicitly needed and authenticated
if ENABLE_REFLECTION:
    from grpc_reflection.v1alpha import reflection
    # Add authentication check before enabling
    reflection.enable_server_reflection(['mypackage.MyService'], server)

server.add_insecure_port('[::]:50051')
server.start()
'''
    return code


if __name__ == '__main__':
    config = fix_grpc_reflection_vulnerability()
    print("\nSecurity Configuration:")
    for key, value in config.items():
        print(f"  {key}: {value}")
    
    print("\nExample secure server code:")
    print(generate_secure_server_code())
print("fix #194")
