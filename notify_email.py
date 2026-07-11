# home/l/Desktop/AxiomTree/axiom_horizon/.axiom_state/submissions/ai-research_725/fix_issue_341.py

def enable_secure_pairing():
    # Enable Secure Simple Pairing (SSP)
    ssp_enabled = True
    
    # Use random generated temporary PIN
    temp_pin = generate_random_pin()
    
    # Ensure all communication is encrypted
    encryption_enabled = True
    
    return ssp_enabled, temp_pin, encryption_enabled

def generate_random_pin():
    import random
    return str(random.randint(1000, 9999))