import time
import hmac, hashlib, json
from statistics import mean, stdev
from sso_federation import _create_jwt, _verify_jwt

secret = "shared-idp-key"
payload = {"user": "alice"}

# Create a valid token
valid_token = _create_jwt(payload, secret)

# Forge a token by tampering with the signature (not the payload)
parts = valid_token.split(".")
sig = parts[2]
# Flip the last character to guarantee mismatch
forged_sig = sig[:-1] + ("0" if sig[-1] != "0" else "1")
forged_token = ".".join([parts[0], parts[1], forged_sig])

def measure(token, label, iterations=500):
    times = []
    for i in range(iterations):
        start = time.perf_counter_ns()
        _verify_jwt(token, secret)
        end = time.perf_counter_ns()
        times.append(end - start)
    avg = mean(times)
    sd = stdev(times)
    print(f"{label} average ns over {iterations} runs: {avg:.0f} (±{sd:.0f})")
    return avg

# Run timing tests
avg_valid = measure(valid_token, "Valid token")
avg_forged = measure(forged_token, "Forged token")
delta = avg_valid - avg_forged
print(f"Δt (valid - forged) = {delta:.0f} ns")

# Show verification results
print("\nVerification results:")
print(f"Valid token: {_verify_jwt(valid_token, secret)}")
print(f"Forged token: {_verify_jwt(forged_token, secret)}")
