# CL.TE HTTP Request Smuggling

## Description
Front-end proxy uses Content-Length, back-end uses Transfer-Encoding chunked. The disagreement allows an attacker to smuggle a second HTTP request that the front-end does not see but the back-end processes.

## Impact
Cache poisoning, request queue injection, bypass access controls, credential theft via injected responses.

## Remediation
Use HTTP/2 end-to-end, reject requests with both CL and TE headers, normalize headers at proxy level, use same parser for front-end and back-end.