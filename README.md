# Discourse Key Authentication Example

An example implementation of the Discourse "User API Key" authentication flow using Node.js, Express, and node-forge.

## Setup

Generate a keypair before running the application.
`openssl genrsa -out keypair.pem 2048`

Install OpenSSL using [Shining Light Productions](https://slproweb.com/products/Win32OpenSSL.html)

## Security Note

This implementation uses RSAES-PKCS1-V1_5 padding which has known [vulnerabilities](https://www.cvedetails.com/cve/CVE-2023-46809/). Use for testing purposes only.

## Example Response

```json
{
  "id": 3130769,
  "username": "dev_shkssj",
  "avatar_template": "/user_avatar/forum.cfx.re/dev_shkssj/{size}/4350194_2.png"
  // ...rest
}
```
