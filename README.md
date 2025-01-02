# JWT utility Package

The **JWT Utility Package** is a lightweight, dependency-free library written in Go that simplifies the creation, signing, and validation of JSON Web Tokens (JWT). This package enables developers to integrate JWT-based authentication into their applications with ease, providing support for common claims and custom data.


## Features

- **Generate Tokens**: Create and sign JWTs with customizable claims.
- **Validate Tokens**: Verify the integrity and validity of JWTs.
- **Extract Claims**: Parse and access standard or custom claims from a token.
- **Common Claims Support**:
  - `exp` (Expiration Time)
  - `iss` (Issuer)
  - `sub` (Subject)
  - `aud` (Audience)
- **Custom Claims**: Add any additional key-value pairs to your token payload.
- **Secure**: Uses HMAC with SHA-256 for signing and validation.
- **No External Dependencies**: Designed to be lightweight and self-contained.


## Installation

To use the **JWT Utility Package** in your project, follow these steps:

**Import** the package in your **GO** project:
```go
import jwtUtility "github.com/dvl-sagar/jwtUtiltyGo"
```
