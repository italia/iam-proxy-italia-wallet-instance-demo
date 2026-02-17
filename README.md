# iam-proxy-italia-wallet-instance-demo

Demo wallet instance for Relying Party and Credential Issuer assessment and developer debugging — IAM Proxy Italia ecosystem.
<br/>
## Table of Contents

## 1. Overview
This is a Web application that acts as a Wallet Instance, in full compliance with the [IT Wallet specifications 1.0.0](https://italia.github.io/eid-wallet-it-docs/releases/v1.0.0/en/).

The application enables users to:

- Obtain, store, and present PID, mDL and more digital credentials.
- Regularly verify the status of the digital credentials stored in the Wallet.

The main purpose of this project is to test whether Credential Issuers and Relying Parties follow the rules, and shows how they share and use credentials.

<br/>


## 2. Specifications Employed

The application is written in **Python** and built with the **Flask** framework. It uses [sd-jwt-python](https://github.com/openwallet-foundation-labs/sd-jwt-python) library from the **OpenWallet Foundation Labs** to handle SD-JWT.

It complies with the following specifications:

- [IT Wallet Technical Documentation v1.0](https://italia.github.io/eid-wallet-it-docs/releases/v1.0.0/en)
 
- [OpenID4VCI v1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 
- [OpenID4VP v1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)

- [OpenID.Federation v1.0 - draft 43](https://openid.net/specs/openid-federation-1_0.html)

- [OpenID.Federation Wallet v1.0 - draft 03](https://openid.net/specs/openid-federation-wallet-1_0.html)


<br/>

## 3. Important things to know

This project is meant **only for testing and learning purposes** and SHOULD NOT be used in production environments.


## 4. Application configuration

The project requires a configuration file named **config.json**, located in the folder **/config** inside the root directory.
This file defines several parameters needed for the application to run correctly.

Before starting the project, make sure to create or update the *config.json* file with the appropriate values.
An example configuration is provided in the [config.json.example](config.json.example) file.

### Configuration Parameters

| Name | Type | Description |
|------|------|--------------|
| `ms_trust_configuration` | JSON Object | Root section defining trust configurations for EU countries. |
| `ms_trust_configuration.<ISO_country_code>` | JSON Object | Trust configuration of a specific EU country (e.g. `IT`). |
| `ms_trust_configuration.<ISO_country_code>.trust_root` | String | Federation Entity ID of the Trust Anchor. |
| `ms_trust_configuration.<ISO_country_code>.trust_framework` | String | Trust framework name (e.g. `oid-fed`). |
| `metadata` | JSON Object | Metadata configuration used by the applicattion, including network, flow, and wallet parameters. |
| `metadata.use_proxy` | Boolean | Enables or disables the use of an HTTP/HTTPS proxy. |
| `metadata.http_proxy` | String | HTTP proxy address (host:port). |
| `metadata.https_proxy` | String | HTTPS proxy address (host:port). |
| `metadata.no_proxy` | String | Comma-separated list of hosts that should bypass the proxy. |
| `metadata.spec_version` | String | Version of the Wallet specification supported by the implementation (e.g. `v1.0.0`). |
| `metadata.initialize_flow` | JSON Object | Defines the configuration of the Initialization flow (PID Issuance flow) implemented by the application. |
| `metadata.initialize_flow.idphints` | JSON Object | Section that defines the Identity Providers (IdPs) to be used for each supported identification methods: *CIE Level 3*, *CIE Level 2*, *SPID Level 2*.|
| `metadata.initialize_flow.idphints.CIE3` | String | URL of the Identity Provider for CIE Level 3. |
| `metadata.initialize_flow.idphints.CIE2` | String | URL of the Identity Provider for CIE Level 2. |
| `metadata.initialize_flow.idphints.SPID2` | String | URL of the Identity Provider SPID Level 2. |
| `metadata.initialize_flow.credential_configuration_id` | String | Credential configuration identifier used during initialization (e.g. `dc_sd_jwt_PersonIdentificationData`). |
| `metadata.initialize_flow.response_mode` | String | Authorization response mode (e.g. `query`). |
| `metadata.initialize_flow.response_type` | String | Authorization response type (e.g. `code`). |
| `metadata.initialize_flow.redirect_uri` | String | Redirect URI where the authorization response is sent. |
| `metadata.credential_flow` | JSON Object | Defines the configuration of the Credential Issuance flow (EAA Issuance flow) implemented by the application. |
| `metadata.credential_flow.response_mode` | String | Authorization response mode (e.g. `query`, `form_post.jwt`). |
| `metadata.credential_flow.response_type` | String | Authorization Response type (e.g. `code`). |
| `metadata.credential_flow.redirect_uri` | String | Redirect URI where the authorization response is sent. |
| `metadata.credential_flow.credential_configurations_supported` | JSON Array | List of supported credential configuration identifiers. |
| `metadata.presentation_flow` | JSON Object | Defines the configuration of the Presentation Remote flow implemented by the application. |
| `metadata.presentation_flow.response_mode` | String | Authorization response mode (e.g. `direct_post.jwt`). |
| `metadata.presentation_flow.response_type` | String | Authorization response type (e.g. `vp_token`). |
| `metadata.presentation_flow.status_assertion_supported` | Boolean | Indicates if status assertion is supported in Presentation Remote flow. |
| `metadata.wallet_provider` | JSON Object | Defines the configuration of the wallet provider associated with the application.|
| `metadata.wallet_provider.id` | String | Federation Entity ID of the wallet provider. |
| `metadata.wallet_provider.key` | JSON Object | Cryptographic key of the wallet provider (an EC private key in JWK format) |
| `logging` | JSON Object | Defines the configuration of the logging system used by application. |


<br/>

## 4. How to build and run application

### 4.1. Standalone Mode

#### 4.1.1. Prerequisites

* Python 3.12+

#### 4.1.2. Instructions

🗂️ Step 0 — Move to the project root directory

Before running any command, make sure you are located in the root directory of the project, where the <code>pyproject.toml</code> and <code>app.py</code> files are placed.

```
cd path/to/your/project
```

1️⃣ Setup a virtual environment

```
python -m venv venv

source venv/Scripts/activate
```

2️⃣ Install dependencies

```
pip install .
```

3️⃣ Build and run 

```
python app.py
```

4️⃣ Open your browser at: https://localhost:8080/

#### 4.1.3. Local checks (before pushing / PR)

Run quality and security checks locally before opening a PR:

```bash
make install-check-deps   # one-time: install ruff, radon, bandit
make check               # run ruff (lint+format), radon (complexity), bandit (security)
```

### 4.2. Container Mode

#### 4.2.1. Prerequisites

* Docker or other container platform

#### 4.2.2. Instructions
🗂️ Step 0 — Move to the project root directory

Before running any command, make sure you are located in the root directory of the project, where the <code>Dockerfile</code> and <code>docker-compose.yml</code> files are placed.

```
cd path/to/your/project
```

1️⃣ Build a new image and run 

```
docker compose --profile build up --build
```

2️⃣ Check image inside the PC
```
docker images

REPOSITORY          TAG       IMAGE ID       SIZE
my-wallet:1.0.0     latest    abc123def456   250MB
```
3️⃣ Check container running inside the PC
```
docker ps -a

CONTAINER ID   IMAGE             COMMAND           CREATED        STATUS              PORTS                                         NAMES
44de42677c00   my-wallet:1.0.0   "python app.py"   35 hours ago   Up About a minute   0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp   my-wallet
```

4️⃣ Open your browser at: https://localhost:8080/

#### 4.2.3. Export image from one PC to another

1️⃣ Check image inside the PC 1
```
docker images

REPOSITORY          TAG       IMAGE ID       SIZE
my-wallet:1.0.0     latest    abc123def456   250MB

```
2️⃣ Export image from PC 1

```
docker save my-wallet:1.0.0 | gzip > my-wallet.tar.gz
```

3️⃣ Import image to PC 2

```
gzip -dc my-wallet.tar.gz | docker load
```

4️⃣ Check image inside the PC 2
```
docker images

REPOSITORY          TAG       IMAGE ID       SIZE
my-wallet:1.0.0     latest    abc123def456   250MB
```

<br/>

## 5. How to use the application

1️⃣ Launch the application

2️⃣ Open your browser at: https://localhost:8080/

3️⃣ You will be presented with a welcome screen where you will be asked to create a PIN for future logins.


### 5.1 Use Case: PID Issuance flow (Wallet initiated)

1. In the Wallet home page that appears, select your EU State, choose an identification method (one of *CIE Level 3*, *CIE Level 2*, *SPID Level 2*) and tap "Inizializza" button.
2. The Wallet Instance discovers the trusted PID Provider using the Federation Services of the Trust Annchor, establishing the trust to the PID Provider according to the Trust Model and obtaining its metadata that discloses the formats of the PID, the algorithms supported, and any other parameter required for interoperability needs.
3.  Using the Authorization Code Flow defined in [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html), the Wallet Instance requests the PID to the PID Provider.
4. The PID Provider checks the authenticity and validity of the Wallet Instance, establishing the trust to the Wallet Provider and obtaining Wallet metadata with the parameters required for interoperability needs, according to the Trust Model.
5. The PID Provider authenticates the user through the National eID system corresponding to the identification method chosen in step 1. For this reason, the Wallet Instance is redirected to the login page of the National eID system.
6. Once the user has been successfully authenticated, the National eID system redirects the Wallet Instance back to the PID Provider. The PID Provider then extracts the authenticated user’s data from the received request and fetch of PID data from National Public Registry (ANPR) which acts as Authentic Source.
7. The PID Provider releases a PID bound to the key material held by the requesting Wallet Instance
8. Upon receiving the PID, the Wallet Instance verifies its authenticity and integrity by checking the digital signature. Only after successful verification is the PID securely stored within the Wallet
9. You will be redirected back to the Wallet home page, which displays the PID card. The flow is now complete.

### 5.2 Use Case: EAA Issuance flow (Wallet initiated)

1. The Wallet Instance obtains the list of the trusted Credential Providers using the Federation Services of the Trust Anchor, then inspects the metadata looking for the Digital Credential capabilities of each Provider.
2. On the Wallet home page, tap "Aggiungi" button, select a Digital Credential type from the popup that appears, and then tap "Conferma" button.
3. Using the Authorization Code Flow defined in [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html), the Wallet Instance requests the selected Digital Credential to the right Provider.
4. The Credential Provider checks the authenticity and validity of the Wallet Instance, establishing the trust to the Wallet Provider and obtaining Wallet metadata with the parameters required for interoperability needs, according to the Trust Model.
5. The Credential Provider, acting as a Relying Party Instance, authenticates the User evaluating the presentation of the PID.
6. Once the user has been successfully authenticated, the PID Provider fetch of Digital Credential data from the relevant Authentic Source.
7.  The Credential Provider releases a Digital Credential bound to the key material held by the requesting Wallet Instance
8.  Upon receiving the Digital Credential, the Wallet Instance verifies its authenticity and integrity by checking the digital signature. Only after successful verification is the Credential securely stored within the Wallet
9.  You will be redirected back to the Wallet home page, which displays the Digital Credential card. The flow is now complete.

### 5.3 Use Case: Presentation Remote flow

1. On the Wallet home page, tap 'Relying Party' button and wait for the Wallet Instance to obtain the list of trusted Relying Parties using the Trust Anchor's Federation Services.
2. Select a Relying Party from the popup that appears.
3. In another browser tab, navigate to the homepage of the selected Relying Party... 
4. TO-DO

<br/>

## 6. Disclaimer

The released software is an initial development release version: 
-  The initial development release is an early endeavor reflecting the efforts of a short time-boxed period, and by no means can it be considered the final product.  
-  The initial development release may be changed substantially over time and might introduce new features, but also may change or remove existing ones, potentially breaking compatibility with your existing code.
-  The initial development release is limited in functional scope.
-  The initial development release may contain errors or design flaws and other problems that could cause system or other failures and data loss.
-  The initial development release has reduced security, privacy, availability, and reliability standards relative to future releases. This could make the software slower, less reliable, or more vulnerable to attacks than mature software.
-  The initial development release is not yet comprehensively documented. 
-  Users of the software must perform sufficient engineering and additional testing to properly evaluate their application and determine whether any of the open-sourced components are suitable for use in that application.
-  We strongly recommend not putting this version of the software into production use.
-  Only the latest version of the software will be supported.

<br/>

## 8. License

This project is licensed under the Apache License, Version 2.0.
For more details, see the [LICENSE](LICENSE) file.

**Icons and images:** UI icons (trash, memory, card, PDF, QR code) are from [Bootstrap Icons](https://icons.getbootstrap.com/) (MIT), in line with the [Bootstrap Italia](https://italia.github.io/bootstrap-italia/) design system. For a full list of assets and their licenses, see [docs/ASSETS.md](docs/ASSETS.md).

<br/>
