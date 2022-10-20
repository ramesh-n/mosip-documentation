# Secure Biometrics Device Interface Specification

## Introduction & Background

This standard specifies a language-agnostic protocol and corresponding interfaces for biometric devices to support features such as discovery of devices, capabilities exposure of the device and capture of biometrics using the device for all instant capture modalities. This protocol also specifically addresses the trustworthiness of both the device and the captured data in addition to data security.


### Objective

This document provides the technical specifications of the interface and the compliance details for biometrics devices to adhere to the Secure Biometrics Device Interface (SBI) standard.


### Target Audience

This document aims to help the biometric device manufactures, their developers, and their designers in building SBI compliant devices.

### SBI Devices

All devices that collect biometric data for SBI reliant applications should operate within the specification of this document.

## Revision History

| Version | State  | Date        | Changes                                                                                                                                                                                                                                                                                                                              |
| ------- | ------ | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| draft.1   | Draft  | 20-Oct-2022 | Initial Draft                                                                                                |


## Glossary of Terms

* Device Provider - An entity that manufactures or imports the devices in their name. This entity should have legal rights to obtain an organization level digital certificate from the respective authority in the country.
* FTM Provider - An entity that manufactures or guarantees the trustworthiness of the foundational trust module. This can be the device provider as well.
* Device - A hardware capable of capturing biometric information.
* L1 Certified Device / L1 Device - A device certified as capable of performing encryption in line with this spec in its trusted zone.
* L0 Certified Device / L0 Device - A device certified as one where the encryption is done on the host machine device driver or the an SBI service.
* FTM Provider Certificate - A digital certificate issued to the "Foundational Trust Provider". This certificate proves that the provider has successfully gone through the required Foundational Trust Provider evaluation. The entity is expected to keep this certificate in secure possession in an HSM. All the individual FTM trust certificates are issued using this certificate as the root. This certificate would be issued by the countries in conjunction with a trusted registry.
* Device Provider Certificate - A digital certificate issued to the "Device Provider". This certificate proves that the provider has been certified for L0/L1 respective compliance. The entity is expected to keep this certificate in secure possession in an HSM. All the individual trust certificates are issued using this certificate as the root. This certificate is issued by the countries in conjunction with a trusted registry.
* Registration - The process of applying for a Foundational Id.
* KYC - Know Your Customer. The process of providing consent to perform profile verification and update.
* Auth - The process of verifying one’s identity.
* FPS - Frames Per Second
* Management Server - A server run by the device provider to manage the life cycle of the biometric devices.
* Device Registration - The process of a device obtaining a certificate from the management server.
* Signature - All signature should be as per RFC 7515.
* header in signature - Header in the signature means the attribute with "alg" set to RS256 and x5c set to base64encoded certificate.
* payload is the byte array of the actual data, always represented as base64urlencoded.
* signature - base64urlencoded signature bytes
* ISO format timestamp | ISO 8601 with format yyyy-mm-ddTHH:MM:ssZ (Example: 2020-12-08T09:39:37Z). This value should be in UTC (Coordinated Universal Time).

***

## Device Specification

The SBI device specification provides compliance guidelines to devices for them to work with SBI reliant applications. The compliance is based on device capability, trust and communication protocols. A SBI compliant device would follow the standards established in this document. It is expected that the devices are compliant with this specification and tested and validated. The details of each of these are outlined in the subsequent sections.

### Device Capability

The SBI compliant device is expected to perform the following,

* Should have the ability to collect one or more biometric
* Should have the ability to sign the captured biometric image or template.
* Should have the ability to protect secret keys
* Should have no mechanism to inject the biometric

### Base Specifications for Devices

Biometrics images for various modalities are represented and exchanged as per the below specifications.

#### Fingerprint Image Format
*Refer ISO 19794-4:2011 Specifications.*

Factor | Registration Devices | Authentication Devices
-------|----------------------|-----------------------
Image Specification | ISO 19794-4:2011 Annex B1 | ISO 19794-4:2011 Annex B2
Minimum Resolution | >= 500 native DPI. Higher densities are preferred. | >= 500 native DPI.
Minimum Active Platen Area or Capture area\* | >=1.6 x 1.5 inches for 1 to 2 fingers<br>>=3.2 x 2.0 inches for 4 fingers | >=0.5 x 0.65 inches\*
Greyscale Density | 8 bits (256 grey levels) | 8 bits (256 grey levels) 
Image Format | JPEG 2000 Lossless | JPEG 2000 Lossy or WSQ
Compression Ratio | Lossless | Up to 15:1
Quality Score | NFIQ v2.0 | NFIQ v1.0
Capture Mode | Auto Capture | Auto Capture
Preview | > 3 FPS M-JPEG frames with NFIQ 2.0 score superimposed | Not Applicable 
ESD | >= 8kv | >= 8kv
EMC Compliance | FCC class A or equivalent | FCC class A or equivalent
Operating Temperature\* |     0 to 50 &deg;C | 0 to 50 &deg;C
FTM | SBI 1.0 - Use host based security (and above) | SBI 2.0 - FTM supported security

#### Iris Image Format
*Refer to ISO 19794-6:2011 Specifications.*

Factor | Registration Devices | Authentication Devices
-------|----------------------|-----------------------
Image Specification | ISO 19794-6:2011 Annex B | ISO 19794-6:2011 Annex B	
Minimum Iris Diameter | >=210 pixels | >=150 pixels
Grey Scale Density | 8 bits (256 grey levels) | 8 bits (256 grey levels)	
Spatial Resolution | >=60% @ 2Lp/mm | >= 50% @ 1Lp/mm	
Pixel Resolution | >10 pixels/mm | >10 pixels/mm	
Capture Distance | >=10CM | >=10CM	
Imaging Wavelength | Approximately 700-900 nm | Approximately 700-900 nm	
Illumination | The eye should be illuminated using infrared or any other source that could produce high-quality gray scale image | The eye should be illuminated using infrared or any other source that could produce high-quality gray scale image
Image Format | IMAGE_TYPE_VGA (K2) OR IMAGE_TYPE_CROPPED (K3) | IMAGE_TYPE_CROPPED_AND_MASKED (K7)
Compression | JPEG 2000 Lossless | JPEG 2000 Lossy
Compression Ratio | Lossless | Up to 15:1 (>= 3.5 KB)
Aspect Ratio | 1:1 | 1:1
Capture Mode | Auto Capture | Auto Capture
Scan Type | Progressive | Progressive
Preview	| >= 3 FPS M-JPEG frames with quality score superimposed | Not Applicable
EMC compliance | FCC Class A or equivalent | FCC Class A or equivalent
Operating Temperature\* | 0 to 50 &deg;C | 0 to &deg;50 C
FTM | SBI 1.0  - Use host-based security (and above) | SBI 2.0 - FTM supported security	

#### Face Image Format
*Refer ISO 19794-5:2011 Specifications.*

Factor | Registration Devices | Authentication Devices
-------|----------------------|-----------------------
Image Specification	| ISO/IEC 19794-5:2011 | ISO/IEC 19794-5:2011
Camera Specification | 1080p with 90 degree FoV or above | 720p or above
Skin Tone | All | All	
Exception Image Specification | Full Frontal with FACE features, two palms next to the face, waist up photo.<br>60mm(width) X 40mm(height) | Not Applicable	
Image quality | ICAO - Full frontal image, +/- 5 degrees rotation, 24 bit RGB, white background<br>35 mm(width) X 45mm(height) | ICAO is not mandated	
Image format | JPEG 2000 Lossless | JPEG 2000 Lossy	
Compression Ratio | Lossless | Up to 15:1
EMC compliance | FCC Class A or equivalent | FCC Class A or equivalent	
Operation Temperature\*	| 0 to 50 &deg;C | 0 to 50 &deg;C
FTM	| SBI 1.0 - Use host based security (and above) | SBI 2.0 - FTM supported security

**Notes:**

* *\* Adopters can change this if needed.*
* *Capture Time across modalities should be less than 4 Seconds (time taken for providing a final capture response to the calling application, when the biometrics are well placed on the sensors)*

It is recommended that adopters look at ergonomics, accessibility, ease of usage, and common availability of devices while choosing devices for use in registration and authentication scenarios.

***

## Device Trust

SBI compliant devices provide a trusted environment for the devices to be used in registration, KYC and AUTH scenarios. The trust level is established based on the device support for trusted execution.

* L1 - The trust is provided by a secure chip with a secure execution environment.
* L0 - The trust is provided at the software level. No hardware related trust exists. This type of compliance is used in controlled environments.

### Foundational Trust Module (FTM)

The foundational trust module would be created using a secure microprocessor capable of performing all required biometric processing and secure storage of keys. The foundational device trust would satisfy the below requirements.

* The module can securely generate, store and process cryptographic keys.
* Generation of asymmetric keys and symmetric keys with TRNG.
* The module can protect keys from extraction.
* The module has to protect the keys from physical tampering, temperature, frequency and voltage related attacks.
* The module could withstand Hardware cloning.
* The module could withstand probing attacks
* The module provides memory segregation for cryptographic operations and protection against buffer overflow attacks
* The module provides the ability to withstand cryptographic side-channel attacks like Differential Power analysis attacks, Timing attacks.
* CAVP validated implementation of the cryptographic algorithm.
* The module can perform a cryptographically validatable secure boot.
* The module can run trusted applications.


The foundational device trust derived from this module is used to enable trust-based computing for biometric capture. The foundational device trust module provides for a trusted execution environment based on the following:

* Secure Boot
  * Ability to cryptographically verify code before execution.
  * Ability to check for integrity violation of the module/device.
  * Halt upon failure.
  * Ability to securely upgrade and perform forward only upgrades, to thwart downgrade attacks.
  * SHA256 hash equivalent or above should be used for all hashing requirements
  * All root of trust is provisioned upon first boot or before.
  * All upgrades would be considered a success only after the successful boot with proper hash and signature verification.
  * The boot should fail upon hash/signature failures and would never operate in an intermediary state.
  * Maximum of 10 failed attempts should lock the upgrade process and brick the device. However, chip manufactures can decide to be less than 10.
* Secure application
  * Ability to run applications that are trusted.
  * Protect against the downgrading of applications.
  * Isolated memory to support cryptographic operations.
  * All trust is anchored during the first boot and not modifiable.

#### Certification

The FTM should have at least one of the following certifications in each category to meet the given requirement.

**Category: Cryptographic Algorithm Implementation**

* CAVP (RSA, AES, SHA256, TRNG (DRBGVS), ECC)

**Note:** 

The supported algorithm and curves are listed <a href="#cryptography">here</a>.


**Category: FTM Chip**

(ONE of the following certifications)

* FIPS 140-2 L3 or above
* PCI PTS 5 or above (Pre-certified)
* PCI - PED 2.0 or above (Pre-Certified)
* One of following Common Criteria (CC) certification
  * https://www.commoncriteriaportal.org/files/ppfiles/pp0035a.pdf
  * https://www.commoncriteriaportal.org/files/ppfiles/pp0084a\_pdf.pdf

**System/Device Level Tamper (optional)**

System/Device Level Tamper Responsiveness is recommended (not mandatory). In this case, FTM should be capable of showcasing Tamper Responsiveness (keys must be erased) against a tamper at the system/device level.

#### Threats to Protect

The FTM should protect against the following threats.

* Hardware cloning attacks - Ability to protect against attacks that could result in a duplicate with keys.
* Hardware Tamper attacks
  * Physical tamper - No way to physically tamper and obtain it secrets.
  * Voltage & frequency related attacks - Should shield against voltage leaks and should prevent low voltage. The FTM should always be in either of the state operational normally or inoperable. The FTM should never be operable when its input voltages are not met.
  * Temperature attacks on the crypto block - Low or High the FTM is expected to operate or reach an inoperable state. No state in between.
* Differential Power Analysis attack.
* Probing attacks - FTM should protect its surface area against any probe related attacks.
* Segregation of memory for execution of cryptographic operation (crypto block should be protected from buffer overflow type attacks).
* Vulnerability of the cryptographic algorithm implementation.
* Attacks against secure boot & secure upgrade.
* TEE/Secure processor OS attack (if applicable).

#### Foundational Trust Module Identity

Upon an FTM provider approved by the adopters, the FTM provider would submit a self-signed public certificate to a trusted registry. Let us call this the FTM root. The adopter would use this certificate to seed their device trust database. The FTM root and their key pairs should be generated and stored in FIPS 140-2 Level 3 or more compliant devices with no possible mechanism to extract the keys. The foundational module upon its first boot is expected to generate a random asymmetric key pair and provide the public part of the key to obtain a valid certificate. The FTM provider would validate to ensure that the chip is unique and would issue a certificate with the issuer set to an FTM certificate chain. The entire certificate issuance would be in a secured provisioning facility. Auditable upon notice by the adopters or its approved auditors. The certificate issued to the module will have a defined validity period as per the application certificate policy document defined by the application adopters. This certificate and private key within the FTM chip is expected to be in its permanent memory.

**Note:**

The validity of the chip certificate can not exceed 20 years from the date of manufacturing.

### Device

SBI devices are most often used to collect biometrics. The devices are expected to follow the specification for all level of compliance and their usage. The SBI devices have a Trust Level where the device is expected to be whitelisted with a fully capable PKI and secure storage of keys at the hardware.

* L0 - A device can obtain L0 certification when it uses a software level cryptographic library with no secure boot or FTM. These devices will follow different device identity and the same would be mentioned as part of exception flows.
* L1 - A device can obtain L1 certification when it is built in a secure facility with one of the certified FTM.

#### Device Identity

All devices that connect to an SBI reliant application must be identifiable. The SBI specification relies on cryptographic Identity as its basis for trust.

**Physical ID**

An identification mark that shows SBI compliance and a readable unique device serial number (minimum of 12 alphanumeric characters), make and model. The same information has to be available over a 2D QR Code or Barcode. This is to help field support and validation.

**Digital ID**

A digital device ID in SBI would be a signed JSON (RFC 7515) as follows:

```
{
  "serialNo": "Serial number",
  "make": "Make of the device",
  "model": "Model of the device",
  "type": "Type of the biometric device",
  "deviceSubType": "Subtypes of the biometric device",
  "deviceProvider": "Device provider name",
  "deviceProviderId": "Device provider id",
  "dateTime": "Current datetime in ISO format"
}
```

Signed with the JSON Web Signature (RFC 7515) using the "Foundational Trust Module" Identity key, this data is the fundamental identity of the device. Every SBI compliant device will need the foundational trust module.

The only exception to this rule is for the L0 compliant devices that have the purpose as "Registration". L0 devices would sign the Digital Id with the device key.

A signed digital ID would look as follows:

```
"digitalId": "base64urlencoded(header).base64urlencoded(payload).base64urlencoded(signature)"
```

The header in the digital id would have:

```
"alg": "RS256",
"typ": "JWT",
"x5c": "<Certificate of the FTM chip, If in case the chain of certificates are sent then the same will be ignored">
```

SBI assumes that the first certificate in the x5c is the FTM's chip public certificate issued by the FTM root certificate.

Unsigned digital ID would look as follows:

```
"digitalId": "base64urlencoded(payload)"
```

Payload is the Digital ID JSON object.

**Note:** 

For an L0 unregistered device, the digital id will be unsigned. In all other scenarios, except for a discovery call, the digital ID will be signed either by the chip key (L1) or the device key (L0).

[TBD] update links below by adding sections

**Accepted Values for Digital ID**

| Parameters     | Description                                                                                                                                                                                                     |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| serialNo       | <ul><li>Serial number of the device.</li><li>This value should be same as printed on the device (Refer <a href="MOSIP-Device-Service-Specification.md#physical-id">Physical ID</a>).</li></ul>                  |
| make           | <ul><li>Brand name.</li><li>This value should be same as printed on the device (Refer <a href="MOSIP-Device-Service-Specification.md#physical-id">Physical ID</a>).</li><li><p></p><ul><li></li></ul></li></ul> |
| model          | <ul><li>Model of the device.</li><li>This value should be same as printed on the device (Refer <a href="MOSIP-Device-Service-Specification.md#physical-id">Physical ID</a>).</li></ul>                          |
| type           | <ul><li>Currently allowed values for device type are "Finger", "Iris" or "Face".</li><li>More types can be added based on Adopter's implementation.</li></ul>                                                   |
| deviceSubType  | <ul><li>Device Sub type is based on the device type.</li><li>For Finger - "Slap", "Single" or "Touchless"</li><li>For Iris - "Single" or "Double"</li><li>For Face - "Full face"</li></ul>                      |
| deviceProvider | <ul><li>Name of the device provider.</li><li>Device provider should be a legal entity in the country.</li></ul>                                                                                                 |
| dateTime       | <ul><li>Current time during the issuance of the request.</li><li>This is in ISO format.</li></ul>                                                                                                               |

### Keys

List of keys used in the device and their explanation.

* **Device Key**

Each biometric device would contain an authorized private key after the device registration. This key is rotated frequently based on the requirement from the SBI reliant application. By default, SBI recommends 30 days key rotation policy for the device key. The device keys are created by the device providers inside the FTM during a successful registration. The device keys are used for signing the biometric. More details of the signing and its usage will be [here](MOSIP-Device-Service-Specification.md#device-service-communication-interfaces). This key is issued by the device provider and the certificate of the device key is issued by the device provider key which in turn is issued by the SBI reliant application after approval of the device providers specific model.

* **FTM Key**

The FTM key is the root of the identity. This key is created by the FTM provider during the manufacturing/provisioning stage. This is a permanent key and would never be rotated. This key is used to sign the Digital ID.

* **Application Key**

The Application key is the public key provided by the SBI reliant application. This key is used to encrypt the biometric. Details of the encryption are listed below. We recommend rotating this key every 1 year.

## Device Service - Communication Interfaces

The section explains the necessary details of the biometric device connectivity, accessibility, discover-ability and protocols used to build and communicate with the device.

The device should implement only the following set of APIs.  All the API’s are independent of the physical layer and the operating system, with the invocation being different across operating systems. While the operating system names are defined in this spec a similar technology can be used for unspecified operating systems. It is expected that the device service ensures that the device is connected locally to the host.

### Device Discovery

Device discovery would be used to identify SBI compliant devices in a system by the applications. The protocol is designed as a simple plug and play with all the necessary abstraction to the specifics.

#### Device Discovery Request

```
{
  "type": "type of the device"
}
```

#### Accepted Values for Device Discovery Request

* type - "Biometric Device", "Finger", "Face", "Iris"

**Note:**

"Biometric Device" - is a special type and used in case if you are looking for any biometric device.

#### Device Discovery Response

```
[
  {
    "deviceId": "Internal ID",
    "deviceStatus": "Device status",
    "certification": "Certification level",
    "serviceVersion": "Device service version",
    "deviceSubId": ["Array of supported device sub Ids"],
    "callbackId": "Base URL to reach to the device",
    "digitalId": "Unsigned Digital ID of the device",
    "deviceCode": "Same as serialNo in digital ID",
    "specVersion": ["Array of supported SBI specification version"],
    "purpose": "Auth  or Registration or empty if not registered",
    "error": {
      "errorCode": "101",
      "errorInfo": "Invalid JSON Value Type For Discovery.."
    }
  },
  ...
]
```

#### Accepted Values for Device Discovery Response

| Parameters      | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| deviceStatus    | Allowed values are "Ready", "Busy", "Not Ready" or "Not Registered".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| certification   | Allowed values are "L0" or "L1" based on the level of certification.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| serviceVersion  | Device service version.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| deviceId        | Internal ID to identify the actual biometric device within the device service.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| deviceSubId     | <ul><li>Allowed values are 1, 2 or 3.</li><li>The device sub id could be used to enable a specific module in the scanner appropriate for a biometric capture requirement.</li><li>Device sub id is a simple index which always starts with 1 and increases sequentially for each sub device present.</li><li>In case of Finger/Iris its 1 for left slap/iris, 2 for right slap/iris and 3 for two thumbs/irises.</li><li>The device sub id should be set to 0 if we don't know any specific device sub id (0 is not applicable for fingerprint slap).</li><li><p></p><ul><li></li></ul></li></ul> |
| callbackId      | <ul><li>This differs as per the OS.</li><li>In case of Linux and windows operating systems it is a HTTP URL.</li><li>In the case of android, it is the intent name.</li><li>In IOS, it is the URL scheme.</li><li>The call back URL takes precedence over future request as a base URL.</li></ul>                                                                                                                                                                                                                                                                                                 |
| digitalId       | Digital ID as per the Digital ID definition but it will not be signed.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| deviceCode      | Same as serialNo in digital ID.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| specVersion     | Array of supported SBI specification version. The array element zero will always contain the spec version using which the response is created.                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| purpose         | Purpose of the device in the SBI ecosystem. Allowed values are "Auth" or "Registration".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| error           | Relevant errors as defined under the <a href="#error-codes">error section</a> of this document.                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| error.errorCode | Standardized error code defined in the <a href="#error-codes">error code section</a>.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| error.errorInfo | Description of the error that can be displayed to end user. Multi lingual support.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

**Notes:**

* The response is an array that we could have a single device enumerating with multiple biometric options.
* The service should ensure to respond only if the type parameter matches the type of device or the type parameter is a "Biometric Device".
* This response is a direct JSON as shown in the response.


#### Windows/Linux

All the device API will be based on the HTTP specification. The device always binds to any of the available ports ranging from 4501 - 4600. The IP address used for binding has to be 127.0.0.1 and not localhost.

The applications that require access to SBI devices could discover them by sending the HTTP request to the supported port range. We will call this port the device\_service\_port in the rest of the document.

_**HTTP Request:**_

```
SBIDISC http://127.0.0.1:<device_service_port>/device
HOST: 127.0.0.1: <device_service_port>
EXT: <app name>
```

_**HTTP Response:**_

```
HTTP/1.1 200 OK
CACHE-CONTROL:no-store
LOCATION:http://127.0.0.1:<device_service_port>
Content-Length: length in bytes of the body
Content-Type: application/json
Connection: Closed
```

**Notes:**

* The payloads are JSON in both cases and are part of the body.
* CallbackId would be set to the `http://127.0.0.1:<device_service_port>/`. So, the caller will use the respective HTTP verb/method and the URL to call the service.

#### Android
For details on android specifications please view the section - <a href="#android-sbi-specification">Android SBI Specification</a>.

<!--
All devices on an android device should listen to the following intent "io.sbi.device".

Upon invocation of this intent, the devices are expected to respond with the JSON response filtered by the respective type.

{% hint style="info" %}
In Android, the CallbackId would be set to the appId. So, the caller will create the intent "appId.Info" or "appId.Capture".
{% endhint %}

#### IOS

All device on an IOS device would respond to the URL schema as follows:

```
SBIDISC://<call-back-app-url>?ext=<caller app name>&type=<type as defined in SBI device request>
```

If a SBI compliant device service app exists then the URL would launch the service. The service in return should respond to the caller using the call-back-app-URL with the base64 encoded JSON as the URL parameter for the key data.

{% hint style="info" %}
* In IOS there are restrictions to have multiple apps registering to the same URL schema.
* CallbackId would be set to the device service app name. So, the caller has to call appnameInfo or appnameCapture as the URL scheme.
{% endhint %}
-->

### Device Info

The device information API would be used to identify the SBI compliant devices and their status by the applications.

#### Device Info Request

NA

#### Accepted Values for Device Info Request

NA

#### Device Info Response

```
[
  {
    "deviceInfo": {
      "deviceStatus": "Current status",
      "deviceId": "Internal ID",
      "firmware": "Firmware version",
      "certification": "Certification level",
      "serviceVersion": "Device service version",
      "deviceSubId": ["Array of supported device sub Ids"],
      "callbackId": "Baseurl to reach to the device",
      "digitalId": "Signed digital id as described in the digital id section of this document.",
      "deviceCode": "Same as serialNo in digital ID",
      "env": "Target environment",
      "purpose": "Auth  or Registration",
      "specVersion": ["Array of supported SBI specification version"],
    },
    "error": {
      "errorCode": "101",
      "errorInfo": "Invalid JSON Value "
    }
  }
  ...
]
```

So the API would respond in the following format.

```
[
  {
    "deviceInfo": "base64urlencode(header).base64urlencode(payload).base64urlencode(signature)"
    "error": {
      "errorCode": "100",
      "errorInfo": "Device not registered. In this case the device info will be only base64urlencode(payload)"
    }
  }
]
```

#### Allowed values for Device Info Response

| Parameters                | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| deviceInfo                | <ul><li>The deviceInfo object is sent as JSON Web Token (JWT).</li><li>For device which is not registered, the deviceInfo will be unsigned.</li><li>For device which is registered, the deviceInfo will be signed using the device key.</li></ul>                                                                                                                                                                                                                                                                                                                                                 |
| deviceInfo.deviceStatus   | <ul><li>This is the status of the device.</li><li>Allowed values are "Ready", "Busy", "Not Ready" or "Not Registered".</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| deviceInfo.deviceId       | Internal Id to identify the actual biometric device within the device service.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| deviceInfo.firmware       | <ul><li>Exact version of the firmware.</li><li>In case of L0 this is same as serviceVersion.</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| deviceInfo.certification  | <ul><li>Allowed values are "L0" or "L1" based on the level of certification.</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| deviceInfo.serviceVersion | Version of the SBI specification that is supported.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| deviceInfo.deviceId       | Internal ID to identify the actual biometric device within the device service.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| deviceSubId               | <ul><li>Allowed values are 1, 2 or 3.</li><li>The device sub id could be used to enable a specific module in the scanner appropriate for a biometric capture requirement.</li><li>Device sub id is a simple index which always starts with 1 and increases sequentially for each sub device present.</li><li>In case of Finger/Iris its 1 for left slap/iris, 2 for right slap/iris and 3 for two thumbs/irises.</li><li>The device sub id should be set to 0 if we don't know any specific device sub id (0 is not applicable for fingerprint slap).</li><li><p></p><ul><li></li></ul></li></ul> |
| deviceInfo.callbackId     | <ul><li>This differs as per the OS.</li><li>In case of Linux and windows operating systems it is a HTTP URL.</li><li>In the case of android, it is the intent name.</li><li>In IOS, it is the URL scheme.</li><li>The call back URL takes precedence over future request as a base URL.</li></ul>                                                                                                                                                                                                                                                                                                 |
| deviceInfo.digitalId      | <ul><li>The digital id as per the digital id definition.</li><li>For L0 devices which is not registered, the digital id will be unsigned.</li><li>For L0 devices which is registered, the digital id will be signed using the device key.</li><li>For L1 devices, the digital id will be signed using the FTM key.</li></ul>                                                                                                                                                                                                                                                                      |
| deviceInfo.env            | <ul><li>The target enviornment.</li><li>For devices that are not registered the enviornment is "None".</li><li>For device that is registered, then send the enviornment in which it is registered.</li><li>Allowed values are "Staging", "Developer", "Pre-Production" or "Production".</li></ul>                                                                                                                                                                                                                                                                                                 |
| deviceInfo.purpose        | <ul><li>The purpose of the device in the SBI ecosystem.</li><li>For devices that are not registered the purpose is empty.</li><li>Allowed values are "Auth" or "Registration".</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                        |
| deviceInfo.specVersion    | Array of supported SBI specification version. The array element Zero will always contain the spec version using which the response is created.                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| error                     | Relevant errors as defined under the <a href="#error-codes">error section</a> of this document.                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| error.errorCode           | Standardized error code defined in the <a href="#error-codes">error code section</a>.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| error.errorInfo           | Description of the error that can be displayed to end user. Multi lingual support.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

**Notes:**

* The response is an array that we could have a single device enumerating with multiple biometric options.
* The service should ensure to respond only if the type parameter matches the type of device or the type parameter is a "Biometric Device".


#### Windows/Linux

The applications that require more details of the SBI devices could get them by sending the HTTP request to the supported port range. The device always binds to any of the available ports ranging from 4501 - 4600. The IP address used for binding has to be 127.0.0.1 and not localhost.

_**HTTP Request:**_

```
SBIDINFO http://127.0.0.1:<device_service_port>/info
HOST: 127.0.0.1:<device_service_port>
EXT: <app name>
```

_**HTTP Response:**_

```
HTTP/1.1 200 OK
CACHE-CONTROL:no-store
LOCATION:http://127.0.0.1:<device_service_port>
Content-Length: length in bytes of the body
Content-Type: application/json
Connection: Closed
```

**Note:**

The payloads are JSON in both cases and are part of the body.

#### Android
For details on android specifications please view the section - <a href="#android-sbi-specification">Android SBI Specification</a>.

<!--
An android device should listen to the following intent "appId.Info".

Upon invocation of this intent, the devices are expected to respond with the JSON response filtered by the respective type.

#### IOS

An IOS device would respond to the URL schema as follows:

```
APPIDINFO://<call-back-app-url>?ext=<caller app name>&type=<type as defined in SBI device request>
```

If a SBI compliant device service app exists then the URL would launch the service. The service in return should respond to the call using the call-back-app-URL with the base64 encoded JSON as the URL parameter for the key data.

{% hint style="info" %}
In IOS there are restrictions to have multiple apps registering to the same URL schema.
{% endhint %}
-->

### Capture

The capture request would be used to capture a biometric from SBI compliant devices by the applications. The captured call will respond with success to only one call at a time. So, in case of a parallel call, the device info details are sent with status as "Busy".

#### Capture Request

```
{
  "env": "Target environment",
  "purpose": "Auth  or Registration",
  "specVersion": "Expected version of the SBI spec",
  "timeout" : "Timeout for capture",
  "captureTime": "Capture request time in ISO format",
  "domainUri": "URI of the auth server",
  "transactionId": "Transaction Id for the current capture",
  "bio": [
    {
      "type": "Type of the biometric data",
      "count":  "Finger/Iris count, in case of face max is set to 1",
      "bioSubType": ["Array of subtypes"],
      "requestedScore": "Expected quality score that should match to complete a successful capture",
      "deviceId": "Internal Id",
      "deviceSubId": "Specific Device Sub Id",
      "previousHash": "Hash of the previous block"
    }
  ],
  "customOpts": {
    //Max of 50 key-value pair. This is so that vendor-specific parameters can be sent if necessary. The values cannot be hardcoded and have to be configured by the apps server and should be modifiable upon need by the applications. Vendors are free to include additional parameters and fine-tuning parameters. None of these values should go undocumented by the vendor. No sensitive data should be available in the customOpts.
  }
}
```

**Note:**

Count value should be driven by the count of the bioSubType for Iris and Finger. For Face, there will be no bioSubType but the count should be "1".

#### Allowed Values for Capture Request

| Parameters         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| env                | <ul><li>The target environment.</li><li>Allowed values are "Staging", "Developer", "Pre-Production" or "Production".</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| purpose            | <ul><li>The purpose of the device in the SBI ecosystem.</li><li>For devices that are not registered the purpose is empty.</li><li>Allowed values are "Auth" or "Registration".</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                       |
| specVersion        | Expected version of SBI specification.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| timeout            | <ul><li>Max time the app will wait for the capture.</li><li>Its expected that the API will respond back before timeout with the best frame.</li><li>All timeouts are in milliseconds.</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                  |
| captureTime        | <ul><li>Time of capture in ISO format.</li><li>The time is as per the requesting application.</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| domainUri          | <ul><li>URI of the authentication server.</li><li>This can be used to federate across multiple providers or countries or unions.</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| transactionId      | <ul><li>Unique Id of the transaction.</li><li>This is an internal Id to the application thats providing the service.</li><li>Different id should be used for every successful auth.</li><li>So even if the transaction fails after auth we expect this number to be unique.</li></ul>                                                                                                                                                                                                                                                                                                            |
| bio.type           | Allowed values are "Finger", "Iris" or "Face".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| bio.count          | <ul><li>Number of biometric data that is collected for a given type.</li><li>The device should validate and ensure that this number is in line with the type of biometric that's captured.</li></ul>                                                                                                                                                                                                                                                                                                                                                                                             |
| bio.bioSubType     | <ul><li>For Finger: ["Left IndexFinger", "Left MiddleFinger", "Left RingFinger", "Left LittleFinger", "Left Thumb", "Right IndexFinger", "Right MiddleFinger", "Right RingFinger", "Right LittleFinger", "Right Thumb", "UNKNOWN"]</li><li>For Iris: ["Left", "Right", "UNKNOWN"]</li><li>For Face: No bioSubType</li></ul>                                                                                                                                                                                                                                                                      |
| bio.requestedScore | Upon reaching the quality score the biometric device is expected to auto capture the image. If the requested score is not met, until the timeout, the best frame during the capture sequence must be captured/returned. This value will be scaled from 0 - 100 for NFIQ v1.0. The logic for scaling is mentioned below.                                                                                                                                                                                                                                                                          |
| bio.deviceId       | Internal Id to identify the actual biometric device within the device service.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| bio.deviceSubId    | <ul><li>Allowed values are 1, 2 or 3.</li><li>The device sub id could be used to enable a specific module in the scanner appropriate for a biometric capture requirement.</li><li>Device sub id is a simple index that always starts with 1 and increases sequentially for each sub-device present.</li><li>In case of Finger/Iris its 1 for left slap/iris, 2 for right slap/iris and 3 for two thumbs/irises.</li><li>The device sub id should be set to 0 if we don't know any specific device sub id (0 is not applicable for fingerprint slap).</li><li><p></p><ul><li></li></ul></li></ul> |
| bio.previousHash   | For the first capture the previousHash is the SHA256 hash of an empty UTF-8 string. From the second capture the previous capture's "hash" is used as input. This is used to chain all the captures across modalities so all captures have happened for the same transaction and during the same time.                                                                                                                                                                                                                                                                                            |
| customOpts         | <ul><li>In case, the device vendor wants to send additional parameters they can use this to send key value pair if necessary.</li><li>The values cannot be hard coded and have to be configured by the apps server and should be modifiable upon need by the applications.</li><li>Vendors are free to include additional parameters and fine-tuning the process.</li><li>None of these values should go undocumented by the vendor.</li><li>No sensitive data should be available in the customOpts.</li></ul>                                                                                  |

NFIQ v1.0 on a scale of 0-100 (quality score).

| Scale    | NFIQ v1.0 |
| -------- | --------- |
| 81 - 100 | 1         |
| 61 - 80  | 2         |
| 41 - 60  | 3         |
| 21 - 40  | 4         |
| 0 - 20   | 5         |

#### Capture Response

```
{
  "biometrics": [
    {
      "specVersion": "SBI spec version",
      "data": {
        "digitalId": "digital Id as described in this document",
        "deviceCode": "Same as serialNo in digital ID",
        "deviceServiceVersion": "SBI version",
        "bioType": "Finger",
        "bioSubType": "UNKNOWN",
        "purpose": "Auth  or Registration",
        "env": "Target environment",
        "domainUri": "URI of the auth server",
        "bioValue": "Encrypt biodata (ISO) with random 256 bit AES key (session key) and encode encrypted biodata with base64 URL safe encoding.",
        "transactionId": "Unique transaction id",
        "timestamp": "Capture datetime in ISO format",
        "requestedScore": "Floating point number to represent the minimum required score for the capture",
        "qualityScore": "Floating point number representing the score for the current capture"
      },
      "hash": "sha256 in hex format in upper case (previous "hash" + sha256 hash of the current biometric ISO data before encryption)",
      "sessionKey": "Encrypt the session key (used to encrypt the bioValue) with Application public key and encode encrypted session key with base64 URL safe encoding.",
      "thumbprint": "SHA256 representation of the certificate (HEX encoded) that was used for encryption of session key. All texts to be treated as uppercase without any spaces or hyphens.",
      "error": {
        "errorCode": "101",
        "errorInfo": "Invalid JSON Value"
      }
    },
    {
      "specVersion" : "SBI spec version",
      "data": {
        "digitalId": "Digital Id as described in this document",
        "deviceCode": "Same as serialNo in digital ID",
        "deviceServiceVersion": "SBI version",
        "bioType": "Finger",
        "bioSubType": "Left IndexFinger",
        "purpose": "Auth  or Registration",
        "env": "target environment",
        "domainUri": "URI of the auth server",
        "bioValue": "Encrypt biodata (ISO) with random 256 bit AES key (session key) and encode encrypted biodata with base64 URL safe encoding.",
        "transactionId": "unique transaction id",
        "timestamp": "Capture datetime in ISO format",
        "requestedScore": "Floating point number to represent the minimum required score for the capture",
        "qualityScore": "Floating point number representing the score for the current capture"
      },
      "hash": "sha256 in hex format in upper case (previous "hash" + sha256 hash of the current biometric ISO data before encryption)",
      "sessionKey": "Encrypt the session key (used to encrypt the biovalue) with Application public key and encode encrypted session key with base64 URL safe encoding.",
      "thumbprint": "SHA256 representation of the certificate (HEX encoded) that was used for encryption of session key. All texts to be treated as uppercase without any spaces or hyphens.",
      "error": {
        "errorCode": "101",
        "errorInfo": "Invalid JSON Value"
      }
    }
  ]
}
```

#### Accepted Values for Capture Response

| Parameters                | Description                                                                                                                                                                                                                                                                                                                                                                            |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| specVersion               | Version of the SBI specification using which the response was generated.                                                                                                                                                                                                                                                                                                               |
| data                      | <ul><li>The data object is sent as JSON Web Token (JWT).</li><li>The data block will be signed using the device key.</li></ul>                                                                                                                                                                                                                                                         |
| data.digitalId            | <ul><li>The digital id as per the digital id definition in JWT format.</li><li>For L0 devices, the digital id will be signed using the device key.</li><li>For L1 devices, the digital id will be signed using the FTM key.</li></ul>                                                                                                                                                  |
| data.deviceCode           | Same as serialNo in digital ID.                                                                                                                                                                                                                                                                                                                                                        |
| data.deviceServiceVersion | SBI version                                                                                                                                                                                                                                                                                                                                                                            |
| data.bioType              | Allowed values are "Finger", "Iris" or "Face".                                                                                                                                                                                                                                                                                                                                         |
| data.bioSubType           | <ul><li>For Finger: ["Left IndexFinger", "Left MiddleFinger", "Left RingFinger", "Left LittleFinger", "Left Thumb", "Right IndexFinger", "Right MiddleFinger", "Right RingFinger", "Right LittleFinger", "Right Thumb", "UNKNOWN"]</li><li>For Iris: ["Left", "Right", "UNKNOWN"]</li><li>For Face: No bioSubType</li></ul>                                                            |
| data.purpose              | <ul><li>The purpose of the device in the SBI ecosystem.</li><li>Allowed values is "Auth".</li></ul>                                                                                                                                                                                                                                                                                  |
| data.env                  | <ul><li>The target environment.</li><li>Allowed values are "Staging", "Developer", "Pre-Production" or "Production".</li></ul>                                                                                                                                                                                                                                                         |
| data.domainUri            | <ul><li>URI of the authentication server.</li><li>This can be used to federate across multiple providers or countries or unions.</li></ul>                                                                                                                                                                                                                                             |
| data.bioValue             | Biometric data is encrypted with random symmetric (AES GCM) key and base-64-URL encoded. For symmetric key encryption of bioValue, (biometrics.data.timestamp XOR transactoinId) is computed and the last 16 bytes and the last 12 bytes of the results are set as the aad and the IV(salt) respectively. Look at the Authentication document to understand more about the encryption. |
| data.transactionId        | Unique transaction id sent in request                                                                                                                                                                                                                                                                                                                                                  |
| data.timestamp            | <ul><li>Time as per the biometric device.</li><li>Note: The biometric device is expected to sync its time from the management server at regular intervals so accurate time could be maintained on the device.</li></ul>                                                                                                                                                                |
| data.requestedScore       | Floating point number to represent the minimum required score for the capture. This value will be scaled from 0 - 100 for NFIQ v1.0. The logic for scaling is mentioned above.                                                                                                                                                                                                         |
| data.qualityScore         | Floating point number representing the score for the current capture. This value will be scaled from 0 - 100 for NFIQ v1.0. The logic for scaling is mentioned above.                                                                                                                                                                                                                  |
| hash                      | sha256 in hex format in upper case (previous "hash" + sha256 hash of the current biometric ISO data before encryption)                                                                                                                                                                                                                                                                 |
| sessionKey                | The session key (used for the encryption of the biodata (ISO)) is encrypted using the Application public certificate with RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING algorithm and then encode the encrypted session key with base64 URL safe encoding.                                                                                                                                           |
| thumbprint                | SHA256 representation of the certificate (HEX encoded) that was used for encryption of session key. All texts to be treated as uppercase without any spaces or hyphens.                                                                                                                                                                                                                |
| error                     | Relevant errors as defined under the <a href="#error-codes">error section</a> of this document.                                                                                                                                                                                                                                                              |
| error.errorCode           | Standardized error code defined in the <a href="#error-codes">error code section</a>.                                                                                                                                                                                                                                                                        |
| error.errorInfo           | Description of the error that can be displayed to the end-user. Multi-lingual support.                                                                                                                                                                                                                                                                                                 |

The entire data object is sent in JWT format. So, the data object will look like this:

```
"data" : "base64urlencode(header).base64urlencode(payload).base64urlencode(signature)
payload - is defined as the entire byte array of data block.
```

#### Windows/Linux

The applications that require capturing biometric data from a SBI device could do so by sending the HTTP request to the supported port range.

_**HTTP Request:**_

```
CAPTURE [http://127.0.0.1:<device_service_port>/capture](http://127.0.0.1/capture)
HOST: 127.0.0.1: <apps port>
EXT: <app name>
```

_**HTTP Response:**_

```
HTTP/1.1 200 OK
CACHE-CONTROL:no-store
LOCATION:[http://127.0.0.1](http://127.0.0.1):<device_service_port>
Content-Length: length in bytes of the body
Content-Type: application/json
Connection: Closed
```

**Note:**

The payloads are JSON in both cases and are part of the body.

#### Android
For details on android specifications please view the section - <a href="#android-sbi-specification">Android SBI Specification</a>.

<!--
All device on an android device should listen to the following intent appid.capture. Upon this intend, the devices are expected to respond with the JSON response filtered by the respective type.

#### IOS

All device on an IOS device would respond to the URL schema as follows.

```
APPIDCAPTURE://<call-back-app-url>?ext=<caller app name>&type=<type as defined in SBI device request>
```

If a SBI compliant device service app exists then the URL would launch the service. The service in return should respond to the call using the call-back-app-URL with the base64 encoded JSON as the URL parameter for the key data.
-->

### Device Stream

The device would open a stream channel to send the live video streams. This would help when there is an assisted operation to collect biometric. Please note the stream API’s are available only for the registration environment.

Used only for the registration module compatible devices. This API is visible only for the devices that are registered for the purpose of "Registration".

#### Device Stream Request

```
{
  "deviceId": "Internal Id",
  "deviceSubId": "Specific device sub Id",
  "timeout": "Timeout for stream"
}
```

#### Allowed Values for device Stream Request

| Parameters  | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| deviceId    | Internal Id to identify the actual biometric device within the device service.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| deviceSubId | <ul><li>Allowed values are 1, 2 or 3.</li><li>The device sub id could be used to enable a specific module in the scanner appropriate for a biometric capture requirement.</li><li>Device sub id is a simple index which always starts with 1 and increases sequentially for each sub device present.</li><li>In case of Finger/Iris its 1 for left slap/iris, 2 for right slap/iris and 3 for two thumbs/irises.</li><li>The device sub id should be set to 0 if we don't know any specific device sub id (0 is not applicable for fingerprint slap).</li><li><p></p><ul><li></li></ul></li></ul> |
| timeout     | <ul><li>Max time after which the stream should close.</li><li>This is an optional paramter and by default the value will be 5 minutes.</li><li>All timeouts are in milliseconds.</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                        |

#### Device Stream Response

Live Video stream with quality of 3 frames per second or more using <a href="https://en.wikipedia.org/wiki/Motion\_JPEG">M-JPEG</a>.

**Note:** 

The preview should have quality markings and segment marking. The preview would also be used to display an error message to the user screen. All error messages should be localized.

#### Error Response for Device Stream

```
{
  "error": {
    "errorCode": "202",
    "errorInfo": "No Device Connected."
  }
}
```

#### Windows/Linux

The applications that require more details of the SBI devices could get them by sending the HTTP request to the supported port range.

_**HTTP Request:**_

```
STREAM   http://127.0.0.1:<device_service_port>/stream
HOST: 127.0.0.1: <apps port>
EXT: <app name>
```

_**HTTP Response:**_ HTTP Chunk of frames to be displayed. Minimum frames 3 per second.

#### Android
For details on android specifications please view the section - <a href="#android-sbi-specification">Android SBI Specification</a>.

<!--
No support for streaming

#### IOS

No support for streaming
-->

### Registration Capture

The registration client application will discover the device. Once the device is discovered the status of the device is obtained with the device info API. During the registration, the registration client sends the RCAPTURE API and the response will provide the actual biometric data in a digitally signed non-encrypted form. When the Device Registration Capture API is called the frames should not be added to the stream. The device is expected to send the images in ISO format.

The requestedScore is on a scale of 1-100 (NFIQ v2.0 for fingerprints). So, in cases where you have four fingers the average of all will be considered for the capture threshold. The device would always send the best frame during the capture time even if the requested score is not met.

The API is used by the devices that are compatible with the registration module. This API should not be supported by devices that are compatible with authentication.

#### Registration Capture Request

```
{
  "env":  "Target environment",
  "purpose": "Auth  or Registration",
  "specVersion": "Expected SBI spec version",
  "timeout": "Timeout for registration capture",
  "captureTime": "Time of capture request in ISO format",
  "transactionId": "Transaction Id for the current capture",
  "bio": [
    {
      "type": "Type of the biometric data",
      "count":  "Finger/Iris count, in case of face max is set to 1",
      "bioSubType": ["Array of subtypes"], //Optional
      "exception": ["Finger or Iris to be excluded"],
      "requestedScore": "Expected quality score that should match to complete a successful capture",
      "deviceId": "Internal Id",
      "deviceSubId": "Specific device Id",
      "previousHash": "Hash of the previous block"
    }
  ],
  "customOpts": {
    //max of 50 key-value pair. This is so that vendor-specific parameters can be sent if necessary. The values cannot be hardcoded and have to be configured by the apps server and should be modifiable upon need by the applications. Vendors are free to include additional parameters and fine-tuning parameters. None of these values should go undocumented by the vendor. No sensitive data should be available in the customOpts.
  }
}
```

**Note:**

To capture the exception photo exception value for Iris or Finger should be sent in bio.exception for bio.type = 'Face'. ICAO checks are not mandatory here but one face must be present within the frame.

#### Accepted Values for Registration Capture Request

| Parameters         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| env                | <ul><li>The target environment.</li><li>Allowed values are "Staging", "Developer", "Pre-Production" or "Production".</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| purpose            | <ul><li>The purpose of the device in the SBI ecosystem.</li><li>For devices that are not registered the purpose is empty.</li><li>Allowed values are "Auth" or "Registration".</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                       |
| specVersion        | Expected version of SBI specification.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| timeout            | <ul><li>Max time the app will wait for the capture.</li><li>Its expected that the API will respond back before timeout with the best frame.</li><li>All timeouts are in milliseconds.</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                  |
| captureTime        | <ul><li>Time of capture in ISO format.</li><li>The time is as per the requesting application.</li></ul>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| transactionId      | <ul><li>Unique Id of the transaction.</li><li>This is an internal Id to the application thats providing the service.</li><li>Different id should be used for every successful auth.</li><li>So even if the transaction fails after auth we expect this number to be unique.</li></ul>                                                                                                                                                                                                                                                                                                            |
| bio.type           | Allowed values are "Finger", "Iris" or "Face".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| bio.count          | <ul><li>Number of biometric data that is collected for a given type.</li><li>The device should validate and ensure that this number is in line with the type of biometric that's captured.</li></ul>                                                                                                                                                                                                                                                                                                                                                                                             |
| bio.bioSubType     | <ul><li>Array of bioSubType for respective biometric type.</li><li>For Finger: ["Left IndexFinger", "Left MiddleFinger", "Left RingFinger", "Left LittleFinger", "Left Thumb", "Right IndexFinger", "Right MiddleFinger", "Right RingFinger", "Right LittleFinger", "Right Thumb", "UNKNOWN"]</li><li>For Iris: ["Left", "Right", "UNKNOWN"]</li><li>For Face: No bioSubType</li><li>This is an optional parameter.</li></ul>                                                                                                                                                                    |
| bio.exception      | <ul><li>This is an array and all the exceptions are marked.</li><li>In case exceptions are sent for face then follow the exception photo specification above.</li><li>For Finger: ["Left IndexFinger", "Left MiddleFinger", "Left RingFinger", "Left LittleFinger", "Left Thumb", "Right IndexFinger", "Right MiddleFinger", "Right RingFinger", "Right LittleFinger", "Right Thumb"]</li><li>For Iris: ["Left", "Right"]</li></ul>                                                                                                                                                              |
| bio.requestedScore | Upon reaching the quality score the biometric device is expected to auto capture the image.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| bio.deviceId       | Internal Id to identify the actual biometric device within the device service.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| bio.deviceSubId    | <ul><li>Allowed values are 1, 2 or 3.</li><li>The device sub id could be used to enable a specific module in the scanner appropriate for a biometric capture requirement.</li><li>Device sub id is a simple index that always starts with 1 and increases sequentially for each sub-device present.</li><li>In case of Finger/Iris its 1 for left slap/iris, 2 for right slap/iris and 3 for two thumbs/irises.</li><li>The device sub id should be set to 0 if we don't know any specific device sub id (0 is not applicable for fingerprint slap).</li><li><p></p><ul><li></li></ul></li></ul> |
| bio.previousHash   | For the first capture the previousHash is the SHA256 hash of an empty UTF-8 string. From the second capture the previous capture's "hash" is used as input. This is used to chain all the captures across modalities so all captures have happened for the same transaction and during the same time.                                                                                                                                                                                                                                                                                            |
| customOpts         | <ul><li>In case, the device vendor wants to send additional parameters they can use this to send key value pair if necessary.</li><li>The values cannot be hard coded and have to be configured by the apps server and should be modifiable upon need by the applications.</li><li>Vendors are free to include additional parameters and fine-tuning the process.</li><li>None of these values should go undocumented by the vendor.</li><li>No sensitive data should be available in the customOpts.</li></ul>                                                                                  |

#### Registration Capture Response

```
{
  "biometrics": [
    {
      "specVersion": "SBI Spec version",
      "data": {
        "digitalId": "Digital id of the device as per the Digital Id definition..",
        "bioType": "Biometric type",
        "deviceCode": "Same as serialNo in digital ID",
        "deviceServiceVersion": "SBI version",
        "bioSubType": "Left IndexFinger",
        "purpose": "Auth  or Registration",
        "env": "Target environment",
        "bioValue": "base64urlencoded biometrics (ISO format)",
        "transactionId": "Unique transaction id sent in request",
        "timestamp": "2019-02-15T10:01:57Z",
        "requestedScore": "Floating point number to represent the minimum required score for the capture. This ranges from 0-100.",
        "qualityScore": "Floating point number representing the score for the current capture. This ranges from 0-100."
      },
      "hash": "sha256 in hex format in upper case (previous "hash" + sha256 hash of the current biometric ISO data)",    
      "error": {
        "errorCode": "101",
        "errorInfo": "Invalid JSON Value Type For Discovery.. ex: {type: 'Biometric Device' or 'Finger' or 'Face' or 'Iris' } "
      }
    },
    {
      "specVersion" : "SBI Spec version",
      "data": {
        "deviceCode": "Same as serialNo in digital ID",
        "bioType" : "Finger",
        "digitalId": "Digital id of the device as per the Digital Id definition.",
        "deviceServiceVersion": "SBI version",
        "bioSubType": "Left MiddleFinger",
        "purpose": "Auth  or Registration",
        "env":  "Target environment",
        "bioValue": "base64urlencoded extracted biometric (ISO format)",
        "transactionId": "Unique transaction id sent in request",
        "timestamp": "2019-02-15T10:01:57Z",
        "requestedScore": "Floating point number to represent the minimum required score for the capture. This ranges from 0-100",
        "qualityScore": "Floating point number representing the score for the current capture. This ranges from 0-100"
      },
      "hash": "sha256 in hex format in upper case (previous "hash" + sha256 hash of the current biometric ISO data)",
      "error": {
        "errorCode": "101",
        "errorInfo": "Invalid JSON Value Type For Discovery.. ex: {type: 'Biometric Device' or 'Finger' or 'Face' or 'Iris' }"
      }
    }
  ]
}
```

#### Allowed Values for Registration Capture Response

| Parameters                | Description                                                                                                                                                                                                                                                                                                                 |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| specVersion               | Version of the SBI specification using which the response was generated.                                                                                                                                                                                                                                                    |
| data                      | <ul><li>The data object is sent as JSON Web Token (JWT).</li><li>The data block will be signed using the device key.</li></ul>                                                                                                                                                                                              |
| data.bioType              | Allowed values are "Finger", "Iris" or "Face".                                                                                                                                                                                                                                                                              |
| data.digitalId            | <ul><li>The digital id as per the digital id definition in JWT format.</li><li>For L0 devices, the digital id will be signed using the device key.</li><li>For L1 devices, the digital id will be signed using the FTM key.</li></ul>                                                                                       |
| data.bioSubType           | <ul><li>For Finger: ["Left IndexFinger", "Left MiddleFinger", "Left RingFinger", "Left LittleFinger", "Left Thumb", "Right IndexFinger", "Right MiddleFinger", "Right RingFinger", "Right LittleFinger", "Right Thumb", "UNKNOWN"]</li><li>For Iris: ["Left", "Right", "UNKNOWN"]</li><li>For Face: No bioSubType</li></ul> |
| data.deviceServiceVersion | SBI Version                                                                                                                                                                                                                                                                                                                 |
| data.env                  | <ul><li>The target environment.</li><li>Allowed values are "Staging", "Developer", "Pre-Production" or "Production".</li></ul>                                                                                                                                                                                              |
| data.purpose              | <ul><li>The purpose of the device in the SBI ecosystem.</li><li>Allowed values are "Auth" or "Registration".</li></ul>                                                                                                                                                                                                    |
| data.bioValue             | Base64-URL-encoded biometrics (in ISO format)                                                                                                                                                                                                                                                                               |
| data.transactionId        | Unique transaction id sent in request                                                                                                                                                                                                                                                                                       |
| data.timestamp            | <ul><li>Time as per the biometric device.</li><li>Note: The biometric device is expected to sync its time from the management server at regular intervals so accurate time could be maintained on the device.</li></ul>                                                                                                     |
| data.requestedScore       | Floating point number to represent the minimum required score for the capture.                                                                                                                                                                                                                                              |
| data.qualityScore         | Floating point number representing the score for the current capture.                                                                                                                                                                                                                                                       |
| hash                      | sha256 in hex format in upper case (previous "hash" + sha256 hash of the current biometric ISO data).                                                                                                                                                                                                                       |
| error                     | Relevant errors as defined under the <a href="#error-codes">error section</a> of this document.                                                                                                                                                                                                   |
| error.errorCode           | Standardized error code defined in the <a href="#error-codes">error code section</a>.                                                                                                                                                                                                             |
| error.errorInfo           | Description of the error that can be displayed to end user. Multi lingual support.                                                                                                                                                                                                                                          |

#### Windows/Linux

The applications that require more details of the SBI devices could get them by sending the HTTP request to the supported port range.

_**HTTP Request:**_

```
RCAPTURE  http://127.0.0.1:<device_service_port>/capture
HOST: 127.0.0.1: <apps port>
EXT: <app name>
```

_**HTTP Response:**_ HTTP response.

#### Android
For details on android specifications please view the section - <a href="#android-sbi-specification">Android SBI Specification</a>.

<!--
No support for Registration Capture

#### IOS

No support for Registration Capture
-->

***

## Certificates

The Application server would provide the following retrieve encryption certificate API which is white-listed to the management servers of the device provider or their partners.

### Retrieve Encryption Certificate Request URL

`POST https://{base_url}/v1/masterdata/device/encryptioncertficates`

**Version:** v1

### Retrieve Encryption Certificate Request

```
{
  "id": "io.sbi.auth.country.certificate",
  "version": "certificate server api version as defined above",
  "request": {
    "data": {
      "env":  "target environment",
      "domainUri": "uri of the auth server"
    }
  },
  "requesttime": "current timestamp in ISO format"
}
```

The request is sent in a JWT format. So the final request will look like this:

```
"request": {
  "data": "base64urlencode(header).base64urlencode(payload).base64urlencode(signature)"
}
```

### Accepted Values for Retrieve Certificate Request

```
env - Allowed values are Staging| Developer| Pre-Production | Production
domainUri - unique uri per auth providers. This can be used to federate across multiple providers or countries or unions.
```

### Encryption Certificate Response

```
{
  "id": "io.sbi.auth.country.certificate",
  "version": "certificate server api version as defined above",
  "responsetime": "Current time in ISO format",
  "response": [
    {
      "certificate": "base64encoded certificate as x509 V3 format"
    }
  ]
}
```

The entire response is sent in a JWT format. So the final response will look like this:

```
"response" : "base64urlencode(header).base64urlencode(payload).base64urlencode(signature)"
```

***

## Management Server and Management Client

### Management Server Functionalities and Interactions

The management server has the following objectives.

1. Validate the devices to ensure its a genuine device from the respective device provider. This can be achieved using the device info and the certificates for the Foundational Trust Module.
2. Register the genuine device with the SBI device server.
3. Manage/Sync time between the end device the server. The time to be synced should be the only trusted time accepted by the device.
4. Ability to issue commands to the end device for
   1. De-registration of the device (Device Keys)
   2. Collect device information to maintain, manage, support and upgrade a device remotely.
5. A central repository of all the approved devices from the device provider.
6. Safe storage of keys using HSM FIPS 140-2 Level 3. These keys are used to issue the device certificate upon registration. The Management Server is created and hosted by the device provider outside of application software. The communication protocols between the SBI and the Management Server can be decided by the respective device provider. Such communication should be restricted to the above-specified interactions only. No transactional information should be sent to this server.
7. Should have the ability to push updates from the server to the client devices.

**Notes:**

_As there is no adopter specific information being exchanged at the management server or the FTM provisioning server, there are no mandates from SBI where these are located globally. However, the adopter is recommended to have an audit and contractual mechanisms to validate the compliance of these components at any point in time._


### Management Client

Management client is the interface that connects the device with the respective management server. The communication between the management server and its clients must be designed with scalability, robustness, performance and security. The management server may add many more capabilities than what is described here, But the basic security objectives should be met at all times irrespective of the offerings.

1. For better and efficient handling of the device at large volume, we expect the devices to auto-register to the Management Server.
2. All communication to the server and from the server should follow the below properties.
   1. All communication is digitally signed with the approved algorithms
   2. All communication to the server are encrypted using one of the approved public key cryptography (HTTPS – TLS1.2/1.3 is required with one of the <a href="#cryptography">approved algorithms</a>.
   3. All request has timestamps attached in ISO format to the milliseconds inside the signature.
   4. All communication back and forth should have the signed digital id as one of the attributes.
3. It's expected that auto-registration has an absolute way to identify and validate the devices.
4. The management client should be able to detect the devices in a plug and play model.
5. All key rotation should be triggered from the server.
6. Should have the ability to detect if it's speaking to the right management server.
7. All upgrades should be verifiable and the client should have the ability to verify software upgrades.
8. Should not allow any downgrade of software.
9. Should not expose any API to capture biometric. The management server should have no ability to trigger a capture request.
10. No logging of biometric data is allowed. (Both in the encrypted and unencrypted format)

***

## Compliance

**L1 Certified Device / L1 Device** - A device certified as capable of performing encryption on the device inside its trusted zone.\
**L0 Certified Device / L0 Device** - A device certified as one where the encryption is done on the host inside its device driver or the SBI device service.

### Secure Provisioning

Secure provisioning applies to both the FTM and the Device providers.

1. The devices and FTM should have a mechanism to protect against fraudulent attempts to create or replicate.
2. The device and FTM trust should be programmed in a secure facility that is certified by the respective application adopters.
3. Organization should have a mechanism to segregate the FTM's and Devices built for SBI using a cryptographically valid and repeatable process.
4. All debug options within the FTM or device should be disabled permanently
5. All key creations need for provisioning should happen automatically using FIPS 140-2 Level 3 or higher devices. No individual or a group or organization should have a mechanism to influence this behaviour.
6. Before the devices/FTM leaving the secure provisioning facility all the necessary trust should be established and should not be re-programmable.

**Note:**

* As there is no adopter specific information being exchanged at the management server or the FTM provisioning server, there are no mandates from applications where these are located globally. However, the adopter is recommended to have an audit and contractual mechanisms to validate the compliance of these components at any point in time.\*


### Compliance Level

| API                  | Compatible |
| -------------------- | ---------- |
| Device Discovery     | L0/L1      |
| Device Info          | L0/L1      |
| Capture              | L1         |
| Registration Capture | L0/L1      |

***

## Cryptography

Supported algorithms:

| Usage                                      | Algorithm       | Key Size | Storage                                              |
| ------------------------------------------ | --------------- | -------- | ---------------------------------------------------- |
| Encryption of biometrics - Session Key     | AES             | >=256    | No storage, Key is created with TRNG/DRBG inside FTM |
| Encryption session key data outside of FTM | RSA OAEP        | >=2048   | FTM trusted memory                                   |
| Encryption session key data outside of FTM | ECC curve 25519 | >=256    | FTM trusted memory                                   |
| Biometric Signature                        | RSA             | >=2048   | Key never leaves FTM created and destroyed           |
| Biometric Signature                        | ECC curve 25519 | >=256    | Key never leaves FTM created and destroyed           |
| Secure Boot                                | RSA             | >=256    | FTM trusted memory                                   |
| Secure Boot                                | ECC curve 25519 | >=256    | FTM trusted memory                                   |

**Note:**

No other ECC curves supported.

## Signature

In all the above APIs, some of the requests and responses are signed with various keys to verify the requester's authenticity. Here we have detailed the key used for signing a particular block in a request or response body of various APIs.

| Request/Response              | Block       | Signature Key                                                                                       |
| ----------------------------- | ----------- | --------------------------------------------------------------------------------------------------- |
| Device Discovery Response     | Device Info | NA as it will not be signed                                                                         |
| Device Discovery Response     | Digital ID  | NA as it will not be signed                                                                         |
| Device Info Response          | Device Info | <ul><li>NA in case of unregistered device</li><li>Device Key in case of registered device</li></ul> |
| Device Info Response          | Digital ID  | <ul><li>For L0 device using device key</li><li>For L1 device using FTM chip key</li></ul>           |
| Capture Response              | Data        | Device key is used                                                                                  |
| Capture Response              | Digital ID  | FTM chip key is used                                                                                |
| Registration Capture Response | Data        | Device key is used                                                                                  |
| Registration Capture Response | Digital ID  | <ul><li>For L0 device using device key</li><li>For L1 device using FTM chip key</li></ul>           |

## Android SBI Specification
This section explains the mechanism for the SBI devices to communicate in the android operating system.

### Status
Draft document V 0.9

### Approach
Discovery will return the appId of the discovered items. User will be given a choice to choose one of the discovered SBI app. The selected app responds back to the intent using the default intent callback functionality.

### Device Discovery
_Request_: io.sbi.device<br>
_action_: io.sbi.device<br>
_data_: no change<br>
_type_: application/json<br>
_Request Schema_: No change in the data structure. The serialized request data as byte array is set in the intent extras with key as “input”.<br>
_Response Schema_: No change in the data structure. The serialized response data (byte array) is set in the intent extras with key as “response”.

_callbackId_ should be set to the appId, can not be empty in android.

### Device Info
_Request_: appId.Info<br>
_action_: appId.Info<br>
_data_: no change<br>
_type_: application/json<br>
_Request Schema_: No change in the data structure. The serialized request data as a byte array is set in the intent extras with the key as “input”.<br>
_Response Schema_: No change in the data structure. The serialized response data as a byte array is set in the intent extras with the key as “response”.

_deviceInfo_: _callbackId_ should be set to the appId, can not be empty in android.

### Capture
_Request_: appId.Capture<br>
_action_: appId.Capture<br>
_data_: no change<br>
_type_: application/json<br>
_flag_: FLAG_GRANT_READ_URI_PERMISSION<br>
_Request Schema_: No change in the data structure. The serialized request data as a byte array is set in the intent extras with the key as “input”.<br>
_Response Schema_: No change in the data structure. The response content is set as content URI “content://authority/path/id” in the intent extras as a string with the key as “response”.

URI must be invalidated right after the read.

### rCapture
_Request_: appId.rCapture<br>
_action_: appId.rCapture<br>
_data_: no change<br>
_type_: application/json<br>
_flag_: FLAG_GRANT_READ_URI_PERMISSION<br>
_Request Schema_: No change in the data structure. The serialized request data as byte array is set in the intent extras with key as “input”.<br>
_Response Schema_: No change in the data structure. The response content is set as content URI “content://authority/path/id” in the intent extras as a string with the key as “response”.

The content provider should not support insert, update, delete

### Device Stream
On receiving rCapture request SBI must show the stream within its UI in the foreground.

### Security
Ensure to set the correct authority in the manifest and set the android:exported as “False”

### Android Tab Specs
Android 9 and above with hardware-backed key store

## Error Codes

| Code | Message                                                                                 |
| ---- | --------------------------------------------------------------------------------------- |
| 0    | Success                                                                                 |
| 100  | Device not registered                                                                   |
| 101  | Unable to detect a biometric object                                                     |
| 102  | Technical error during extraction.                                                      |
| 103  | Device tamper detected                                                                  |
| 104  | Unable to connect to the management server                                              |
| 105  | Image orientation error                                                                 |
| 106  | Device not found                                                                        |
| 107  | Device public key expired                                                               |
| 108  | Domain public key missing                                                               |
| 109  | Requested number of biometric (Finger/IRIS) not supported                               |
| 5xx  | Custom errors. The device provider is free to choose his error code and error messages. |
