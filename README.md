# A Simple SAML Identity Provider (IdP) for Testing SSO Interfaces

This project contains a SAML IdP developed at Randori for testing SSO
interfaces in other products.

It is not intended to provide any actual security, but rather as a starting
point to test SAML interfaces in products supporting external identity providers.

As released, this code provides a near-bare-minimum set of functionality to
complete a SAML sign-on process. It doesn't implement all of the spec, but the
parts that are implemented are done so in a way that is easy to hack in new test
functionality.

We hope you find it useful for testing!

## Building

```
./make-key.sh
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

There are a few variables at the top of saml-idp.py to control the host, port
and whether requests should be decompressed or not (this isn't autodetected).

This is meant to be a starting point for your modifications, so most
'configuration' should be done by editing code to suit whatever SAML function
you are attempting to probe.

There is a limited ability to change a few behaviors at runtime, such as which
parts of the response to sign, and which username to return as the logged in
user.

## Running

```
source venv/bin/activate
python3 saml-idp.py
```

If you haven't changed the defaults, your IdP is running on 0.0.0.0:10443 with
metadata at https://localhost:10443/metadata. The default ACS endpoint is
https://localhost:10443/, so visiting the site directly will give you an error
related to no SAMLRequest value in your request.

## Gotchas

Even though the XML is shown decoded on the login page, only the encoded
value is returned, so editing the XML response directly (in the preview
textarea in your browser) will have no effect unless you want to add some
javascript to update the encoded value.

## Contributing

Any improvements that keep with the spirit of the project are welcome as PRs!

Better as a PR: Adding attributes to the XML response.

Better as a fork: Replacing the XML and signature generating code with a
third-party library which just "takes care of it."


