#!/bin/bash

# In order to use this script: apt-get install ruby-mustache xmlsec1 openssl

# do not set temp directory to root (content of this directory is cleared with rm -rf )
TEMP_DIRECTORY=`pwd`/suomifi_temp_generated_test_data

# working directory for SAML response generation
TEMP_TEST_MATERIAL=$TEMP_DIRECTORY/generated_saml_test_material

# mustache template to generate SAML response
SAML_RESPONSE_TEMPLATE=$TEMP_TEST_MATERIAL/samlResponse_template.xml

# contains processed SAML_RESPONSE_TEMPLATE
SAML_RESPONSE=$TEMP_TEST_MATERIAL/samlResponse.xml

# file for mustache configuration which is used to process SAML_RESPONSE_TEMPLATE_CONTENT
MUSTACHE_CONFIGURATION=$TEMP_TEST_MATERIAL/mustache.yml

# Directory where test certificates are created (and from where those certificates are later on added
# to generated testcases)
CERTIFICATE_DIRECTORY=$TEMP_DIRECTORY/certificates

# filename prefix for certificate which is used as "valid IdP" certificate
VALID_IDP_NAME=IDP
# filename prefix for certificate which is used as "invalid IdP" certificate
INVALID_IDP_NAME=INDVALID_IDP

# filename prefix for certificate which is used as "valid SP" certificate
VALID_SP_NAME=SP
# filename prefix for certificate which is used as "invalid SP" certificate
INVALID_SP_NAME=INVALID_SP

# Password used to protect pkcs12 container ( which - container - is needed for xmlsec1 )
P12_PASSWORD=test

# Workaround to process possible assertion level signature before Response/Message level signature
# I.e. Response/Message level signature is commented out first and comments are stripped
# after possible assertion level signature is processed
# Following magic string is used placed to XML comment line(s) which (xml comment lines) should
# be removed once possible assertion level signature is generated
TOP_LEVEL_SIGNATURE_MARKER=__this_line_is_removed_after_possible_assertion_signature_is_processed__

# mustache saml response template:
SAML_RESPONSE_TEMPLATE_CONTENT=`cat<<EOF
<saml2p:Response Destination="{{{ destination }}}"
                 ID="{{{ response_id }}}"
                 InResponseTo="{{{ in_response_to }}}"
                 IssueInstant="{{{ issue_instant }}}"
                 Version="2.0"
                 xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                 >
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">{{{ issuer }}}</saml2:Issuer>
{{#add_top_level_signature}}
<!-- $TOP_LEVEL_SIGNATURE_MARKER  this line is removed once possible assertion level signature is handled
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
            <ds:Reference URI="#{{{ response_id }}}">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
                <ds:DigestValue></ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue />
        <ds:KeyInfo>
            <ds:X509Data><ds:X509Certificate /></ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>
$TOP_LEVEL_SIGNATURE_MARKER this line is removed once possible assertion level signature is handled -->
{{/add_top_level_signature}}
    <saml2p:Status>
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </saml2p:Status>
{{#encrypt_assertion}}
    <saml2:EncryptedAssertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
{{/encrypt_assertion}}
    <saml2:Assertion ID="{{{ assertion_id }}}"
                     IssueInstant="{{{ issue_instant }}}"
                     Version="2.0"
                     xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                     >
        <saml2:Issuer>{{{ issuer }}}</saml2:Issuer>
{{#add_assertion_signature}}
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
                <ds:Reference URI="#{{{ assertion_id }}}">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
                    <ds:DigestValue></ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue />
            <ds:KeyInfo>
                <ds:X509Data>
<ds:X509Certificate />
                </ds:X509Data>
            </ds:KeyInfo>
        </ds:Signature>
{{/add_assertion_signature}}
        <saml2:Subject>
            <saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
                          NameQualifier="{{{ issuer }}}"
                          SPNameQualifier="{{{ recipient }}}"
                          >__NAME_ID__</saml2:NameID>
            <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml2:SubjectConfirmationData Address="10.10.10.10"
                                               InResponseTo="{{{ in_response_to }}}"
                                               NotOnOrAfter="{{{ not_on_or_after }}}"
                                               Recipient="{{{ destination }}}"
                                               />
            </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions NotBefore="{{{ not_before }}}"
                          NotOnOrAfter="{{{ not_on_or_after }}}"
                          >
            <saml2:AudienceRestriction>
                <saml2:Audience>{{{ recipient }}}</saml2:Audience>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement AuthnInstant="{{{ auth_instant }}}"
                              SessionIndex="{{{ session_index }}}"
                              >
            <saml2:SubjectLocality Address="10.10.10.10" />
            <saml2:AuthnContext>
                <saml2:AuthnContextClassRef>urn:oid:1.2.246.517.3002.110.1</saml2:AuthnContextClassRef>
            </saml2:AuthnContext>
        </saml2:AuthnStatement>
        <saml2:AttributeStatement>
            <saml2:Attribute FriendlyName="firstName"
                             Name="http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue>__firstName__</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="sn"
                             Name="urn:oid:2.5.4.4"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue>__sn__</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute FriendlyName="nationalIdentificationNumber"
                             Name="urn:oid:1.2.246.21"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue>__nationalIdentificationNumber__</saml2:AttributeValue>
            </saml2:Attribute>
        </saml2:AttributeStatement>
    </saml2:Assertion>
{{#encrypt_assertion}}
    </saml2:EncryptedAssertion>
{{/encrypt_assertion}}
{{#add_dummy_unsigned_assertion}}
    <!--
    BEGIN dummy assertion to test that SAML responses with multiple subject assertions and/or
    plain text assertions are not processed
    -->
    <saml2:Assertion ID="DUMMY_ASSERTION"
                 IssueInstant="{{{ issue_instant }}}"
                 Version="2.0"
                 xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                 >
        <saml2:Issuer>{{{ issuer }}}</saml2:Issuer>
        <saml2:Subject>
            <saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
                         NameQualifier="{{{ issuer }}}"
                         SPNameQualifier="{{{ recipient }}}"
                         >__dummy_NAME_ID__</saml2:NameID>
            <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml2:SubjectConfirmationData Address="10.10.10.10"
                                               InResponseTo="{{{ in_response_to }}}"
                                               NotOnOrAfter="{{{ not_on_or_after }}}"
                                               Recipient="{{{ recipient }}}"
                                               />
            </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions NotBefore="{{{ not_before }}}"
                         NotOnOrAfter="{{{ not_on_or_after }}}"
                          >
            <saml2:AudienceRestriction>
                <saml2:Audience>{{{ recipient }}}</saml2:Audience>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement AuthnInstant="{{{ auth_instant }}}"
                             SessionIndex="{{{ session_index }}}"
                              >
            <saml2:SubjectLocality Address="10.10.10.10" />
            <saml2:AuthnContext>
                <saml2:AuthnContextClassRef>urn:oid:1.2.246.517.3002.110.1</saml2:AuthnContextClassRef>
            </saml2:AuthnContext>
        </saml2:AuthnStatement>
        <saml2:AttributeStatement>
            <saml2:Attribute FriendlyName="nationalIdentificationNumber"
                             Name="urn:oid:1.2.246.21"
                             NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                             >
                <saml2:AttributeValue>__dummy_nationalIdentificationNumber__</saml2:AttributeValue>
            </saml2:Attribute>
        </saml2:AttributeStatement>
    </saml2:Assertion>
    <!--
    END dummy assertion to test that SAML responses with multiple subject assertions and/or
    plain text assertions are not processed
    -->
{{/add_dummy_unsigned_assertion}}
</saml2p:Response>
EOF`

# parse_yaml function has been copied from: https://stackoverflow.com/a/21189044
function parse_yaml {
   local prefix=$2
   local s='[[:space:]]*' w='[a-zA-Z0-9_]*' fs=$(echo @|tr @ '\034')
   sed -ne "s|^\($s\):|\1|" \
        -e "s|^\($s\)\($w\)$s:$s[\"']\(.*\)[\"']$s\$|\1$fs\2$fs\3|p" \
        -e "s|^\($s\)\($w\)$s:$s\(.*\)$s\$|\1$fs\2$fs\3|p"  $1 |
   awk -F$fs '{
      indent = length($1)/2;
      vname[indent] = $2;
      for (i in vname) {if (i > indent) {delete vname[i]}}
      if (length($3) > 0) {
         vn=""; for (i=0; i<indent; i++) {vn=(vn)(vname[i])("_")}
         printf("%s%s%s=\"%s\"\n", "'$prefix'",vn, $2, $3);
      }
   }'
}

function generateTestCertificate {

    FILENAME_PREFIX=$1

    PRIVATE_KEY_FILE=$CERTIFICATE_DIRECTORY/${FILENAME_PREFIX}_key.pem
    CERT_FILE=$CERTIFICATE_DIRECTORY/${FILENAME_PREFIX}_cert.pem
    P12_FILE=$CERTIFICATE_DIRECTORY/${FILENAME_PREFIX}.p12

    openssl req \
    -x509 \
    -sha256 \
    -nodes \
    -newkey rsa:4096 \
    -keyout $PRIVATE_KEY_FILE \
    -out $CERT_FILE \
    -days 365000 \
    -subj "/C=fi/ST=state/L=city/O=some_organization/OU=some_unit/CN=localhost/emailAddress=webmaster@localhost"

    openssl pkcs12 -nodes -export -out $P12_FILE -inkey $PRIVATE_KEY_FILE -in $CERT_FILE -passout pass:$P12_PASSWORD
}

function generateCertificates() {

    mkdir -p $CERTIFICATE_DIRECTORY

    generateTestCertificate $VALID_IDP_NAME
    generateTestCertificate $VALID_SP_NAME

    generateTestCertificate $INVALID_IDP_NAME
    generateTestCertificate $INVALID_SP_NAME

    INVALID_IDP_CERT_DATA=$(cat $CERTIFICATE_DIRECTORY/${INVALID_IDP_NAME}_cert.pem)
    VALID_IDP_CERT_DATA=$(cat $CERTIFICATE_DIRECTORY/${VALID_IDP_NAME}_cert.pem)

    INVALID_SP_CERT_DATA=$(cat $CERTIFICATE_DIRECTORY/${INVALID_SP_NAME}_cert.pem)
    INVALID_SP_KEY_DATA=$(cat $CERTIFICATE_DIRECTORY/${INVALID_SP_NAME}_key.pem)

    VALID_SP_CERT_DATA=$(cat $CERTIFICATE_DIRECTORY/${VALID_SP_NAME}_cert.pem)
    VALID_SP_KEY_DATA=$(cat $CERTIFICATE_DIRECTORY/${VALID_SP_NAME}_key.pem)
}



function generateTestData {

    rm $TEMP_TEST_MATERIAL/*.xml

    eval $(parse_yaml $MUSTACHE_CONFIGURATION "CONF_")

    # put saml response template (which shall be used to generate actual saml response) to file
    echo "$SAML_RESPONSE_TEMPLATE_CONTENT" > $SAML_RESPONSE_TEMPLATE

    # process mustache template with configuration variables given in $MUSTACHE_CONFIGURATION file
    mustache $MUSTACHE_CONFIGURATION $SAML_RESPONSE_TEMPLATE > $SAML_RESPONSE

    # Process possible Assertion's signature first (i.e. inner content first)
    if [ "$CONF_add_assertion_signature" = true ]; then
        echo "Prosessing Assertion's signature"
        xmlsec1 --sign \
        --id-attr:ID Assertion \
        --output $SAML_RESPONSE \
        --pkcs12 $CERTIFICATE_DIRECTORY/${CONF_friendly_name_of_idp_key_used_for_signing_assertion}.p12 \
        --pwd $P12_PASSWORD \
        $SAML_RESPONSE
    else
        echo "Skipping prosessing Assertion's signature"
    fi

    if [ "$CONF_encrypt_assertion" = true ]; then
      echo "Prosessing assertion encrypting"

      cat > $TEMP_TEST_MATERIAL/encryption-template.xml <<EOF
<EncryptedData
  xmlns="http://www.w3.org/2001/04/xmlenc#"
  Type="http://www.w3.org/2001/04/xmlenc#Element">
  <EncryptionMethod Algorithm=
                      "http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <EncryptedKey>
      <EncryptionMethod Algorithm=
                          "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
      <ds:KeyInfo>
        <ds:KeyName/>
        <ds:X509Data>
          <ds:X509Certificate/>
        </ds:X509Data>
      </ds:KeyInfo>
      <CipherData>
        <CipherValue/>
      </CipherData>
    </EncryptedKey>
  </ds:KeyInfo>
  <CipherData>
    <CipherValue/>
  </CipherData>
</EncryptedData>
EOF
      xmlsec1 --encrypt \
      --pubkey-cert-pem ${CERTIFICATE_DIRECTORY}/${CONF_friendly_name_of_sp_certificate_used_for_assertion_encryption}_cert.pem \
      --session-key aes-128 \
      --xml-data $SAML_RESPONSE \
      --node-xpath "/*[local-name()='Response']/*[local-name()='EncryptedAssertion']/*[local-name()='Assertion']" \
      --output $SAML_RESPONSE --print-debug \
      $TEMP_TEST_MATERIAL/encryption-template.xml
    else
      echo "Skipping assertion enryption"
    fi

    # Remove possible comments surrounding Response/Message level signature template
    echo "Removing possible comments surrounding Response/Message level signature"
    sed -i -e '/^.*'$TOP_LEVEL_SIGNATURE_MARKER'.*$/d' $SAML_RESPONSE

    # Process possible Response/Message level signature
    if [ "$CONF_add_top_level_signature" = true ]; then
        echo "Prosessing Response/Message's signature"

        xmlsec1 --sign \
        --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response \
        --output $SAML_RESPONSE \
        --pkcs12 $CERTIFICATE_DIRECTORY/${CONF_friendly_name_of_idp_key_used_for_signing_response}.p12 \
        --pwd $P12_PASSWORD \
        $SAML_RESPONSE
    else
        echo "Skipping prosessing Response/Message's signature"
    fi
}

mkdir -p $TEMP_TEST_MATERIAL

# generate IdP and SP certificates used in various test scenarios
generateCertificates

# Start generating suomifiGeneratedTestData.js file
TEST_CASES_FILE="suomifiGeneratedTestData.js"
cat > $TEST_CASES_FILE <<EOF
// This file is generated with `basename "$0"` at `date`

// Content of this file MUST NOT be reformatted (e.g. with code reformatter) due to signed XML documents
// in certain variables (do not remove e.g. possible trailing whitespaces etc.)

const testData = {};

/**
 * Certificate which represents "unknown IDP's" certificate
 *
 * @type {string}
 */
testData.${INVALID_IDP_NAME}_CERT = \`$INVALID_IDP_CERT_DATA\`;

/**
 *
 * @type {string}
 */
testData.${VALID_IDP_NAME}_CERT = \`$VALID_IDP_CERT_DATA\`;

/**
 * Private key of "uknown SP" (i.e. key of "some other" SP)
 *
 * @type {string}
 */
testData.${INVALID_SP_NAME}_KEY = \`$INVALID_SP_KEY_DATA\`;

/**
 *
 * @type {string}
 */
testData.${VALID_SP_NAME}_KEY = \`$VALID_SP_KEY_DATA\`;
EOF


# Generate variations of SAML responses to be sent to suomifi-passport-saml instance to test various scenarios

#-----------------------------------------------------------------------------------------------------------------------
echo -n '
/**
 * Valid unsigned login response, with one unsigned/unencrypted assertion.
 *
 * @type {string}
 */
testData.UNSIGNED_MESSAGE_UNSIGNED_UNENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE =
`' >> $TEST_CASES_FILE
cat > $MUSTACHE_CONFIGURATION <<EOF
---
destination: 'https://localhost/saml-sp1/callback'
response_id: RESPONSE_ID
in_response_to: IN_RESPONSE_TO_ID
assertion_id: ASSERTION_ID
not_before: '2016-11-16T21:46:05.867Z'
not_on_or_after: '2110-11-16T21:46:05.867Z'
issue_instant: '2016-11-16T21:56:05.867Z'
auth_instant: '2016-11-16T21:56:05.867Z'
session_index: SESSION_INDEX
issuer: 'https://localhost/idp1'
recipient: 'https://localhost/sp1'
# -----------------------------------------
# true/false
add_dummy_unsigned_assertion: false
add_top_level_signature: false
add_assertion_signature: false
encrypt_assertion: false
# -----------------------------------------
# $INVALID_IDP_NAME or $VALID_IDP_NAME
friendly_name_of_idp_key_used_for_signing_response: $VALID_IDP_NAME
friendly_name_of_idp_key_used_for_signing_assertion: $VALID_IDP_NAME
# -----------------------------------------
# $INVALID_SP_NAME  or $VALID_SP_NAME
friendly_name_of_sp_certificate_used_for_assertion_encryption: $VALID_SP_NAME
---
EOF
generateTestData && echo -n "$(cat $SAML_RESPONSE)" >> $TEST_CASES_FILE
echo -e '`;\n\n' >> $TEST_CASES_FILE
#-----------------------------------------------------------------------------------------------------------------------

#-----------------------------------------------------------------------------------------------------------------------
echo -n '
/**
 * Valid unsigned login response, with one unsigned/unencrypted assertion.
 *
 * @type {string}
 */
testData.UNSIGNED_MESSAGE_SIGNED_UNENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE =
`' >> $TEST_CASES_FILE
cat > $MUSTACHE_CONFIGURATION <<EOF
---
destination: 'https://localhost/saml-sp1/callback'
response_id: RESPONSE_ID
in_response_to: IN_RESPONSE_TO_ID
assertion_id: ASSERTION_ID
not_before: '2016-11-16T21:46:05.867Z'
not_on_or_after: '2110-11-16T21:46:05.867Z'
issue_instant: '2016-11-16T21:56:05.867Z'
auth_instant: '2016-11-16T21:56:05.867Z'
session_index: SESSION_INDEX
issuer: 'https://localhost/idp1'
recipient: 'https://localhost/sp1'
# -----------------------------------------
# true/false
add_dummy_unsigned_assertion: false
add_top_level_signature: false
add_assertion_signature: true
encrypt_assertion: false
# -----------------------------------------
# $INVALID_IDP_NAME or $VALID_IDP_NAME
friendly_name_of_idp_key_used_for_signing_response: $VALID_IDP_NAME
friendly_name_of_idp_key_used_for_signing_assertion: $VALID_IDP_NAME
# -----------------------------------------
# $INVALID_SP_NAME  or $VALID_SP_NAME
friendly_name_of_sp_certificate_used_for_assertion_encryption: $VALID_SP_NAME
---
EOF
generateTestData && echo -n "$(cat $SAML_RESPONSE)" >> $TEST_CASES_FILE
echo -e '`;\n\n' >> $TEST_CASES_FILE
#-----------------------------------------------------------------------------------------------------------------------

#-----------------------------------------------------------------------------------------------------------------------
echo -n '
/**
 * Valid unsigned login response, with one unsigned/unencrypted assertion.
 *
 * @type {string}
 */
testData.UNSIGNED_MESSAGE_SIGNED_ENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE =
`' >> $TEST_CASES_FILE
cat > $MUSTACHE_CONFIGURATION <<EOF
---
destination: 'https://localhost/saml-sp1/callback'
response_id: RESPONSE_ID
in_response_to: IN_RESPONSE_TO_ID
assertion_id: ASSERTION_ID
not_before: '2016-11-16T21:46:05.867Z'
not_on_or_after: '2110-11-16T21:46:05.867Z'
issue_instant: '2016-11-16T21:56:05.867Z'
auth_instant: '2016-11-16T21:56:05.867Z'
session_index: SESSION_INDEX
issuer: 'https://localhost/idp1'
recipient: 'https://localhost/sp1'
# -----------------------------------------
# true/false
add_dummy_unsigned_assertion: false
add_top_level_signature: false
add_assertion_signature: true
encrypt_assertion: true
# -----------------------------------------
# $INVALID_IDP_NAME or $VALID_IDP_NAME
friendly_name_of_idp_key_used_for_signing_response: $VALID_IDP_NAME
friendly_name_of_idp_key_used_for_signing_assertion: $VALID_IDP_NAME
# -----------------------------------------
# $INVALID_SP_NAME  or $VALID_SP_NAME
friendly_name_of_sp_certificate_used_for_assertion_encryption: $VALID_SP_NAME
---
EOF
generateTestData && echo -n "$(cat $SAML_RESPONSE)" >> $TEST_CASES_FILE
echo -e '`;\n\n' >> $TEST_CASES_FILE
#-----------------------------------------------------------------------------------------------------------------------

#-----------------------------------------------------------------------------------------------------------------------
echo -n '
/**
 * Signed login response, with one signed and encrypted assertion along with unsigned plain text assertion.
 * I.e. login response with more than one assertions.
 *
 * @type {string}
 */
testData.SIGNED_MESSAGE_SIGNED_ENCRYPTED_ASSERTION_ALONG_WITH_PLAIN_TEXT_ASSERTION_LOGIN_RESPONSE =
`' >> $TEST_CASES_FILE
cat > $MUSTACHE_CONFIGURATION <<EOF
---
destination: 'https://localhost/saml-sp1/callback'
response_id: RESPONSE_ID
in_response_to: IN_RESPONSE_TO_ID
assertion_id: ASSERTION_ID
not_before: '2016-11-16T21:46:05.867Z'
not_on_or_after: '2110-11-16T21:46:05.867Z'
issue_instant: '2016-11-16T21:56:05.867Z'
auth_instant: '2016-11-16T21:56:05.867Z'
session_index: SESSION_INDEX
issuer: 'https://localhost/idp1'
recipient: 'https://localhost/sp1'
# -----------------------------------------
# true/false
add_dummy_unsigned_assertion: true
add_top_level_signature: true
add_assertion_signature: true
encrypt_assertion: true
# -----------------------------------------
# $INVALID_IDP_NAME or $VALID_IDP_NAME
friendly_name_of_idp_key_used_for_signing_response: $VALID_IDP_NAME
friendly_name_of_idp_key_used_for_signing_assertion: $VALID_IDP_NAME
# -----------------------------------------
# $INVALID_SP_NAME  or $VALID_SP_NAME
friendly_name_of_sp_certificate_used_for_assertion_encryption: $VALID_SP_NAME
---
EOF
generateTestData && echo -n "$(cat $SAML_RESPONSE)" >> $TEST_CASES_FILE
echo -e '`;\n\n' >> $TEST_CASES_FILE
#-----------------------------------------------------------------------------------------------------------------------

#-----------------------------------------------------------------------------------------------------------------------
echo -n '
/**
 * Unsigned login response, with one unsigned encrypted assertion.
 *
 * @type {string}
 */
testData.UNSIGNED_MESSAGE_UNSIGNED_ENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE =
`' >> $TEST_CASES_FILE
cat > $MUSTACHE_CONFIGURATION <<EOF
---
destination: 'https://localhost/saml-sp1/callback'
response_id: RESPONSE_ID
in_response_to: IN_RESPONSE_TO_ID
assertion_id: ASSERTION_ID
not_before: '2016-11-16T21:46:05.867Z'
not_on_or_after: '2110-11-16T21:46:05.867Z'
issue_instant: '2016-11-16T21:56:05.867Z'
auth_instant: '2016-11-16T21:56:05.867Z'
session_index: SESSION_INDEX
issuer: 'https://localhost/idp1'
recipient: 'https://localhost/sp1'
# -----------------------------------------
# true/false
add_dummy_unsigned_assertion: false
add_top_level_signature: false
add_assertion_signature: false
encrypt_assertion: true
# -----------------------------------------
# $INVALID_IDP_NAME or $VALID_IDP_NAME
friendly_name_of_idp_key_used_for_signing_response: $VALID_IDP_NAME
friendly_name_of_idp_key_used_for_signing_assertion: $VALID_IDP_NAME
# -----------------------------------------
# $INVALID_SP_NAME  or $VALID_SP_NAME
friendly_name_of_sp_certificate_used_for_assertion_encryption: $VALID_SP_NAME
---
EOF
generateTestData && echo -n "$(cat $SAML_RESPONSE)" >> $TEST_CASES_FILE
echo -e '`;\n\n' >> $TEST_CASES_FILE
#-----------------------------------------------------------------------------------------------------------------------


#-----------------------------------------------------------------------------------------------------------------------
echo -n '
/**
 * Valid signed login response, with one unsigned/unencrypted assertion.
 * Signed with {@link '$VALID_IDP_NAME'_CERT}
 *
 * @type {string}
 */
testData.SIGNED_MESSAGE_UNSIGNED_UNENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE =
`' >> $TEST_CASES_FILE
cat > $MUSTACHE_CONFIGURATION <<EOF
---
destination: 'https://localhost/saml-sp1/callback'
response_id: RESPONSE_ID
in_response_to: IN_RESPONSE_TO_ID
assertion_id: ASSERTION_ID
not_before: '2016-11-16T21:46:05.867Z'
not_on_or_after: '2110-11-16T21:46:05.867Z'
issue_instant: '2016-11-16T21:56:05.867Z'
auth_instant: '2016-11-16T21:56:05.867Z'
session_index: SESSION_INDEX
issuer: 'https://localhost/idp1'
recipient: 'https://localhost/sp1'
# -----------------------------------------
# true/false
add_dummy_unsigned_assertion: false
add_top_level_signature: true
add_assertion_signature: false
encrypt_assertion: false
# -----------------------------------------
# $INVALID_IDP_NAME or $VALID_IDP_NAME
friendly_name_of_idp_key_used_for_signing_response: $VALID_IDP_NAME
friendly_name_of_idp_key_used_for_signing_assertion: $VALID_IDP_NAME
# -----------------------------------------
# $INVALID_SP_NAME  or $VALID_SP_NAME
friendly_name_of_sp_certificate_used_for_assertion_encryption: $VALID_SP_NAME
---
EOF
generateTestData && echo -n "$(cat $SAML_RESPONSE)" >> $TEST_CASES_FILE
echo -e '`;\n\n' >> $TEST_CASES_FILE
#-----------------------------------------------------------------------------------------------------------------------


#-----------------------------------------------------------------------------------------------------------------------
echo -n '
/**
 * Valid signed login response, with one signed/unencrypted assertion.
 * Signed with {@link '$VALID_IDP_NAME'_CERT}
 *
 * @type {string}
 */
testData.SIGNED_MESSAGE_SIGNED_UNENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE =
`' >> $TEST_CASES_FILE
cat > $MUSTACHE_CONFIGURATION <<EOF
---
destination: 'https://localhost/saml-sp1/callback'
response_id: RESPONSE_ID
in_response_to: IN_RESPONSE_TO_ID
assertion_id: ASSERTION_ID
not_before: '2016-11-16T21:46:05.867Z'
not_on_or_after: '2110-11-16T21:46:05.867Z'
issue_instant: '2016-11-16T21:56:05.867Z'
auth_instant: '2016-11-16T21:56:05.867Z'
session_index: SESSION_INDEX
issuer: 'https://localhost/idp1'
recipient: 'https://localhost/sp1'
# -----------------------------------------
# true/false
add_dummy_unsigned_assertion: false
add_top_level_signature: true
add_assertion_signature: true
encrypt_assertion: false
# -----------------------------------------
# $INVALID_IDP_NAME or $VALID_IDP_NAME
friendly_name_of_idp_key_used_for_signing_response: $VALID_IDP_NAME
friendly_name_of_idp_key_used_for_signing_assertion: $VALID_IDP_NAME
# -----------------------------------------
# $INVALID_SP_NAME  or $VALID_SP_NAME
friendly_name_of_sp_certificate_used_for_assertion_encryption: $VALID_SP_NAME
---
EOF
generateTestData && echo -n "$(cat $SAML_RESPONSE)" >> $TEST_CASES_FILE
echo -e '`;\n\n' >> $TEST_CASES_FILE
#-----------------------------------------------------------------------------------------------------------------------


#-----------------------------------------------------------------------------------------------------------------------
echo -n '
/**
 * Valid signed login response, with one signed/encrypted assertion.
 * Signed with {@link '$VALID_IDP_NAME'_CERT}
 *
 * @type {string}
 */
testData.SIGNED_MESSAGE_SIGNED_ENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE =
`' >> $TEST_CASES_FILE
cat > $MUSTACHE_CONFIGURATION <<EOF
---
destination: 'https://localhost/saml-sp1/callback'
response_id: RESPONSE_ID
in_response_to: IN_RESPONSE_TO_ID
assertion_id: ASSERTION_ID
not_before: '2016-11-16T21:46:05.867Z'
not_on_or_after: '2110-11-16T21:46:05.867Z'
issue_instant: '2016-11-16T21:56:05.867Z'
auth_instant: '2016-11-16T21:56:05.867Z'
session_index: SESSION_INDEX
issuer: 'https://localhost/idp1'
recipient: 'https://localhost/sp1'
# -----------------------------------------
# true/false
add_dummy_unsigned_assertion: false
add_top_level_signature: true
add_assertion_signature: true
encrypt_assertion: true
# -----------------------------------------
# $INVALID_IDP_NAME or $VALID_IDP_NAME
friendly_name_of_idp_key_used_for_signing_response: $VALID_IDP_NAME
friendly_name_of_idp_key_used_for_signing_assertion: $VALID_IDP_NAME
# -----------------------------------------
# $INVALID_SP_NAME  or $VALID_SP_NAME
friendly_name_of_sp_certificate_used_for_assertion_encryption: $VALID_SP_NAME
---
EOF
generateTestData && echo -n "$(cat $SAML_RESPONSE)" >> $TEST_CASES_FILE
echo -e '`;\n\n' >> $TEST_CASES_FILE
#-----------------------------------------------------------------------------------------------------------------------

#-----------------------------------------------------------------------------------------------------------------------
echo -n '
/**
 * Valid signed login response, with one signed/encrypted assertion.
 * Signed with {@link '$VALID_IDP_NAME'_CERT}
 *
 * @type {string}
 */
testData.SIGNED_MESSAGE_USIGNED_ENCRYPTED_ASSERTION_VALID_LOGIN_RESPONSE =
`' >> $TEST_CASES_FILE
cat > $MUSTACHE_CONFIGURATION <<EOF
---
destination: 'https://localhost/saml-sp1/callback'
response_id: RESPONSE_ID
in_response_to: IN_RESPONSE_TO_ID
assertion_id: ASSERTION_ID
not_before: '2016-11-16T21:46:05.867Z'
not_on_or_after: '2110-11-16T21:46:05.867Z'
issue_instant: '2016-11-16T21:56:05.867Z'
auth_instant: '2016-11-16T21:56:05.867Z'
session_index: SESSION_INDEX
issuer: 'https://localhost/idp1'
recipient: 'https://localhost/sp1'
# -----------------------------------------
# true/false
add_dummy_unsigned_assertion: false
add_top_level_signature: true
add_assertion_signature: false
encrypt_assertion: true
# -----------------------------------------
# $INVALID_IDP_NAME or $VALID_IDP_NAME
friendly_name_of_idp_key_used_for_signing_response: $VALID_IDP_NAME
friendly_name_of_idp_key_used_for_signing_assertion: $VALID_IDP_NAME
# -----------------------------------------
# $INVALID_SP_NAME  or $VALID_SP_NAME
friendly_name_of_sp_certificate_used_for_assertion_encryption: $VALID_SP_NAME
---
EOF
generateTestData && echo -n "$(cat $SAML_RESPONSE)" >> $TEST_CASES_FILE
echo -e '`;\n\n' >> $TEST_CASES_FILE
#-----------------------------------------------------------------------------------------------------------------------


echo -e '
module.exports = Object.freeze(testData);
' >> $TEST_CASES_FILE