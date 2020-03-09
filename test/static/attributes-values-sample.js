module.exports = [
  {
    $: {
      FriendlyName: "mail",
      Name: "urn:oid:0.9.2342.19200300.100.1.3",
      NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
    },
    AttributeValue: [
      {
        _: "example-user@example-university.edu",
        $: {
          "xmlns:xsd": "http://www.w3.org/2001/XMLSchema",
          "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
          "xsi:type": "xsd:string"
        }
      }
    ]
  },
  {
    $: {
      FriendlyName: "eduPersonTargetedID",
      Name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.10",
      NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
    },
    AttributeValue: [
      {
        NameID: [
          {
            _: "SBJMMcDv00BWSefyNqumyK0A+Jb=",
            $: {
              Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
              NameQualifier:
                "https://idp.example-university.edu/idp/shibboleth",
              SPNameQualifier: "https://www.example-service-provider.com/entity"
            }
          }
        ]
      }
    ]
  },
  {
    $: {
      FriendlyName: "eduPersonPrimaryAffiliation",
      Name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.5",
      NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
    },
    AttributeValue: [
      {
        _: "staff",
        $: {
          "xmlns:xsd": "http://www.w3.org/2001/XMLSchema",
          "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
          "xsi:type": "xsd:string"
        }
      }
    ]
  },
  {
    $: {
      FriendlyName: "displayName",
      Name: "urn:oid:2.16.840.1.113730.3.1.241",
      NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
    },
    AttributeValue: [
      {
        _: "Smith John",
        $: {
          "xmlns:xsd": "http://www.w3.org/2001/XMLSchema",
          "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
          "xsi:type": "xsd:string"
        }
      }
    ]
  },
  {
    $: {
      FriendlyName: "givenName",
      Name: "urn:oid:2.5.4.42",
      NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
    },
    AttributeValue: [
      {
        _: "John",
        $: {
          "xmlns:xsd": "http://www.w3.org/2001/XMLSchema",
          "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
          "xsi:type": "xsd:string"
        }
      }
    ]
  },
  {
    $: {
      FriendlyName: "surname",
      Name: "urn:oid:2.5.4.4",
      NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
    },
    AttributeValue: [
      {
        _: "Smith",
        $: {
          "xmlns:xsd": "http://www.w3.org/2001/XMLSchema",
          "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
          "xsi:type": "xsd:string"
        }
      }
    ]
  }
];
