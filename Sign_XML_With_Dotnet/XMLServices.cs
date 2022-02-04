using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Sign_XML_With_Dotnet
{
    static class XMLServices
    {
        public static X509Certificate2 GetCertificateFromStore(string certName)
        {

            // Get the certificate store for the current user.
            X509Store store = new(StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);

                // Place all certificates in an X509Certificate2Collection object.
                X509Certificate2Collection certCollection = store.Certificates;
                // If using a certificate with a trusted root you do not need to FindByTimeValid, instead:
                // currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, true);
                X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                X509Certificate2Collection signingCert = currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, false);
                if (signingCert.Count == 0)
                    return null;
                // Return the first certificate in the collection, has the right name and is current.
                return signingCert[0];
            }
            finally
            {
                store.Close();
            }
        }

        public static XmlDocument SignXml(XmlDocument xml, string tagAssinatura, string tagAtributoId, X509Certificate2 x509Cert)
        {
            try
            {
                if (xml.GetElementsByTagName(tagAssinatura).Count == 0)
                {
                    throw new Exception("Signature tag " + tagAssinatura.Trim() + " does not exist in XML.");
                }
                else if (xml.GetElementsByTagName(tagAtributoId).Count == 0)
                {
                    throw new Exception("Signature tag " + tagAtributoId.Trim() + " does not exist in XML.");
                }
                else
                {
                    XmlNodeList lists = xml.GetElementsByTagName(tagAssinatura);
                    foreach (XmlNode nodes in lists)
                    {
                        foreach (XmlNode childNodes in nodes.ChildNodes)
                        {
                            if (!childNodes.Name.Equals(tagAtributoId))
                                continue;

                            if (childNodes.NextSibling != null && childNodes.NextSibling.Name.Equals("Signature"))
                                continue;

                            // Create a reference to be signed
                            Reference reference = new()
                            {
                                Uri = ""
                            };

                            XmlElement childElemen = (XmlElement)childNodes;
                            if (childElemen.GetAttributeNode("Id") != null)
                            {
                                reference.Uri = "#" + childElemen.GetAttributeNode("Id").Value;
                            }
                            else if (childElemen.GetAttributeNode("id") != null)
                            {
                                reference.Uri = "#" + childElemen.GetAttributeNode("id").Value;
                            }

                            // Create a SignedXml object
                            SignedXml signedXml = new(xml);

                            // .net versions prior to 4.6.2 used the SHA1 algorithm by default
                            // However it is considered an unsafe algorithm by microsoft.
                            // As of .net 4.6.2 or .net core the signature default is SHA256
                            // Therefore, to continue using SHA1 it is necessary to specify in this line
                            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;

                            // Add the key to the SignedXml document
                            signedXml.SigningKey = x509Cert.PrivateKey;

                            // Add an enveloped transformation to the reference.
                            XmlDsigEnvelopedSignatureTransform env = new();
                            reference.AddTransform(env);

                            reference.DigestMethod = SignedXml.XmlDsigSHA1Url;

                            XmlDsigC14NTransform c14 = new();
                            reference.AddTransform(c14);

                            // Add the reference to the SignedXml object.
                            signedXml.AddReference(reference);

                            // Create a new KeyInfo object
                            KeyInfo keyInfo = new();

                            // Load the certificate into a KeyInfoX509Data object
                            // and add it to the KeyInfo object.
                            keyInfo.AddClause(new KeyInfoX509Data(x509Cert));

                            // Add the KeyInfo object to the SignedXml object.
                            signedXml.KeyInfo = keyInfo;
                            signedXml.ComputeSignature();

                            // Get the XML representation of the signature and save
                            // it to an XmlElement object.
                            XmlElement xmlDigitalSignature = signedXml.GetXml();

                            nodes.AppendChild(xml.ImportNode(xmlDigitalSignature, true));
                        }
                    }

                    return xml;
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to sign xml: " + ex.Message);
            }
        }
    }
}
