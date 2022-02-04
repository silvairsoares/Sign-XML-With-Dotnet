using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace Sign_XML_With_Dotnet
{
    class Program
    {
        static void Main(string[] args)
        {
            XmlDocument xmlNaoAssinado = new();

            // Format the document to ignore white spaces.
            xmlNaoAssinado.PreserveWhitespace = false;

            // Load the passed XML file using it’s name.
            ///xmlNaoAssinado.LoadXml("String completa do XML, ainda sem assinatura");
            xmlNaoAssinado.LoadXml("<?xml version=\"1.0\" encoding=\"UTF - 8\" ?> \n" +
                "<NFe xmlns=\"http://www.contoso.com/books\"> \n" +
                "  <infNFe versao=\"4.00\" Id=\"NFe52211005462662000105550010000041721855216620\" >\n" +
                "  </infNFe> \n" +
                "</NFe>");

            //string tagAssinatura = "Name_of_tag_to_be_signed";
            string tagAssinatura = "NFe";

            //string tagAtributoId = "Name_of_tag_that_contains_the_id_attribute";
            string tagAtributoId = "infNFe";

            // Instantiates the digital certificate
            X509Certificate2 CertificadoDigital = XMLServices.GetCertificateFromStore("CN=Name_of_digital_certificate_here");            

            XmlDocument XMLAssinado = XMLServices.SignXml(xmlNaoAssinado, tagAssinatura, tagAtributoId, CertificadoDigital);

            Console.WriteLine("Hello World!");
        }
    }
}
