using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
namespace XMLSignatureTest
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string base64 = textBox1.Text;

            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = null;
            doc.PreserveWhitespace = true;
            string samlResponse = UTF8Encoding.ASCII.GetString(Convert.FromBase64String(base64));
            doc.LoadXml(samlResponse);
            //Check the Document Signature

            List<X509Certificate2> Certs = GetCertificates(doc);    //we Are using the Certs in the Saml to make it easier I know we should be using Metadata Cert

            bool isDocSigValid = false;
            isDocSigValid = dk.nita.saml20.Utils.XmlSignatureUtils.CheckSignature(doc);

            SignedXml docSignedXml = RetrieveSignature(doc.DocumentElement);

            isDocSigValid = CheckSignature(docSignedXml, Certs);


            XmlNodeList assertionList =  doc.DocumentElement.GetElementsByTagName("Assertion", "urn:oasis:names:tc:SAML:2.0:assertion");

            bool isAssertionSigValid = false;
            if (assertionList.Count == 1)
            {
                XmlElement xmlAssertion = (XmlElement) assertionList[0];
                SignedXml assertionSignedXml = RetrieveSignature(xmlAssertion);
                isAssertionSigValid = CheckSignature(assertionSignedXml, Certs);
            }

            

            lblDocSig.Text = "Document Signature:" + isDocSigValid.ToString();
            lblAssertionSignature.Text = "Assertion Signature:" + isAssertionSigValid.ToString();


        }


        private static List<X509Certificate2> GetCertificates(XmlDocument doc)
        {
            List<X509Certificate2> lCert = new List<X509Certificate2>();
            XmlNodeList nodeList = doc.GetElementsByTagName("ds:X509Certificate");

            if (nodeList.Count == 0)
                nodeList = doc.GetElementsByTagName("X509Certificate");

            foreach (XmlNode xn in nodeList)
            {
                try
                {
                    X509Certificate2 xc = new X509Certificate2(Convert.FromBase64String(xn.InnerText));
                    lCert.Add(xc);
                }
                catch { }
            }

            return lCert;
        }

        private static SignedXml RetrieveSignature(XmlElement el)
        {
            SignedXml signedXml = new SignedXml(el);
            XmlNodeList nodeList = el.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#");
            if (nodeList.Count == 0)
                throw new InvalidOperationException("Document does not contain a signature to verify.");
            signedXml.LoadXml((XmlElement)nodeList[0]);

            return signedXml;
        }

        private static bool CheckSignature(SignedXml signedXml, IEnumerable<X509Certificate2> trustedCertificates)
        {
            foreach (X509Certificate2 cert in trustedCertificates)
            {
                if (signedXml.CheckSignature(cert.PublicKey.Key))
                    return true;
            }

            return false;
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {
            lblDocSig.Text = "Document Signature:";
            lblAssertionSignature.Text = "Assertion Signature:";
        }
    }
}
