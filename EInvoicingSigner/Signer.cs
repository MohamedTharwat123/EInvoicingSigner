using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ess;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.IO;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;

public class TokenSigner
    {
    private readonly string DllLibPath = "eps2003csp11.dll";
    private readonly string DllLibPath2 = "D:\\g\\EInvoicingSigner\\EInvoicing\\EInvoicing\\eps2003csp11.dll";

    private string TokenPin = "999999999";
    private string TokenCertificate = "Egypt Trust Sealing CA";

    public static void Main(String[] args)
    {
        TokenSigner tokenSigner = new TokenSigner();
        if (args == null || args.Length == 0)
        {
            tokenSigner.ListCertificates();

            Console.WriteLine("Help.");
            Console.WriteLine("First argument is the folder path.");
            Console.WriteLine("Second argument is the token pin.");
            Console.WriteLine("Third argument is the certificate issuer.");


        }
        else
        {
            Console.WriteLine("First argument "+ args[0]);
            if (args.Length >= 2)
            {
                Console.WriteLine("Second argument " + args[1]);
                tokenSigner.TokenPin = args[1];
            }
            if (args.Length >= 3)
            {
                Console.WriteLine("Third argument " + args[2]);
                tokenSigner.TokenCertificate = args[2];
            }

            if (File.Exists(args[0] + @"\SourceDocumentJson.json") == false)
            {
                Console.WriteLine("The file " + args[0] + @"\SourceDocumentJson.json is not exist");
            }
            else
            {

                String cades = "";
                String SourceDocumentJson = File.ReadAllText(args[0] + @"\SourceDocumentJson.json");

                JObject request = JsonConvert.DeserializeObject<JObject>(SourceDocumentJson, new JsonSerializerSettings()
                {
                    FloatFormatHandling = FloatFormatHandling.String,
                    FloatParseHandling = FloatParseHandling.Decimal,
                    DateFormatHandling = DateFormatHandling.IsoDateFormat,
                    DateParseHandling = DateParseHandling.None
                });


                Console.WriteLine("request");
                Console.WriteLine(request);

                //Start serialize
                String canonicalString = tokenSigner.Serialize(request);
                Console.WriteLine("canonicalString");
                Console.WriteLine(canonicalString);
                File.WriteAllBytes(args[0] + @"\CanonicalString.txt", Encoding.UTF8.GetBytes(canonicalString));
                // retrieve cades(signature)
                //if (request["documentTypeVersion"].Value<string>() == "0.9")
                if (request["documentTypeVersion"].Value<string>() == "1")

                {
                        cades = "ANY";
                }
                else
                {
                    Console.WriteLine("before sign start");

                    cades = tokenSigner.SignWithCMS(canonicalString);
                }
                File.WriteAllBytes(args[0] + @"\Cades.txt", Encoding.UTF8.GetBytes(cades));
                JObject signaturesObject = new JObject(
                                       new JProperty("signatureType", "I"),
                                       new JProperty("value", cades));
                JArray signaturesArray = new JArray();
                signaturesArray.Add(signaturesObject);
                request.Add("signatures", signaturesArray);
                String fullSignedDocument = "{\"documents\":[" + request.ToString() + "]}";
                File.WriteAllBytes(args[0] + @"\FullSignedDocument.json", Encoding.UTF8.GetBytes(fullSignedDocument));
            }
        }
    }
       

        private byte[] Hash(string input)
        {
            using (SHA256 sha = SHA256.Create())
            {
                var output = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
                return output;
            }
        }

        private byte[] HashBytes(byte[] input)
        {
            using (SHA256 sha = SHA256.Create())
            {
                var output = sha.ComputeHash(input);
                Console.WriteLine(output);
                return output;
            }
        }
        public string SignWithCMS(String serializedJson)
        {
            byte[] data = Encoding.UTF8.GetBytes(serializedJson);
            Console.WriteLine("got the data");

            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
            Console.WriteLine("after factories");
            Console.WriteLine(File.Exists(DllLibPath) ? "File exists." : "File does not exist.");
            using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, DllLibPath, AppType.MultiThreaded))
            {
                Console.WriteLine("after access the dll file to read the connecting devices");
                ISlot slot = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent).FirstOrDefault();
                Console.WriteLine(slot);
                if (slot is null)
                {
                    Console.WriteLine("Signed with text  No Slot Found ");
                    return "No slots found";
                }
                Console.WriteLine("after if return");
                ITokenInfo tokenInfo = slot.GetTokenInfo();

                ISlotInfo slotInfo = slot.GetSlotInfo();


                using (var session = slot.OpenSession(SessionType.ReadWrite))
                {

                    session.Login(CKU.CKU_USER, Encoding.UTF8.GetBytes(TokenPin));

                    var certificateSearchAttributes = new List<IObjectAttribute>()
                    {
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509)
                    };

                    IObjectHandle certificate = session.FindAllObjects(certificateSearchAttributes).FirstOrDefault();

                    if (certificate is null)
                    {
                        return "Certificate not found";
                    }

                    X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                    store.Open(OpenFlags.MaxAllowed);

                // find cert by thumbprint
                var foundCerts = store.Certificates.Find(X509FindType.FindByIssuerName, TokenCertificate, false);

                //var foundCerts = store.Certificates.Find(X509FindType.FindBySerialNumber, "2b1cdda84ace68813284519b5fb540c2", true);

                

                    if (foundCerts.Count == 0)
                        return "no device detected";

                    var certForSigning = foundCerts[0];
                    store.Close();


                    ContentInfo content = new ContentInfo(new Oid("1.2.840.113549.1.7.5"), data);


                    SignedCms cms = new SignedCms(content, true);

                    EssCertIDv2 bouncyCertificate = new EssCertIDv2(new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.9.16.2.47")), this.HashBytes(certForSigning.RawData));

                    SigningCertificateV2 signerCertificateV2 = new SigningCertificateV2(new EssCertIDv2[] { bouncyCertificate });


                    CmsSigner signer = new CmsSigner(certForSigning);

                    signer.DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1");



                    signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));
                    signer.SignedAttributes.Add(new AsnEncodedData(new Oid("1.2.840.113549.1.9.16.2.47"), signerCertificateV2.GetEncoded()));


                    cms.ComputeSignature(signer);

                    var output = cms.Encode();
                    Console.WriteLine("output");
                    Console.WriteLine(output);

                    return Convert.ToBase64String(output);
                }
            }
        }

    public string Serialize(JObject request)
    {
        return SerializeToken(request);
    }

    private string SerializeToken(JToken request)
    {
        string serialized = "";
        if (request.Parent is null)
        {
            SerializeToken(request.First);
        }
        else
        {



            if (request.Type == JTokenType.Property)
            {
                string name = ((JProperty)request).Name.ToUpper();
                serialized += "\"" + name + "\"";
                foreach (var property in request)
                {
                    if (property.Type == JTokenType.Object)
                    {
                        serialized += SerializeToken(property);
                    }
                    if (property.Type == JTokenType.Boolean || property.Type == JTokenType.Integer || property.Type == JTokenType.Float || property.Type == JTokenType.Date)
                    {
                        serialized += "\"" + property.Value<string>() + "\"";
                    }
                    if(property.Type == JTokenType.String)
                    {
                        serialized +=  JsonConvert.ToString(property.Value<string>()) ;
                    }
                    if (property.Type == JTokenType.Array)
                    {
                        foreach (var item in property.Children())
                        {
                            serialized += "\"" + ((JProperty)request).Name.ToUpper() + "\"";
                            serialized += SerializeToken(item);
                        }
                    }
                }
            }
            // Added to fix "References"
            if (request.Type == JTokenType.String)
            {
                serialized += JsonConvert.ToString(request.Value<string>());
            }
        }
        if (request.Type == JTokenType.Object)
        {
            foreach (var property in request.Children())
            {

                if (property.Type == JTokenType.Object || property.Type == JTokenType.Property)
                {
                    serialized += SerializeToken(property);
                }
            }
        }

        return serialized;
    }


    public void ListCertificates()
    {
       
        X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.MaxAllowed);
        X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
        X509Certificate2Collection fcollection = (X509Certificate2Collection)collection.Find(X509FindType.FindBySerialNumber, "2b1cdda84ace68813284519b5fb540c2", true);
        foreach (X509Certificate2 x509 in fcollection)
        {
            try
            {
                byte[] rawdata = x509.RawData;
                Console.WriteLine("Content Type: {0}{1}", X509Certificate2.GetCertContentType(rawdata), Environment.NewLine);
                Console.WriteLine("Friendly Name: {0}{1}", x509.FriendlyName, Environment.NewLine);
                Console.WriteLine("Certificate Verified?: {0}{1}", x509.Verify(), Environment.NewLine);
                Console.WriteLine("Simple Name: {0}{1}", x509.GetNameInfo(X509NameType.SimpleName, true), Environment.NewLine);
                Console.WriteLine("Signature Algorithm: {0}{1}", x509.SignatureAlgorithm.FriendlyName, Environment.NewLine);
                Console.WriteLine("Public Key: {0}{1}", x509.PublicKey.Key.ToXmlString(false), Environment.NewLine);
                Console.WriteLine("Certificate Archived?: {0}{1}", x509.Archived, Environment.NewLine);
                Console.WriteLine("Length of Raw Data: {0}{1}", x509.RawData.Length, Environment.NewLine);               
                x509.Reset();
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine("Information could not be written out for this certificate.");
                throw ex;
            }
        }
        store.Close();       
    }

}

