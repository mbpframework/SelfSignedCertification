using CERTENROLLLib;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Mbp.SelfSignedCertification
{
    /// <summary>
    /// 自签名证书工具类
    /// </summary>
    public static class SelfSignedCertificateUtil
    {
        private static X509Certificate2 CreateSelfSignedCertificate(string subjectName)
        {
            // create DN for subject and issuer
            var dn = new CX500DistinguishedName();
            dn.Encode("CN=" + subjectName, X500NameFlags.XCN_CERT_NAME_STR_NONE);

            // create a new private key for the certificate
            CX509PrivateKey privateKey = new CX509PrivateKey();
            privateKey.ProviderName = "Microsoft Base Cryptographic Provider v1.0";
            privateKey.MachineContext = true;
            privateKey.Length = 2048;
            privateKey.KeySpec = X509KeySpec.XCN_AT_SIGNATURE; // use is not limited
            privateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            privateKey.Create();

            // Use the stronger SHA512 hashing algorithm
            var hashobj = new CObjectId();
            hashobj.InitializeFromAlgorithmName(ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
                ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY,
                AlgorithmFlags.AlgorithmFlagsNone, "SHA256");

            // add extended key usage if you want - look at MSDN for a list of possible OIDs
            var oid1 = new CObjectId();
            oid1.InitializeFromValue("1.3.6.1.5.5.7.3.1"); // 服务器身份验证

            var oid2 = new CObjectId();
            oid2.InitializeFromValue("1.3.6.1.5.5.7.3.2"); // 客户端身份验证

            var oidlist = new CObjectIds();
            oidlist.Add(oid1);
            oidlist.Add(oid2);
            var eku = new CX509ExtensionEnhancedKeyUsage();
            eku.InitializeEncode(oidlist);

            // Create the self signing request
            var cert = new CX509CertificateRequestCertificate();
            cert.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextMachine, privateKey, "");
            cert.Subject = dn;
            cert.Issuer = dn; // the issuer and the subject are the same

            cert.NotBefore = DateTime.Now.AddDays(-10);
            // this cert expires immediately. Change to whatever makes sense for you
            cert.NotAfter = DateTime.Now.AddYears(1);
            cert.X509Extensions.Add((CX509Extension)eku); // add the EKU
            cert.HashAlgorithm = hashobj; // Specify the hashing algorithm


            string strDnsName = "localhost";
            CAlternativeName objRfc822Name = new CAlternativeName();
            CAlternativeNames objAlternativeNames = new CAlternativeNames();
            CX509ExtensionAlternativeNames objExtensionAlternativeNames = new CX509ExtensionAlternativeNames();

            // Set Alternative DNS Name 
            objRfc822Name.InitializeFromString(AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME, strDnsName);

            // Set Alternative Names
            objAlternativeNames.Add(objRfc822Name);
            objExtensionAlternativeNames.InitializeEncode(objAlternativeNames);
            cert.X509Extensions.Add((CX509Extension)objExtensionAlternativeNames);

            cert.Encode(); // encode the certificate

            // Do the final enrollment process
            var enroll = new CX509Enrollment();
            enroll.InitializeFromRequest(cert); // load the certificate
            enroll.CertificateFriendlyName = subjectName; // Optional: add a friendly name
            string csr = enroll.CreateRequest(); // Output the request in base64
            // and install it back as the response
            enroll.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate,
                csr, EncodingType.XCN_CRYPT_STRING_BASE64, ""); // no password
            // output a base64 encoded PKCS#12 so we can import it back to the .Net security classes
            var base64encoded = enroll.CreatePFX("", // no password, this is for internal consumption
                PFXExportOptions.PFXExportChainWithRoot);

            // instantiate the target class with the PKCS#12 data (and the empty password)
            return new System.Security.Cryptography.X509Certificates.X509Certificate2(
                System.Convert.FromBase64String(base64encoded), "",
                // mark the private key as exportable (this is usually what you want to do)
                System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable
            );
        }

        private static string ExportToFile(X509Certificate cert)
        {
            StringBuilder builder = new StringBuilder();

            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }

        public static string ExportToFile(string path, string certContext)
        {
            File.WriteAllText(path, certContext);
            return path;
        }

        private static bool AddCertToAuthRoot(X509Certificate2 certificate)
        {
            X509Store trustedMyStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            X509Store trustedPublisherStore = new X509Store(StoreName.TrustedPublisher, StoreLocation.LocalMachine);
            X509Store trustedAuthRootStore = new X509Store(StoreName.AuthRoot, StoreLocation.LocalMachine);
            X509Store trustedRootStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            X509Store trustedPeopleStore = new X509Store(StoreName.TrustedPeople, StoreLocation.LocalMachine);
            try
            {
                trustedMyStore.Open(OpenFlags.ReadWrite);
                trustedMyStore.Add(certificate);

                trustedPublisherStore.Open(OpenFlags.ReadWrite);
                trustedPublisherStore.Add(certificate);

                trustedAuthRootStore.Open(OpenFlags.ReadWrite);
                trustedAuthRootStore.Add(certificate);

                trustedRootStore.Open(OpenFlags.ReadWrite);
                trustedRootStore.Add(certificate);

                trustedPeopleStore.Open(OpenFlags.ReadWrite);
                trustedPeopleStore.Add(certificate);

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("AddCertToAuthRoot fail :" + ex.Message);
                return false;
            }
            finally
            {
                trustedMyStore.Close();
                trustedPublisherStore.Close();
                trustedAuthRootStore.Close();
                trustedRootStore.Close();
                trustedPeopleStore.Close();
            }
        }

        private static void RemoveExistsCerts(string subjectName)
        {
            Console.WriteLine("Remove exists certificates ..." + subjectName);
            for (var i = 1; i < 9; i++)
            {
                try
                {
                    var storeName = (StoreName)i;
                    var store = new X509Store(storeName, StoreLocation.LocalMachine);
                    store.Open(OpenFlags.ReadWrite | OpenFlags.IncludeArchived);
                    X509Certificate2Collection cers = store.Certificates.Find(X509FindType.FindBySubjectName, subjectName, false);
                    foreach (var cer in cers)
                    {
                        store.Remove(cer);
                    }
                    store.Close();
                }
                catch (Exception e)
                {
                    Console.WriteLine("RemoveExistsCerts fail :" + e.Message);
                }
            }
        }

        public static void BindSslPort(string subjectName, List<int> ports)
        {
            if (string.IsNullOrEmpty(subjectName))
            {
                Console.WriteLine("Invalid common name!");
                return;
            }

            RemoveExistsCerts(subjectName);
            X509Certificate2 certificate = CreateSelfSignedCertificate(subjectName);
            AddCertToAuthRoot(certificate);

            foreach (var port in ports)
            {
                BindSslPort(port, certificate);
            }
        }

        private static void BindSslPort(int port, X509Certificate2 certificate)
        {
            Console.WriteLine("Begin to bind port: " + port);
            var bindPortToCertificate = new Process();
            bindPortToCertificate.StartInfo.FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.SystemX86), "netsh.exe");
            bindPortToCertificate.StartInfo.Arguments = string.Format("http delete sslcert ipport=0.0.0.0:{0}", port);
            bindPortToCertificate.Start();
            bindPortToCertificate.WaitForExit(2000);

            bindPortToCertificate = new Process();
            bindPortToCertificate.StartInfo.FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.SystemX86), "netsh.exe");
            bindPortToCertificate.StartInfo.Arguments = string.Format("http add sslcert ipport=0.0.0.0:{0} certhash={1} appid={{{2}}}", port, certificate.Thumbprint, Guid.NewGuid());
            bindPortToCertificate.Start();
            bindPortToCertificate.WaitForExit(2000);
            Console.WriteLine("Bind port to SSL succeed! ");
        }
    }
}
