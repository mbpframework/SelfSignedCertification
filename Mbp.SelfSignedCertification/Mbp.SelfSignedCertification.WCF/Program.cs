using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.Text;
using System.Threading.Tasks;

namespace Mbp.SelfSignedCertification.WCF
{
    class Program
    {
        static void Main(string[] args)
        {

            // Create the ServiceHost.
            using (ServiceHost host = new ServiceHost(typeof(Service1)))
            {
                //ServiceCredentials serviceCredentials = host.Description.Behaviors.Find<ServiceCredentials>();
                //if (null == serviceCredentials)
                //{
                //    serviceCredentials = new ServiceCredentials();
                //    serviceCredentials.ClientCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None;
                //    host.Description.Behaviors.Add(serviceCredentials);
                //}
                ////serviceCredentials.ClientCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None;
                //serviceCredentials.ServiceCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.Root, X509FindType.FindBySubjectName, "localhost");


                host.Open();

                Console.ReadLine();

                // Close the ServiceHost.
                host.Close();
            }
        }
    }
}
