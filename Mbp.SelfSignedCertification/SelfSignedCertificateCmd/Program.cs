using Mbp.SelfSignedCertification;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SelfSignedCertificateCmd
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("正在为本机生成自签名证书用于本地服务......");

            SelfSignedCertificateUtil.BindSslPort("localhost", new List<int>() { 8260, 8360 });

        }
    }
}
