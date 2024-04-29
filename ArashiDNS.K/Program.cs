using ARSoft.Tools.Net.Dns;
using KcpTransport;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using ArashiDNS.Ching;
using NaCl.Core;
using ChaCha20Poly1305 = NaCl.Core.ChaCha20Poly1305;
using Org.BouncyCastle.Utilities;

namespace ArashiDNS.K
{
    internal class Program
    {
        public static IPEndPoint ListenerEndPoint = new(IPAddress.Loopback, 25353);
        public static IPEndPoint ServerEndPoint = new(IPAddress.Loopback, 20053);
        public static string PassStr = Convert.ToBase64String(Encoding.UTF8.GetBytes("dnsoverkcp"));
        public static bool UseTable = false;

        static void Main(string[] args)
        {
            var dnsServer = new DnsServer(new UdpServerTransport(ListenerEndPoint),
                new TcpServerTransport(ListenerEndPoint));
            dnsServer.QueryReceived += DnsServerOnQueryReceived;
            dnsServer.Start();

            if (!Console.IsInputRedirected && Console.KeyAvailable)
            {
                while (true)
                    if (Console.ReadKey().KeyChar == 'q')
                        Environment.Exit(0);
            }

            EventWaitHandle wait = new AutoResetEvent(false);
            while (true) wait.WaitOne();
        }

        private static async Task DnsServerOnQueryReceived(object sender, QueryReceivedEventArgs e)
        {
            try
            {
                if (e.Query is not DnsMessage query) return;

                using var connection = await KcpConnection.ConnectAsync(new KcpClientConnectionOptions()
                {
                    RemoteEndPoint = ServerEndPoint,
                    UpdatePeriod = TimeSpan.FromMilliseconds(1),
                });
                await using var stream = await connection.OpenOutboundStreamAsync();

                var dnsBytes = query.Encode().ToArraySegment(false).ToArray();

                if (UseTable)
                    dnsBytes = Table.ConfuseBytes(dnsBytes, PassStr);
                else
                    new ChaCha20(
                            SHA512.HashData(Encoding.UTF8.GetBytes(PassStr)).Take(32).ToArray(), DateTime.Now.Minute)
                        .Encrypt(dnsBytes,
                            SHA512.HashData(Encoding.UTF8.GetBytes(DateTime.UtcNow.ToString("yyyyMMddHHmm")))
                                .TakeLast(12).ToArray(), dnsBytes);
                await stream.WriteAsync(dnsBytes);

                var buffer = new byte[4096];
                var len = await stream.ReadAsync(buffer);
                if (UseTable)
                    buffer = Table.DeConfuseBytes(buffer, PassStr);
                else
                    new ChaCha20(
                            SHA512.HashData(Encoding.UTF8.GetBytes(PassStr)).Take(32).ToArray(), DateTime.Now.Minute)
                        .Decrypt(dnsBytes, SHA512.HashData(Encoding.UTF8.GetBytes(DateTime.UtcNow.ToString("yyyyMMddHHmm")))
                            .TakeLast(12).ToArray(), dnsBytes);

                var answer = DnsMessage.Parse(buffer.Take(len).ToArray());
                e.Response = answer;
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception);
            }
        }
    }
}
