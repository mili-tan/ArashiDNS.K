using System.Net;
using System.Security.Cryptography;
using System.Text;
using ArashiDNS.Ching;
using ARSoft.Tools.Net.Dns;
using KcpTransport;
using NaCl.Core;
using ChaCha20Poly1305 = NaCl.Core.ChaCha20Poly1305;


namespace ArashiDNS.KS
{
    internal class Program
    {
        public static string PassStr = Convert.ToBase64String(Encoding.UTF8.GetBytes("dnsoverkcp"));
        public static bool UseTable = false;

        static async Task Main(string[] args)
        {
            await Task.WhenAny(RunServer());

            if (!Console.IsInputRedirected && Console.KeyAvailable)
            {
                while (true)
                    if (Console.ReadKey().KeyChar == 'q')
                        Environment.Exit(0);
            }

            EventWaitHandle wait = new AutoResetEvent(false);
            while (true) wait.WaitOne();
        }

        static async Task RunServer()
        {
            var listener = await KcpListener.ListenAsync("0.0.0.0", 20053);

            while (true)
            {
                var connection = await listener.AcceptConnectionAsync();
                ConsumeClient(connection);
            }

            static async void ConsumeClient(KcpConnection connection)
            {
                using (connection)
                await using (var stream = await connection.OpenOutboundStreamAsync())
                {
                    try
                    {
                        while (true)
                        {
                            var buffer = new byte[4096];
                            var len = await stream.ReadAsync(buffer);

                            if (UseTable) buffer = Table.DeConfuseBytes(buffer, PassStr);
                            else
                                new ChaCha20(
                                        SHA512.HashData(Encoding.UTF8.GetBytes(PassStr)).Take(32).ToArray(), DateTime.Now.Minute)
                                    .Decrypt(buffer, SHA512.HashData(Encoding.UTF8.GetBytes(DateTime.UtcNow.ToString("yyyyMMddHHmm")))
                                        .TakeLast(12).ToArray(), buffer);

                            var query = DnsMessage.Parse(buffer.Take(len).ToArray());
                            var answer =
                                await new DnsClient(IPAddress.Parse("127.0.0.1"), 10000).SendMessageAsync(query) ??
                                new DnsMessage() {ReturnCode = ReturnCode.ServerFailure};

                            var dnsBytes = answer.Encode().ToArraySegment(false).ToArray();
                            if (UseTable)
                                dnsBytes = Table.ConfuseBytes(dnsBytes, PassStr);
                            else
                                new ChaCha20(
                                        SHA512.HashData(Encoding.UTF8.GetBytes(PassStr)).Take(32).ToArray(), DateTime.Now.Minute)
                                    .Encrypt(buffer, SHA512.HashData(Encoding.UTF8.GetBytes(DateTime.UtcNow.ToString("yyyyMMddHHmm")))
                                        .TakeLast(12).ToArray(), buffer);
                            await stream.WriteAsync(dnsBytes);

                            // Send to Client(Unreliable)
                            // await stream.WriteUnreliableAsync(Encoding.UTF8.GetBytes(str));
                        }
                    }
                    catch (KcpDisconnectedException e)
                    {
                        // when client has been disconnected, ReadAsync will throw KcpDisconnectedException
                        Console.WriteLine($"Disconnected, Id:{connection.ConnectionId}");
                    }
                }
            }
        }
    }
}
