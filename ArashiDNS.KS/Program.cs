using System.Net;
using System.Security.Cryptography;
using System.Text;
using ArashiDNS.Ching;
using ARSoft.Tools.Net.Dns;
using KcpTransport;
using NaCl.Core;


namespace ArashiDNS.KS
{
    internal class Program
    {
        public static IPEndPoint ListenerEndPoint = new(IPAddress.Loopback, 20053);
        public static IPEndPoint UpEndPoint = new(IPAddress.Parse("8.8.8.8"), 53);
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
            var listener = await KcpListener.ListenAsync(ListenerEndPoint);

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
                                await new DnsClient(new[] {UpEndPoint.Address},
                                    new IClientTransport[]
                                    {
                                        new UdpClientTransport(UpEndPoint.Port), new TcpClientTransport(UpEndPoint.Port)
                                    }).SendMessageAsync(query) ??
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
