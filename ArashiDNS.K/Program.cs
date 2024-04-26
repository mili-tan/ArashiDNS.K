using ARSoft.Tools.Net.Dns;
using KcpTransport;
using System.Net;

namespace ArashiDNS.K
{
    internal class Program
    {
        public static IPEndPoint ListenerEndPoint = new(IPAddress.Loopback, 25353);
        public static IPEndPoint ServerEndPoint = new(IPAddress.Loopback, 20053);

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
            if (e.Query is not DnsMessage query) return;
            var buffer = new byte[2048];
            var dnsBytes = query.Encode().ToArraySegment(false).ToArray();

            using var connection = await KcpConnection.ConnectAsync(new KcpClientConnectionOptions()
            {
                RemoteEndPoint = ServerEndPoint,
                UpdatePeriod = TimeSpan.FromMilliseconds(1),
            });
            await using var stream = await connection.OpenOutboundStreamAsync();

            await stream.WriteAsync(dnsBytes);
            var len = await stream.ReadAsync(buffer);

            var answer = DnsMessage.Parse(buffer.Take(len).ToArray());
            e.Response = answer;
        }
    }
}
