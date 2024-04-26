using System.Net;
using System.Net.Sockets;
using System.Text;
using ARSoft.Tools.Net.Dns;
using KcpTransport;

namespace ArashiDNS.KS
{
    internal class Program
    {
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
                            var buffer = new byte[2048];
                            var len = await stream.ReadAsync(buffer);

                            var query = DnsMessage.Parse(buffer.Take(len).ToArray());
                            var answer =
                                await new DnsClient(IPAddress.Parse("127.0.0.1"), 10000).SendMessageAsync(query) ??
                                new DnsMessage() {ReturnCode = ReturnCode.ServerFailure};

                            await stream.WriteAsync(answer?.Encode().ToArraySegment(false).ToArray());

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
