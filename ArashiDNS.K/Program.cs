using ARSoft.Tools.Net.Dns;
using KcpTransport;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Arashi.Aoi;
using ArashiDNS.Ching;
using McMaster.Extensions.CommandLineUtils;
using NaCl.Core;
using Microsoft.Extensions.ObjectPool;

namespace ArashiDNS.K
{
    internal class Program
    {
        public static IPEndPoint ListenerEndPoint = new(IPAddress.Loopback, 25353);
        public static IPEndPoint ServerEndPoint = new(IPAddress.Loopback, 20053);
        public static string PassStr = Convert.ToBase64String(Encoding.UTF8.GetBytes("dnsoverkcp"));
        public static bool UseTable = false;
        public static bool UseLog;

        public static DefaultObjectPool<KcpConnection> KcpPool = new(new KcpConnectionPooledObjectPolicy(
            new KcpClientConnectionOptions()
            {
                RemoteEndPoint = ServerEndPoint,
                UpdatePeriod = TimeSpan.FromMilliseconds(1),
            }), 10);


        static void Main(string[] args)
        {
            var cmd = new CommandLineApplication
            {
                Name = "ArashiDNS.K",
                Description = "ArashiDNS.K - DNS over KCP Client" +
                              Environment.NewLine +
                              $"Copyright (c) {DateTime.Now.Year} Milkey Tan. Code released under the MPL License"
            };
            cmd.HelpOption("-?|-h|--help");
            var isZh = Thread.CurrentThread.CurrentCulture.Name.Contains("zh");
            var serverArgument = cmd.Argument("target",
                isZh ? "目标 DNS over KCP 端点" : "Target DNS over KCP service endpoint");
            var ipOption = cmd.Option<string>("-l|--listen <IPEndPoint>",
                isZh ? "监听的地址与端口" : "Set server listening address and port", CommandOptionType.SingleValue);
            var passOption = cmd.Option<int>("-p|--pass <pass>",
                isZh ? "用于加密或混淆的口令" : "Password for encryption or obfuscation", CommandOptionType.SingleValue);
            var cOption = cmd.Option("-c", isZh ? "使用混淆而不是加密（不安全！）" : "Use obfuscation instead of encryption (unsafe!)",
                CommandOptionType.NoValue);
            var logOption = cmd.Option("--log", isZh ? "打印查询与响应日志。" : "Print query and response logs",
                CommandOptionType.NoValue);

            cmd.OnExecute(() =>
            {
                if (serverArgument.HasValue) ServerEndPoint = IPEndPoint.Parse(serverArgument.Value!);
                if (ipOption.HasValue()) ListenerEndPoint = IPEndPoint.Parse(ipOption.Value()!);
                if (passOption.HasValue()) PassStr = Convert.ToBase64String(Encoding.UTF8.GetBytes(passOption.Value()!));
                if (cOption.HasValue()) UseTable = true;
                if (logOption.HasValue()) UseLog = true;

                var dnsServer = new DnsServer(new UdpServerTransport(ListenerEndPoint),
                    new TcpServerTransport(ListenerEndPoint));
                dnsServer.QueryReceived += DnsServerOnQueryReceived;
                dnsServer.Start();

                Console.WriteLine("ArashiDNS.K - DNS over KCP Client");
                Console.WriteLine("Now listening on: " + ListenerEndPoint);
                Console.WriteLine("The server is: " + ServerEndPoint);
                Console.WriteLine("Application started. Press Ctrl+C / q to shut down.");

                if (!Console.IsInputRedirected && Console.KeyAvailable)
                {
                    while (true)
                        if (Console.ReadKey().KeyChar == 'q')
                            Environment.Exit(0);
                }

                EventWaitHandle wait = new AutoResetEvent(false);
                while (true) wait.WaitOne();
            });

            cmd.Execute(args);
        }

        private static async Task DnsServerOnQueryReceived(object sender, QueryReceivedEventArgs e)
        {
            try
            {
                if (e.Query is not DnsMessage query) return;
                var connection = KcpPool.Get();
                var stream = await connection.OpenOutboundStreamAsync();
                var dnsBytes = query.Encode().ToArraySegment(false).ToArray();

                if (UseTable) dnsBytes = Table.ConfuseBytes(dnsBytes, PassStr);
                else
                    new ChaCha20(
                            SHA512.HashData(Encoding.UTF8.GetBytes(PassStr)).Take(32).ToArray(), DateTime.Now.Minute)
                        .Encrypt(dnsBytes,
                            SHA512.HashData(Encoding.UTF8.GetBytes(DateTime.UtcNow.ToString("yyyyMMddHHmm")))
                                .TakeLast(12).ToArray(), dnsBytes);
                await stream.WriteAsync(dnsBytes);

                var buffer = new byte[4096];
                var len = await stream.ReadAsync(buffer);
                if (UseTable) buffer = Table.DeConfuseBytes(buffer, PassStr);
                else
                    new ChaCha20(
                            SHA512.HashData(Encoding.UTF8.GetBytes(PassStr)).Take(32).ToArray(), DateTime.Now.Minute)
                        .Decrypt(dnsBytes, SHA512.HashData(Encoding.UTF8.GetBytes(DateTime.UtcNow.ToString("yyyyMMddHHmm")))
                            .TakeLast(12).ToArray(), dnsBytes);

                KcpPool.Return(connection);

                var answer = DnsMessage.Parse(buffer.Take(len).ToArray());
                e.Response = answer;

                if (UseLog) await Task.Run(() => PrintDnsMessage(answer));
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception);
            }
        }

        public static void PrintDnsMessage(DnsMessage message)
        {
            Console.Write($"Q: {message.Questions.FirstOrDefault()} ");
            Console.Write($"R: {message.ReturnCode} ");
            foreach (var item in message.AnswerRecords) Console.Write($" A:{item} ");
            Console.Write(Environment.NewLine);
        }
    }
}
