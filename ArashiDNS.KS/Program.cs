using System.Net;
using System.Security.Cryptography;
using System.Text;
using Arashi.Aoi;
using ArashiDNS.Ching;
using ARSoft.Tools.Net.Dns;
using KcpTransport;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.ObjectPool;
using NaCl.Core;
using static Org.BouncyCastle.Math.EC.ECCurve;


namespace ArashiDNS.KS
{
    internal class Program
    {
        public static IPEndPoint ListenerEndPoint = new(IPAddress.Loopback, 20053);
        public static IPEndPoint UpEndPoint = new(IPAddress.Parse("8.8.8.8"), 53);
        public static string PassStr = Convert.ToBase64String(Encoding.UTF8.GetBytes("dnsoverkcp"));
        public static bool UseTable = false;
        public static int Timeout = 10009;
        public static bool UseLog;

        public static DefaultObjectPool<DnsClient> UpPool = new(new DnsClientPooledObjectPolicy(
            new[] {UpEndPoint.Address}, Timeout, UpEndPoint.Port), 30);

        static async Task Main(string[] args)
        {
            var cmd = new CommandLineApplication
            {
                Name = "ArashiDNS.KS",
                Description = "ArashiDNS.KS - DNS over KCP Server" +
                  Environment.NewLine +
                  $"Copyright (c) {DateTime.Now.Year} Milkey Tan. Code released under the MPL License"
            };
            cmd.HelpOption("-?|-h|--help");
            var isZh = Thread.CurrentThread.CurrentCulture.Name.Contains("zh");
            var upArgument = cmd.Argument("target",
                isZh ? "目标上游 DNS 端点" : "Target upstream DNS service endpoint");
            var ipOption = cmd.Option<string>("-l|--listen <IPEndPoint>",
                isZh ? "监听的地址与端口" : "Set server listening address and port", CommandOptionType.SingleValue);
            var passOption = cmd.Option<int>("-p|--pass <pass>",
                isZh ? "用于加密或混淆的口令" : "Password for encryption or obfuscation", CommandOptionType.SingleValue);
            var cOption = cmd.Option("-c", isZh ? "使用混淆而不是加密（不安全！）" : "Use obfuscation instead of encryption (unsafe!)",
                CommandOptionType.NoValue);
            var wOption = cmd.Option<int>("-w <timeout>",
                isZh ? "等待回复的超时时间(毫秒)。" : "Timeout time to wait for reply", CommandOptionType.SingleValue);
            var logOption = cmd.Option("-log", isZh ? "打印查询与响应日志。" : "Print query and response logs",
                CommandOptionType.NoValue);

            cmd.OnExecute(() =>
            {
                if (isZh) UpEndPoint = new(IPAddress.Parse("119.29.29.29"), 53);
                if (upArgument.HasValue) UpEndPoint = IPEndPoint.Parse(upArgument.Value!);
                if (ipOption.HasValue()) ListenerEndPoint = IPEndPoint.Parse(ipOption.Value()!);
                if (passOption.HasValue()) PassStr = Convert.ToBase64String(Encoding.UTF8.GetBytes(passOption.Value()!));
                if (wOption.HasValue()) Timeout = int.Parse(wOption.Value()!);
                if (cOption.HasValue()) UseTable = true;
                if (logOption.HasValue()) UseLog = true;

                Task.WhenAny(RunServer());

                Console.WriteLine("ArashiDNS.KS - DNS over KCP Server");
                Console.WriteLine("The forwarded upstream is: " + UpEndPoint);
                Console.WriteLine("Now listening on: " + ListenerEndPoint);
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

                            var client = UpPool.Get();
                            var query = DnsMessage.Parse(buffer.Take(len).ToArray());
                            var answer = await client.SendMessageAsync(query) ??
                                         new DnsMessage() {ReturnCode = ReturnCode.ServerFailure};
                            UpPool.Return(client);

                            var dnsBytes = answer.Encode().ToArraySegment(false).ToArray();
                            if (UseLog) await Task.Run(() => PrintDnsMessage(answer));
                            if (UseTable) dnsBytes = Table.ConfuseBytes(dnsBytes, PassStr);
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

        public static void PrintDnsMessage(DnsMessage message)
        {
            Console.Write($"Q: {message.Questions.FirstOrDefault()} ");
            Console.Write($"R: {message.ReturnCode} ");
            foreach (var item in message.AnswerRecords) Console.Write($" A:{item} ");
            Console.Write(Environment.NewLine);
        }
    }
}
