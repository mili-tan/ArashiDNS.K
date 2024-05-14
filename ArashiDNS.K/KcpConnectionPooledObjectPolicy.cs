using Microsoft.Extensions.ObjectPool;
using KcpTransport;

namespace Arashi.Aoi
{
    public class KcpConnectionPooledObjectPolicy(KcpClientConnectionOptions kcpClientConnectionOptions) : IPooledObjectPolicy<KcpConnection>
    {

        public KcpConnection Create() => KcpConnection.ConnectAsync(kcpClientConnectionOptions).Result;

        public bool Return(KcpConnection obj) => true;
    }
}
