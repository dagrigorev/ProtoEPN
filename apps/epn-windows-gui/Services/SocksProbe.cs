using System.IO;
using System.Net.Sockets;
using System.Text;

namespace Epn.WindowsGui.Services;

public static class SocksProbe
{
    public static async Task VerifyHttpAsync(int socksPort, CancellationToken cancellationToken)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync("127.0.0.1", socksPort, cancellationToken);
        await using var stream = tcp.GetStream();

        await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, cancellationToken);
        var greeting = await ReadExactAsync(stream, 2, cancellationToken);
        if (greeting[0] != 0x05 || greeting[1] != 0x00)
        {
            throw new InvalidOperationException("SOCKS5 proxy rejected no-auth handshake.");
        }

        var host = Encoding.ASCII.GetBytes("example.com");
        var request = new byte[7 + host.Length];
        request[0] = 0x05;
        request[1] = 0x01;
        request[2] = 0x00;
        request[3] = 0x03;
        request[4] = (byte)host.Length;
        Buffer.BlockCopy(host, 0, request, 5, host.Length);
        request[^2] = 0x00;
        request[^1] = 0x50;

        await stream.WriteAsync(request, cancellationToken);
        var reply = await ReadExactAsync(stream, 10, cancellationToken);
        if (reply[1] != 0x00)
        {
            throw new InvalidOperationException($"SOCKS5 connect test failed with code 0x{reply[1]:X2}.");
        }

        var http = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(http, cancellationToken);
        var response = await ReadSomeAsync(stream, 16, cancellationToken);
        if (!Encoding.ASCII.GetString(response).StartsWith("HTTP/", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Tunneled HTTP probe did not return an HTTP response.");
        }
    }

    private static async Task<byte[]> ReadExactAsync(Stream stream, int count, CancellationToken cancellationToken)
    {
        var buffer = new byte[count];
        var offset = 0;
        while (offset < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, count - offset), cancellationToken);
            if (read == 0)
            {
                throw new IOException("Unexpected EOF from SOCKS5 proxy.");
            }
            offset += read;
        }
        return buffer;
    }

    private static async Task<byte[]> ReadSomeAsync(Stream stream, int maxCount, CancellationToken cancellationToken)
    {
        var buffer = new byte[maxCount];
        var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
        if (read == 0)
        {
            throw new IOException("Unexpected EOF from tunneled HTTP probe.");
        }
        Array.Resize(ref buffer, read);
        return buffer;
    }
}
