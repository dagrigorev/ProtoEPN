namespace Epn.WindowsGui.Services;

public sealed record EpnEndpoint(string Host, int Port);

public static class EndpointParser
{
    public static EpnEndpoint Parse(string input)
    {
        var value = input.Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException("Endpoint URL is required.");
        }

        if (!value.Contains("://", StringComparison.Ordinal))
        {
            value = "epn://" + value;
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            throw new InvalidOperationException("Endpoint URL is invalid.");
        }

        var port = uri.Port > 0 ? uri.Port : 8000;
        if (string.IsNullOrWhiteSpace(uri.Host))
        {
            throw new InvalidOperationException("Endpoint host is required.");
        }

        return new EpnEndpoint(uri.Host, port);
    }
}
