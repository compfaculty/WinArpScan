using System.Collections.Concurrent;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using NetTools;

bool success = false;
IPAddress[]? ipAddresses = null;
MacVendorLookup macVendorLookup = new MacVendorLookup("mac-vendors.csv");

if (args.Length >= 1)
{
    success = IPAddressRange.TryParse(string.Join("", args), out IPAddressRange iPAddressRange);
    ipAddresses = iPAddressRange.AsEnumerable().ToArray();
}

if (!success || ipAddresses is null)
{
    Console.WriteLine("Invalid IP range!");
    return;
}

var ipAddressesCount = ipAddresses.Length;
var processedIpAddressesCount = 0;

List<string> header = new() { "IP", "MAC" };
ConcurrentBag<string[]> activeHosts = new();

header.AddRange(macVendorLookup.GetHeader());

Console.WriteLine("Starting scan...");

Parallel.ForEach(ipAddresses, ipAddress =>
{
    string? mac = new ArpUtilities().SendArpRequest(ipAddress);

    Interlocked.Increment(ref processedIpAddressesCount);
    if (mac is null) return;
    var info = new List<string> { ipAddress.ToString(), mac };
    info.AddRange(macVendorLookup.GetInformation(mac));
    Console.WriteLine(
        $"Progress: {processedIpAddressesCount}/{ipAddressesCount} [{100d / ipAddressesCount * processedIpAddressesCount:0.00}%] | Active: {ipAddress}");
    activeHosts.Add(info.ToArray());
});

if (!activeHosts.IsEmpty)
{
    Console.WriteLine(Environment.NewLine + "Active hosts:");

    List<string[]> activeHostsTable = activeHosts.ToList();

    activeHostsTable.Insert(0, header.ToArray());

    Console.WriteLine($"{Environment.NewLine}Found {activeHosts.Count} active hosts");
    foreach (var host in activeHostsTable)
    {
        Console.WriteLine(string.Join(",", host));
    }
}
else
{
    Console.WriteLine($"{Environment.NewLine}No active hosts found");
}

internal class ArpUtilities
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(int destIp, int srcIp, byte[] pMacAddr, ref uint phyAddrLen);

    private uint _macAddrLen = (uint)new byte[6].Length;

    public string? SendArpRequest(IPAddress ipAddress)
    {
        var macAddr = new byte[6];

        try
        {
            _ = SendARP(BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0), 0, macAddr, ref _macAddrLen);
            var mac = BitConverter.ToString(macAddr).ToUpper();
            if (mac != "00-00-00-00-00-00")
            {
                return mac;
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
        }

        return null;
    }
}

internal class MacVendorLookup
{
    private readonly string[] _header;
    private readonly string[][] _fields;

    public MacVendorLookup(string csvPath)
    {
        if (!File.Exists(csvPath))
        {
            Console.WriteLine($"file {csvPath} not found");
            _header = Array.Empty<string>();
            _fields = Array.Empty<string[]>();
            return;
        }

        string[] lines = File.ReadAllLines(csvPath);

        _header = lines[0].Split(',');
        _fields = lines.Skip(1).Select(l => Regex.Split(l, ",(?=(?:[^\"]*\"[^\"]*\")*(?![^\"]*\"))")).ToArray();
    }

    public string[] GetInformation(string macAddress)
    {
        var data = _fields.FirstOrDefault(f => macAddress.StartsWith(f[0]))?.ToArray();

        if (_fields.Length == 0 || _header.Length == 0)
        {
            return Array.Empty<string>();
        }

        if (data is null)
        {
            var result = new string[_header.Length - 1];
            for (var i = 0; i < result.Length; i++)
            {
                result[i] = "Unknown";
            }

            return result;
        }
        else
        {
            List<string> result = new();
            for (var i = 1; i < _header.Length; i++)
            {
                result.Add($"{data[i]}");
            }

            return result.ToArray();
        }
    }

    public IEnumerable<string> GetHeader()
    {
        return _header.Skip(1).ToArray();
    }
}