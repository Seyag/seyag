// Replace these documentation addresses and subnet settings for your deployment.
var lanProxy = "192.0.2.10:8118";
var tailnetProxy = "198.51.100.10:8118";
var backupProxy = "203.0.113.20:8118";
var lanNetwork = "192.0.2.0";
var lanMask = "255.255.255.0";

function FindProxyForURL(url, host) {
  // Tailnet names require the proxy when the client DNS cannot resolve them.
  if (dnsDomainIs(host, ".ts.net")) return "PROXY " + tailnetProxy;
  if (isPlainHostName(host) || dnsDomainIs(host, ".local")) return "DIRECT";
  // Check only IP literals. Resolving names here adds latency to every request.
  if (/^[0-9.]+$/.test(host) && (isInNet(host, "192.168.0.0/16".split("/")[0], "255.255.0.0") ||
      isInNet(host, "100.64.0.0/10".split("/")[0], "255.192.0.0"))) return "DIRECT";
  if (dnsDomainIs(host, ".cdn-apple.com") || dnsDomainIs(host, ".mzstatic.com") || dnsDomainIs(host, ".aaplimg.com") ||
      host == "iosapps.itunes.apple.com" || host == "osxapps.itunes.apple.com" || host == "appldnld.apple.com") return "DIRECT";
  // Allow chat delivery without sending media around inspection.
  if (dnsDomainIs(host, ".whatsapp.net") || host == "graph.whatsapp.com") {
    var label = host.split(".")[0];
    if (label != "mmg" && label != "scontent" && label.indexOf("media") != 0) return "DIRECT";
  }
  // Login and enrollment need to work before the tunnel is connected.
  if (host == "tailscale.com" || dnsDomainIs(host, ".tailscale.com") || host == "tailscale.io" || dnsDomainIs(host, ".tailscale.io")) return "DIRECT";
  if (dnsDomainIs(host, ".manageengine.com")) return "DIRECT";
  if (isInNet(myIpAddress(), lanNetwork, lanMask))
    return "PROXY " + lanProxy + "; PROXY " + tailnetProxy + "; PROXY " + backupProxy;
  return "PROXY " + tailnetProxy + "; PROXY " + lanProxy + "; PROXY " + backupProxy;
}
