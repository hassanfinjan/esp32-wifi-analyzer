#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <esp_wifi.h>
#include <Adafruit_NeoPixel.h>

// AP Configuration
const char* ap_ssid = "WiFi-Analyzer";
const char* ap_password = "12345678";

WebServer server(80);

// Pin Definitions
#define LED_PIN 2
#define RGB_PIN 48
#define RGB_COUNT 1

Adafruit_NeoPixel strip(RGB_COUNT, RGB_PIN, NEO_GRB + NEO_KHZ800);

// Network data storage
struct NetworkInfo {
  String ssid;
  int32_t rssi;
  uint8_t channel;
  uint8_t encryption;
  uint8_t bssid[6];
  int clientCount;
};

std::vector<NetworkInfo> networks;
std::vector<String> clients;

// Packet capture callback
typedef struct {
  uint8_t mac[6];
} mac_addr;

typedef struct {
  int16_t fctl;
  int16_t duration;
  mac_addr da;
  mac_addr sa;
  mac_addr bssid;
  int16_t seqctl;
  unsigned char payload[];
} wifi_ieee80211_packet_t;

typedef struct {
  wifi_ieee80211_packet_t hdr;
  uint8_t payload[0];
} wifi_promiscuous_pkt_t;

std::map<String, unsigned long> lastSeen;

String macToString(const uint8_t* mac) {
  char buf[18];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

void promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  wifi_ieee80211_packet_t *ipkt = &pkt->hdr;
  
  String srcMac = macToString(ipkt->sa.mac);
  String dstMac = macToString(ipkt->da.mac);
  String bssidMac = macToString(ipkt->bssid.mac);
  
  // Track devices
  if (srcMac != "FF:FF:FF:FF:FF:FF") {
    lastSeen[srcMac] = millis();
  }
  if (dstMac != "FF:FF:FF:FF:FF:FF" && dstMac != "00:00:00:00:00:00") {
    lastSeen[dstMac] = millis();
  }
}

const char* HTML_PAGE = R"(
<!DOCTYPE html>
<html>
<head>
  <meta name='viewport' content='width=device-width,initial-scale=1'>
  <title>WiFi Analyzer</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Segoe UI', Tahoma, sans-serif;
      background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
      color: #fff;
      padding: 20px;
      min-height: 100vh;
    }
    .container { max-width: 1400px; margin: 0 auto; }
    h1 {
      text-align: center;
      color: #00ff88;
      margin-bottom: 30px;
      font-size: 2.5em;
      text-shadow: 0 0 20px rgba(0,255,136,0.5);
    }
    .controls {
      display: flex;
      gap: 15px;
      justify-content: center;
      margin-bottom: 30px;
      flex-wrap: wrap;
    }
    button {
      padding: 15px 30px;
      border: none;
      border-radius: 10px;
      font-size: 16px;
      font-weight: bold;
      cursor: pointer;
      transition: all 0.3s;
      background: linear-gradient(135deg, #00ff88 0%, #00cc66 100%);
      color: #000;
    }
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 5px 20px rgba(0,255,136,0.4);
    }
    button.secondary {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: #fff;
    }
    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 15px;
      margin-bottom: 30px;
    }
    .stat-card {
      background: rgba(255,255,255,0.05);
      border: 2px solid rgba(0,255,136,0.3);
      border-radius: 15px;
      padding: 20px;
      text-align: center;
      backdrop-filter: blur(10px);
    }
    .stat-value {
      font-size: 2.5em;
      font-weight: bold;
      color: #00ff88;
      text-shadow: 0 0 15px rgba(0,255,136,0.5);
    }
    .stat-label {
      color: #aaa;
      margin-top: 10px;
      font-size: 0.9em;
    }
    .section {
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(0,255,136,0.2);
      border-radius: 15px;
      padding: 25px;
      margin-bottom: 20px;
      backdrop-filter: blur(10px);
    }
    .section h2 {
      color: #00ff88;
      margin-bottom: 20px;
      font-size: 1.8em;
    }
    .network-item {
      background: rgba(0,255,136,0.05);
      border-left: 4px solid #00ff88;
      border-radius: 8px;
      padding: 15px;
      margin: 10px 0;
      display: grid;
      grid-template-columns: 2fr 1fr 1fr 1fr;
      gap: 15px;
      align-items: center;
    }
    .network-name {
      font-size: 1.2em;
      font-weight: bold;
      color: #00ff88;
    }
    .signal-bar {
      width: 100%;
      height: 8px;
      background: rgba(255,255,255,0.1);
      border-radius: 4px;
      overflow: hidden;
    }
    .signal-fill {
      height: 100%;
      border-radius: 4px;
      transition: width 0.3s;
    }
    .signal-excellent { background: linear-gradient(90deg, #00ff88, #00cc66); }
    .signal-good { background: linear-gradient(90deg, #ffd700, #ffb700); }
    .signal-fair { background: linear-gradient(90deg, #ff9500, #ff7700); }
    .signal-poor { background: linear-gradient(90deg, #ff3b3b, #cc0000); }
    .client-item {
      background: rgba(102,126,234,0.1);
      border-left: 4px solid #667eea;
      border-radius: 8px;
      padding: 12px;
      margin: 8px 0;
      font-family: monospace;
      font-size: 0.9em;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .badge {
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 0.8em;
      font-weight: bold;
    }
    .badge-secure { background: rgba(0,255,136,0.2); color: #00ff88; }
    .badge-open { background: rgba(255,59,59,0.2); color: #ff3b3b; }
    .loading {
      display: inline-block;
      width: 20px;
      height: 20px;
      border: 3px solid rgba(0,255,136,0.3);
      border-top: 3px solid #00ff88;
      border-radius: 50%;
      animation: spin 1s linear infinite;
      margin-right: 10px;
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    .channel-graph {
      display: flex;
      align-items: flex-end;
      justify-content: space-around;
      height: 150px;
      margin: 20px 0;
      padding: 10px;
      background: rgba(0,0,0,0.3);
      border-radius: 10px;
    }
    .channel-bar {
      flex: 1;
      margin: 0 2px;
      background: linear-gradient(to top, #667eea, #764ba2);
      border-radius: 4px 4px 0 0;
      position: relative;
      transition: all 0.3s;
    }
    .channel-bar:hover {
      background: linear-gradient(to top, #00ff88, #00cc66);
    }
    .channel-label {
      position: absolute;
      bottom: -25px;
      left: 50%;
      transform: translateX(-50%);
      font-size: 0.8em;
      color: #aaa;
    }
  </style>
</head>
<body>
  <div class='container'>
    <h1>📡 WiFi Network Analyzer</h1>
    
    <div class='controls'>
      <button onclick='scanNetworks()'>🔍 Scan Networks</button>
      <button onclick='startMonitor()' class='secondary'>📊 Start Monitor</button>
      <button onclick='stopMonitor()' class='secondary'>⏹️ Stop Monitor</button>
      <button onclick='location.reload()'>🔄 Refresh</button>
    </div>
    
    <div class='stats'>
      <div class='stat-card'>
        <div class='stat-value' id='networkCount'>0</div>
        <div class='stat-label'>Networks Found</div>
      </div>
      <div class='stat-card'>
        <div class='stat-value' id='clientCount'>0</div>
        <div class='stat-label'>Active Clients</div>
      </div>
      <div class='stat-card'>
        <div class='stat-value' id='channelUsage'>-</div>
        <div class='stat-label'>Most Used Channel</div>
      </div>
      <div class='stat-card'>
        <div class='stat-value' id='monitorStatus'>OFF</div>
        <div class='stat-label'>Monitor Mode</div>
      </div>
    </div>
    
    <div class='section'>
      <h2>📊 Channel Usage</h2>
      <div class='channel-graph' id='channelGraph'></div>
    </div>
    
    <div class='section'>
      <h2>📡 Detected Networks</h2>
      <div id='networkList'>
        <div style='text-align:center;color:#666;padding:20px;'>
          Click "Scan Networks" to begin
        </div>
      </div>
    </div>
    
    <div class='section'>
      <h2>📱 Detected Clients</h2>
      <div id='clientList'>
        <div style='text-align:center;color:#666;padding:20px;'>
          Start monitor mode to detect clients
        </div>
      </div>
    </div>
  </div>
  
  <script>
    let monitoring = false;
    
    function cmd(url, callback) {
      fetch(url)
        .then(r => r.text())
        .then(callback)
        .catch(e => console.error(e));
    }
    
    function getSignalQuality(rssi) {
      if (rssi >= -50) return { quality: 'Excellent', percent: 100, class: 'excellent' };
      if (rssi >= -60) return { quality: 'Good', percent: 75, class: 'good' };
      if (rssi >= -70) return { quality: 'Fair', percent: 50, class: 'fair' };
      return { quality: 'Poor', percent: 25, class: 'poor' };
    }
    
    function scanNetworks() {
      document.getElementById('networkList').innerHTML = '<div class="loading"></div> Scanning...';
      cmd('/scan', data => {
        const networks = JSON.parse(data);
        let html = '';
        
        networks.forEach(net => {
          const signal = getSignalQuality(net.rssi);
          const secure = net.enc != 0;
          
          html += `<div class='network-item'>
            <div>
              <div class='network-name'>${net.ssid || '(Hidden)'}</div>
              <div style='font-size:0.8em;color:#999;margin-top:5px;'>
                ${net.bssid} • CH ${net.channel}
              </div>
            </div>
            <div>
              <div class='badge ${secure ? 'badge-secure' : 'badge-open'}'>
                ${secure ? '🔒 Secure' : '🔓 Open'}
              </div>
            </div>
            <div>
              <div style='color:#aaa;font-size:0.9em;margin-bottom:5px;'>
                ${net.rssi} dBm (${signal.quality})
              </div>
              <div class='signal-bar'>
                <div class='signal-fill signal-${signal.class}' style='width:${signal.percent}%'></div>
              </div>
            </div>
            <div style='text-align:center;color:#00ff88;font-weight:bold;'>
              ${net.clients} clients
            </div>
          </div>`;
        });
        
        document.getElementById('networkList').innerHTML = html;
        document.getElementById('networkCount').innerText = networks.length;
        
        updateChannelGraph(networks);
      });
    }
    
    function updateChannelGraph(networks) {
      const channels = new Array(14).fill(0);
      networks.forEach(net => {
        if(net.channel >= 1 && net.channel <= 14) {
          channels[net.channel - 1]++;
        }
      });
      
      const maxCount = Math.max(...channels);
      let html = '';
      
      for(let i = 0; i < 13; i++) {
        const height = maxCount > 0 ? (channels[i] / maxCount * 100) : 0;
        html += `<div class='channel-bar' style='height:${height}%'>
          <div class='channel-label'>${i + 1}</div>
        </div>`;
      }
      
      document.getElementById('channelGraph').innerHTML = html;
      
      const mostUsed = channels.indexOf(Math.max(...channels)) + 1;
      document.getElementById('channelUsage').innerText = mostUsed;
    }
    
    function startMonitor() {
      monitoring = true;
      document.getElementById('monitorStatus').innerText = 'ON';
      document.getElementById('monitorStatus').style.color = '#00ff88';
      cmd('/start_monitor', () => {
        updateClients();
      });
    }
    
    function stopMonitor() {
      monitoring = false;
      document.getElementById('monitorStatus').innerText = 'OFF';
      document.getElementById('monitorStatus').style.color = '#ff3b3b';
      cmd('/stop_monitor');
    }
    
    function updateClients() {
      if(!monitoring) return;
      
      cmd('/clients', data => {
        const clients = JSON.parse(data);
        let html = '';
        
        if(clients.length === 0) {
          html = '<div style="text-align:center;color:#666;padding:20px;">No clients detected yet...</div>';
        } else {
          clients.forEach(client => {
            html += `<div class='client-item'>
              <span>📱 ${client.mac}</span>
              <span style='color:#aaa;font-size:0.9em;'>${client.lastSeen}s ago</span>
            </div>`;
          });
        }
        
        document.getElementById('clientList').innerHTML = html;
        document.getElementById('clientCount').innerText = clients.length;
        
        setTimeout(updateClients, 2000);
      });
    }
    
    scanNetworks();
  </script>
</body>
</html>
)";

void handleRoot() {
  server.send(200, "text/html", HTML_PAGE);
}

void handleScan() {
  int n = WiFi.scanNetworks();
  
  String json = "[";
  for(int i = 0; i < n; i++) {
    if(i > 0) json += ",";
    
    uint8_t* bssid = WiFi.BSSID(i);
    String bssidStr = macToString(bssid);
    
    // Count clients for this network (from captured data)
    int clientCount = 0;
    for(auto& pair : lastSeen) {
      // Simple heuristic: if device was seen recently, count it
      if(millis() - pair.second < 30000) {
        clientCount++;
      }
    }
    
    json += "{";
    json += "\"ssid\":\"" + WiFi.SSID(i) + "\",";
    json += "\"rssi\":" + String(WiFi.RSSI(i)) + ",";
    json += "\"channel\":" + String(WiFi.channel(i)) + ",";
    json += "\"enc\":" + String(WiFi.encryptionType(i)) + ",";
    json += "\"bssid\":\"" + bssidStr + "\",";
    json += "\"clients\":" + String(clientCount);
    json += "}";
  }
  json += "]";
  
  server.send(200, "application/json", json);
}

void handleStartMonitor() {
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&promiscuousCallback);
  server.send(200, "text/plain", "Monitor started");
  
  strip.setPixelColor(0, strip.Color(0, 255, 0));
  strip.show();
}

void handleStopMonitor() {
  esp_wifi_set_promiscuous(false);
  server.send(200, "text/plain", "Monitor stopped");
  
  strip.setPixelColor(0, strip.Color(0, 0, 0));
  strip.show();
}

void handleClients() {
  String json = "[";
  bool first = true;
  
  unsigned long now = millis();
  for(auto it = lastSeen.begin(); it != lastSeen.end(); ) {
    if(now - it->second > 60000) {
      it = lastSeen.erase(it);
      continue;
    }
    
    if(!first) json += ",";
    first = false;
    
    json += "{";
    json += "\"mac\":\"" + it->first + "\",";
    json += "\"lastSeen\":" + String((now - it->second) / 1000);
    json += "}";
    
    ++it;
  }
  json += "]";
  
  server.send(200, "application/json", json);
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println("\n\nWiFi Analyzer Starting...");
  
  pinMode(LED_PIN, OUTPUT);
  
  strip.begin();
  strip.show();
  strip.setBrightness(50);
  
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(ap_ssid, ap_password);
  
  Serial.print("AP IP: http://");
  Serial.println(WiFi.softAPIP());
  
  server.on("/", handleRoot);
  server.on("/scan", handleScan);
  server.on("/start_monitor", handleStartMonitor);
  server.on("/stop_monitor", handleStopMonitor);
  server.on("/clients", handleClients);
  
  server.begin();
  Serial.println("Ready! Connect to: WiFi-Analyzer (12345678)");
  Serial.println("Open: http://192.168.4.1");
  
  for(int i=0; i<3; i++) {
    strip.setPixelColor(0, strip.Color(0, 255, 0));
    strip.show();
    delay(200);
    strip.setPixelColor(0, 0);
    strip.show();
    delay(200);
  }
}

void loop() {
  server.handleClient();
}
