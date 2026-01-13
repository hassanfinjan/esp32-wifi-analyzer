#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>

const char* ap_ssid = "ESP32-Analyzer";
const char* ap_password = "analyzer";

WebServer server(80);

#define MAX_NETWORKS 50
struct NetworkInfo {
  String ssid;
  int32_t rssi;
  uint8_t channel;
  uint8_t encryption;
  String bssid;
  bool hidden;
};

NetworkInfo networks[MAX_NETWORKS];
int networkCount = 0;
unsigned long lastScan = 0;

const char* getEncryptionType(uint8_t type) {
  switch(type) {
    case WIFI_AUTH_OPEN: return "Open";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-Enterprise";
    case WIFI_AUTH_WPA3_PSK: return "WPA3";
    default: return "Unknown";
  }
}

String getSignalQuality(int32_t rssi) {
  if(rssi >= -50) return "Excellent";
  if(rssi >= -60) return "Good";
  if(rssi >= -70) return "Fair";
  if(rssi >= -80) return "Weak";
  return "Very Weak";
}

int getRSSIPercentage(int32_t rssi) {
  if(rssi >= -50) return 100;
  if(rssi <= -100) return 0;
  return 2 * (rssi + 100);
}

void scanNetworks() {
  networkCount = WiFi.scanNetworks(false, true, false, 300);
  if(networkCount > MAX_NETWORKS) networkCount = MAX_NETWORKS;
  
  for(int i = 0; i < networkCount; i++) {
    networks[i].ssid = WiFi.SSID(i);
    networks[i].rssi = WiFi.RSSI(i);
    networks[i].channel = WiFi.channel(i);
    networks[i].encryption = WiFi.encryptionType(i);
    networks[i].bssid = WiFi.BSSIDstr(i);
    networks[i].hidden = WiFi.SSID(i).length() == 0;
    
    if(networks[i].hidden) {
      networks[i].ssid = "[Hidden Network]";
    }
  }
  
  lastScan = millis();
}

void handleRoot() {
  String html = R"(
<!DOCTYPE html>
<html>
<head>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>WiFi Analyzer</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { 
  font-family:'Segoe UI',sans-serif;
  background:#0a0e27;
  color:#fff;
  padding:15px;
}
.header {
  text-align:center;
  padding:20px;
  background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);
  border-radius:15px;
  margin-bottom:20px;
  box-shadow:0 10px 30px rgba(102,126,234,0.3);
}
h1 { font-size:2em; margin-bottom:10px; }
.stats {
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
  gap:10px;
  margin-bottom:20px;
}
.stat-card {
  background:rgba(255,255,255,0.05);
  padding:15px;
  border-radius:10px;
  border:1px solid rgba(102,126,234,0.3);
  text-align:center;
}
.stat-value { font-size:2em; color:#667eea; font-weight:bold; }
.stat-label { color:#888; margin-top:5px; font-size:0.9em; }
.controls {
  display:flex;
  gap:10px;
  margin-bottom:20px;
  flex-wrap:wrap;
}
button {
  flex:1;
  min-width:150px;
  padding:15px;
  border:none;
  border-radius:10px;
  font-size:16px;
  font-weight:bold;
  cursor:pointer;
  transition:all 0.3s;
  background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);
  color:#fff;
}
button:hover { transform:translateY(-2px); box-shadow:0 5px 20px rgba(102,126,234,0.4); }
button:active { transform:translateY(0); }
.network-card {
  background:rgba(255,255,255,0.03);
  border:1px solid rgba(102,126,234,0.2);
  border-radius:12px;
  padding:15px;
  margin-bottom:15px;
  transition:all 0.3s;
}
.network-card:hover {
  background:rgba(255,255,255,0.08);
  border-color:#667eea;
  transform:translateX(5px);
}
.network-header {
  display:flex;
  justify-content:space-between;
  align-items:center;
  margin-bottom:10px;
}
.network-ssid {
  font-size:1.3em;
  font-weight:bold;
  color:#667eea;
}
.signal-badge {
  padding:5px 12px;
  border-radius:20px;
  font-size:0.85em;
  font-weight:bold;
}
.signal-excellent { background:#10b981; }
.signal-good { background:#3b82f6; }
.signal-fair { background:#f59e0b; }
.signal-weak { background:#ef4444; }
.signal-very-weak { background:#7f1d1d; }
.network-details {
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
  gap:10px;
  font-size:0.9em;
  color:#aaa;
}
.detail { 
  display:flex;
  align-items:center;
  gap:8px;
}
.detail-label { color:#667eea; font-weight:bold; }
.signal-bar {
  width:100%;
  height:20px;
  background:rgba(255,255,255,0.1);
  border-radius:10px;
  overflow:hidden;
  margin-top:10px;
}
.signal-fill {
  height:100%;
  background:linear-gradient(90deg,#ef4444 0%,#f59e0b 50%,#10b981 100%);
  transition:width 0.5s;
  border-radius:10px;
}
.channel-graph {
  background:rgba(255,255,255,0.03);
  border:1px solid rgba(102,126,234,0.2);
  border-radius:12px;
  padding:20px;
  margin-bottom:20px;
  overflow-x:auto;
}
.channel-bars {
  display:flex;
  align-items:flex-end;
  height:200px;
  gap:5px;
  min-width:600px;
}
.channel-bar {
  flex:1;
  background:linear-gradient(180deg,#667eea 0%,#764ba2 100%);
  border-radius:5px 5px 0 0;
  position:relative;
  min-width:30px;
  transition:all 0.3s;
  cursor:pointer;
}
.channel-bar:hover { opacity:0.8; }
.channel-label {
  position:absolute;
  bottom:-25px;
  left:50%;
  transform:translateX(-50%);
  font-size:0.8em;
  color:#888;
  white-space:nowrap;
}
.channel-count {
  position:absolute;
  top:-20px;
  left:50%;
  transform:translateX(-50%);
  font-size:0.9em;
  font-weight:bold;
  color:#667eea;
}
.loading {
  text-align:center;
  padding:40px;
  color:#667eea;
}
.spinner {
  border:4px solid rgba(102,126,234,0.1);
  border-top:4px solid #667eea;
  border-radius:50%;
  width:40px;
  height:40px;
  animation:spin 1s linear infinite;
  margin:0 auto 10px;
}
@keyframes spin {
  0% { transform:rotate(0deg); }
  100% { transform:rotate(360deg); }
}
.hidden-badge {
  background:#ef4444;
  color:#fff;
  padding:3px 8px;
  border-radius:12px;
  font-size:0.75em;
  margin-left:10px;
}
</style>
</head>
<body>
<div class='header'>
  <h1>📡 WiFi Analyzer</h1>
  <div>Real-time Network Monitoring</div>
</div>

<div class='stats'>
  <div class='stat-card'>
    <div class='stat-value' id='totalNetworks'>0</div>
    <div class='stat-label'>Networks Found</div>
  </div>
  <div class='stat-card'>
    <div class='stat-value' id='openNetworks'>0</div>
    <div class='stat-label'>Open Networks</div>
  </div>
  <div class='stat-card'>
    <div class='stat-value' id='hiddenNetworks'>0</div>
    <div class='stat-label'>Hidden Networks</div>
  </div>
</div>

<div class='controls'>
  <button onclick='scan()'>🔄 Scan Now</button>
  <button onclick='toggleAutoScan()' id='autoBtn'>▶️ Auto Scan</button>
  <button onclick='sortBy("rssi")'>📊 Sort by Signal</button>
  <button onclick='sortBy("channel")'>📻 Sort by Channel</button>
</div>

<div class='channel-graph'>
  <h3 style='margin-bottom:15px;color:#667eea;'>📊 Channel Distribution</h3>
  <div class='channel-bars' id='channelGraph'></div>
</div>

<div id='networks'></div>

<script>
let autoScan = false;
let autoScanInterval;
let currentSort = 'rssi';

function scan() {
  document.getElementById('networks').innerHTML = '<div class="loading"><div class="spinner"></div>Scanning networks...</div>';
  fetch('/scan').then(r=>r.json()).then(data => {
    displayNetworks(data);
    updateChannelGraph(data);
  });
}

function displayNetworks(data) {
  const stats = { total: data.length, open: 0, hidden: 0 };
  
  data.forEach(n => {
    if(n.enc === 'Open') stats.open++;
    if(n.hidden) stats.hidden++;
  });
  
  document.getElementById('totalNetworks').innerText = stats.total;
  document.getElementById('openNetworks').innerText = stats.open;
  document.getElementById('hiddenNetworks').innerText = stats.hidden;
  
  let html = '';
  data.forEach(n => {
    const quality = n.rssi >= -50 ? 'excellent' : n.rssi >= -60 ? 'good' : n.rssi >= -70 ? 'fair' : n.rssi >= -80 ? 'weak' : 'very-weak';
    const qualityText = n.rssi >= -50 ? 'Excellent' : n.rssi >= -60 ? 'Good' : n.rssi >= -70 ? 'Fair' : n.rssi >= -80 ? 'Weak' : 'Very Weak';
    const percent = Math.max(0, Math.min(100, 2 * (n.rssi + 100)));
    
    html += `
      <div class='network-card'>
        <div class='network-header'>
          <div>
            <span class='network-ssid'>${n.ssid}</span>
            ${n.hidden ? '<span class="hidden-badge">HIDDEN</span>' : ''}
          </div>
          <span class='signal-badge signal-${quality}'>${qualityText}</span>
        </div>
        <div class='signal-bar'>
          <div class='signal-fill' style='width:${percent}%'></div>
        </div>
        <div class='network-details'>
          <div class='detail'><span class='detail-label'>Signal:</span> ${n.rssi} dBm</div>
          <div class='detail'><span class='detail-label'>Channel:</span> ${n.ch}</div>
          <div class='detail'><span class='detail-label'>Security:</span> ${n.enc}</div>
          <div class='detail'><span class='detail-label'>BSSID:</span> ${n.bssid}</div>
        </div>
      </div>
    `;
  });
  
  document.getElementById('networks').innerHTML = html;
}

function updateChannelGraph(data) {
  const channels = {};
  for(let i = 1; i <= 13; i++) channels[i] = 0;
  
  data.forEach(n => {
    if(n.ch >= 1 && n.ch <= 13) channels[n.ch]++;
  });
  
  const maxCount = Math.max(...Object.values(channels));
  let html = '';
  
  for(let ch = 1; ch <= 13; ch++) {
    const height = maxCount > 0 ? (channels[ch] / maxCount) * 100 : 0;
    html += `
      <div class='channel-bar' style='height:${height}%' title='Channel ${ch}: ${channels[ch]} networks'>
        ${channels[ch] > 0 ? `<div class='channel-count'>${channels[ch]}</div>` : ''}
        <div class='channel-label'>Ch ${ch}</div>
      </div>
    `;
  }
  
  document.getElementById('channelGraph').innerHTML = html;
}

function toggleAutoScan() {
  autoScan = !autoScan;
  const btn = document.getElementById('autoBtn');
  if(autoScan) {
    btn.innerText = '⏸️ Stop Auto';
    scan();
    autoScanInterval = setInterval(scan, 10000);
  } else {
    btn.innerText = '▶️ Auto Scan';
    clearInterval(autoScanInterval);
  }
}

function sortBy(type) {
  currentSort = type;
  scan();
}

scan();
</script>
</body>
</html>
)";
  
  server.send(200, "text/html", html);
}

void handleScan() {
  scanNetworks();
  
  String json = "[";
  for(int i = 0; i < networkCount; i++) {
    if(i > 0) json += ",";
    json += "{";
    json += "\"ssid\":\"" + networks[i].ssid + "\",";
    json += "\"rssi\":" + String(networks[i].rssi) + ",";
    json += "\"ch\":" + String(networks[i].channel) + ",";
    json += "\"enc\":\"" + String(getEncryptionType(networks[i].encryption)) + "\",";
    json += "\"bssid\":\"" + networks[i].bssid + "\",";
    json += "\"hidden\":" + String(networks[i].hidden ? "true" : "false");
    json += "}";
  }
  json += "]";
  
  server.send(200, "application/json", json);
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println("\nWiFi Analyzer Starting...");
  
  // Set WiFi to station mode to scan
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(ap_ssid, ap_password);
  
  Serial.print("AP IP: http://");
  Serial.println(WiFi.softAPIP());
  Serial.println("Connect to: ESP32-Analyzer (password: analyzer)");
  Serial.println("Then open: http://192.168.4.1");
  
  server.on("/", handleRoot);
  server.on("/scan", handleScan);
  server.begin();
  
  Serial.println("Ready!");
}

void loop() {
  server.handleClient();
}
