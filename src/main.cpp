#include <Arduino.h>
#include <ArduinoJson.h>
#include <DNSServer.h>
#include <ESPmDNS.h>
#include <Preferences.h>
#include <WebServer.h>
#include <WebSocketsServer.h>
#include <WiFi.h>
#include <time.h>

#include "blake2b.h"

namespace {
constexpr size_t MAX_HEADER = 256;
constexpr uint32_t WIFI_CONNECT_TIMEOUT_MS = 20000;
constexpr uint8_t DNS_PORT = 53;
constexpr uint8_t CONFIG_BUTTON_PIN = 0; // BOOT button on most ESP32 development boards
constexpr uint8_t STATUS_LED_PIN = 2; // Built-in LED on the common ESP32 DevKit board
constexpr uint16_t DEFAULT_POOL_PORT = 3333;
constexpr uint8_t POOL_LOG_CAPACITY = 24;
constexpr char BRAND_NAME[] = "retardminer";
constexpr char MAIN_WEBSITE[] = "https://retardminer.com/";
constexpr char SETTINGS_NAMESPACE[] = "retardminer";
constexpr char LEGACY_SETTINGS_NAMESPACE[] = "espbip110";
constexpr char SETUP_SSID[] = "retardminer-setup";
const char POOP_ICON_SVG[] PROGMEM = R"SVG(<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" role="img" aria-label="retardminer poop logo"><path fill="#75411f" d="M127 18c17 19 19 34 10 44 27 1 46 13 51 31 2 7 1 13-3 19 24 5 40 21 40 42 0 9-3 17-8 24 15 8 21 24 15 39-7 17-24 25-49 25H69c-25 0-42-9-47-26-5-17 2-32 18-40-8-10-10-23-6-35 6-20 22-32 43-34-6-12-4-25 4-35 9-11 23-16 40-16 8 0 11-5 10-12 0-7-3-14-10-22-2-3 3-8 6-4Z"/><path fill="none" stroke="#c98b5a" stroke-linecap="round" stroke-width="11" d="M72 111c21-4 43-2 62 4M92 71c13-5 27-5 40-2" opacity=".65"/><ellipse cx="89" cy="159" rx="21" ry="24" fill="#fff"/><ellipse cx="164" cy="159" rx="21" ry="24" fill="#fff"/><circle cx="96" cy="164" r="9" fill="#26180f"/><circle cx="157" cy="164" r="9" fill="#26180f"/><path fill="#26180f" d="M84 194c3-4 8-5 12-2 18 14 42 14 61 0 4-3 9-2 12 2 3 4 2 9-2 12-24 19-57 19-81 0-4-3-5-8-2-12Z"/></svg>)SVG";
enum PowMode : uint8_t { POW_SIA = 0, POW_PYBLOCK_BLAKE2B = 1 };
WiFiClient pool;
WebServer web(80);
WebSocketsServer websocket(81);
DNSServer dns;
Preferences preferences;
uint8_t header[MAX_HEADER], target[32];
size_t header_len = 0;
uint64_t nonce = 0, hashes = 0, last_report_hashes = 0;
uint64_t templates_received = 0;
uint64_t shares_submitted = 0, shares_accepted = 0, shares_rejected = 0;
struct WorkerJob { uint8_t header[MAX_HEADER], target[32]; size_t header_len; PowMode mode; uint16_t nonce_offset; uint8_t nonce_size; uint32_t generation; };
struct FoundShare { uint64_t nonce; uint8_t hash[32]; uint32_t generation; };
WorkerJob worker_job{};
QueueHandle_t found_shares = nullptr;
portMUX_TYPE mining_mux = portMUX_INITIALIZER_UNLOCKED;
String job_id;
String stratum_extranonce1, stratum_extranonce2, stratum_ntime, stratum_nbits, stratum_version;
String pool_difficulty, pool_server_message, pool_last_message;
String last_template_error;
uint8_t stratum_extranonce2_size = 0;
uint32_t request_id = 1, last_connect_attempt = 0, last_report = 0;
uint32_t last_dashboard = 0;
uint32_t last_template_ms = 0, pool_connected_since = 0, last_share_request_id = 0;
uint32_t pool_connection_attempts = 0, pool_sessions = 0;
uint32_t subscribe_request_id = 0, authorize_request_id = 0;
constexpr uint32_t RECONNECT_BACKOFF_MIN_MS = 5000, RECONNECT_BACKOFF_MAX_MS = 300000;
uint32_t reconnect_backoff_ms = RECONNECT_BACKOFF_MIN_MS;
bool session_got_reply = false;
double current_hashrate = 0;
volatile bool portal_active = false;
bool web_started = false;
bool websocket_started = false;
bool mdns_started = false;
bool pool_was_connected = false;
bool restart_requested = false;
bool dashboard_dirty = false;
String pool_logs[POOL_LOG_CAPACITY];
uint8_t pool_log_start = 0, pool_log_count = 0;

struct Settings {
  String wifi_ssid, wifi_password, pool_host, pool_username, pool_password, device_name;
  uint16_t pool_port;
  PowMode pow_mode;
};
Settings settings;
void request_new_template();
uint64_t hash_count() { portENTER_CRITICAL(&mining_mux); uint64_t value = hashes; portEXIT_CRITICAL(&mining_mux); return value; }
void add_hashes(uint32_t count) { portENTER_CRITICAL(&mining_mux); hashes += count; portEXIT_CRITICAL(&mining_mux); }
String log_timestamp() { time_t now = time(nullptr); if (now < 1700000000) return "time unavailable"; struct tm local; localtime_r(&now, &local); char text[24]; strftime(text, sizeof(text), "%Y-%m-%d %H:%M:%S", &local); return String(text); }
void add_pool_log(const String &message) {
  String entry = log_timestamp() + "  " + message;
  if (entry.length() > 160) entry = entry.substring(0, 157) + "...";
  const uint8_t slot = (pool_log_start + pool_log_count) % POOL_LOG_CAPACITY;
  pool_logs[slot] = entry;
  if (pool_log_count < POOL_LOG_CAPACITY) ++pool_log_count;
  else pool_log_start = (pool_log_start + 1) % POOL_LOG_CAPACITY;
  dashboard_dirty = true;
}

String saved_or_empty(const char *key) {
  return preferences.isKey(key) ? preferences.getString(key) : String();
}
void load_settings() {
  preferences.begin(SETTINGS_NAMESPACE, true);
  const bool has_current_settings = preferences.isKey("ssid") || preferences.isKey("pool_host") || preferences.isKey("device_name");
  if (!has_current_settings) {
    // Read existing installations without stranding their saved configuration.
    preferences.end();
    preferences.begin(LEGACY_SETTINGS_NAMESPACE, true);
  }
  settings.wifi_ssid = saved_or_empty("ssid");
  settings.wifi_password = saved_or_empty("wifi_pw");
  settings.pool_host = saved_or_empty("pool_host");
  settings.pool_username = saved_or_empty("pool_user");
  settings.pool_password = saved_or_empty("pool_pw");
  settings.device_name = preferences.isKey("device_name") ? saved_or_empty("device_name") : BRAND_NAME;
  if (!has_current_settings && settings.device_name == "esp-bip110") settings.device_name = BRAND_NAME;
  settings.pool_port = preferences.isKey("pool_port") ? preferences.getUShort("pool_port") : DEFAULT_POOL_PORT;
  settings.pow_mode = preferences.isKey("pow_mode") ? PowMode(preferences.getUChar("pow_mode")) : POW_SIA;
  preferences.end();
}
bool valid_settings(const Settings &s) {
  return s.wifi_ssid.length() && s.pool_host.length() && s.pool_username.length() && s.pool_port &&
         s.device_name.length() && s.device_name.length() <= 32 && s.pow_mode <= POW_PYBLOCK_BLAKE2B;
}
bool valid_device_name(const String &name) {
  if (!name.length() || name.length() > 32 || name[0] == '-' || name[name.length() - 1] == '-') return false;
  for (size_t i = 0; i < name.length(); ++i) if (!isalnum(name[i]) && name[i] != '-') return false;
  return true;
}
String html_escape(const String &value) {
  String out; out.reserve(value.length());
  for (size_t i = 0; i < value.length(); ++i) { char c = value[i]; if (c == '&') out += "&amp;"; else if (c == '<') out += "&lt;"; else if (c == '>') out += "&gt;"; else if (c == '\"') out += "&quot;"; else out += c; }
  return out;
}
String input(const char *name, const char *label, const String &value, const char *type = "text") {
  return String("<label>") + label + "<input type='" + type + "' name='" + name + "' value='" + html_escape(value) + "'></label>";
}
String pow_mode_input() {
  String out = "<label>Proof of work<select name='pow_mode' id='pow_mode'>";
  out += String("<option value=0") + (settings.pow_mode == POW_SIA ? " selected" : "") + ">BLAKE2b-Sia (F2Pool)</option>";
  out += String("<option value=1") + (settings.pow_mode == POW_PYBLOCK_BLAKE2B ? " selected" : "") + ">Bitcoin BLAKE2b Stratum V1 (PyBLOCK)</option></select></label>";
  return out;
}
String brand_document_head() {
  return String("<meta charset=utf-8><meta name=application-name content='") + BRAND_NAME +
         "'><title>" + BRAND_NAME +
         "</title><link rel=icon type='image/svg+xml' href='/favicon.svg'><link rel=canonical href='" + MAIN_WEBSITE + "'>";
}
String brand_header() {
  return String("<header class=brand><img class=brand-logo src=/favicon.svg alt='Poop logo'><div><h1>") + BRAND_NAME +
         "</h1><a class=brand-site href='" + MAIN_WEBSITE + "' target=_blank rel='noopener'>Main website &middot; retardminer.com</a></div></header>";
}
String brand_footer() {
  return String("<footer><a href='") + MAIN_WEBSITE + "' target=_blank rel='noopener'>retardminer.com</a></footer>";
}
void send_config_page_legacy(const String &notice = "") {
  String page = "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'><style>:root{color-scheme:dark;--bg:#080a0e;--panel:#11151d;--panel2:#171d27;--line:#2a3342;--text:#eff4fa;--muted:#94a3b8;--accent:#41e6a1;--accent2:#39a9ff}*{box-sizing:border-box}body{font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:48rem;margin:0 auto;padding:1rem;background:radial-gradient(circle at 10% 0,#17243a 0,var(--bg) 32rem);color:var(--text)}h1{font-size:1.6rem;letter-spacing:.04em;margin:1.2rem 0 .2rem}h2{font-size:.85rem;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);margin:1.5rem 0 .7rem}.eyebrow{color:var(--accent);font-size:.72rem;font-weight:700;letter-spacing:.14em;text-transform:uppercase}.shell{background:rgba(17,21,29,.9);border:1px solid var(--line);border-radius:1rem;padding:1rem;box-shadow:0 1.5rem 5rem #0008}label{display:block;margin:.9rem 0;color:var(--muted);font-size:.85rem}input,select{appearance:none;box-sizing:border-box;width:100%;padding:.75rem;margin-top:.35rem;border:1px solid var(--line);border-radius:.45rem;background:#090d13;color:var(--text);font-size:1rem}input:focus,select:focus{outline:2px solid #41e6a155;border-color:var(--accent)}button{width:100%;border:0;border-radius:.5rem;padding:.85rem 1rem;margin-top:1rem;background:linear-gradient(135deg,var(--accent),#20b486);color:#03120c;font-weight:800;font-size:1rem;cursor:pointer}.notice{border:1px solid #41e6a155;background:#41e6a112;color:#b7ffdd;border-radius:.5rem;padding:.7rem}.hint{color:var(--muted);font-size:.8rem;line-height:1.45}</style><main class=shell><div class=eyebrow>ESP32 &middot; BLAKE2b miner</div><h1>Control center</h1><p class=hint>Live mining telemetry and persistent board configuration.</p>";
  page.replace("<meta name=viewport", brand_document_head() + "<meta name=viewport");
  page.replace("</style>", ".brand{display:flex;align-items:center;gap:.7rem}.brand-logo{width:3rem;height:3rem}.brand h1{margin:0;text-transform:lowercase}.brand-site,footer a{color:var(--accent)}footer{margin-top:1.5rem;text-align:center;color:var(--muted)}</style>");
  page.replace("<div class=eyebrow>ESP32 &middot; BLAKE2b miner</div><h1>Control center</h1>", brand_header());
  if (notice.length()) page += "<p class=notice>" + notice + "</p>";
  if (WiFi.status() == WL_CONNECTED) page += "<p class=notice>Connected: " + WiFi.localIP().toString() + " &middot; Setup address: http://" + html_escape(settings.device_name) + ".local</p>";
  page += R"HTML(<section id="dashboard"><h2>Live board status <span class="live">&#9679; LIVE</span></h2><div class="stats"><div><small>Network / pool</small><strong id="connection">connecting</strong></div><div><small>Current job</small><strong id="job">—</strong></div><div><small>Total hashes</small><strong id="hashes">0</strong></div><div><small>Rate</small><strong id="rate">0 H/s</strong></div></div><div class="visuals"><canvas id="gauge" width="180" height="100"></canvas><canvas id="chart" width="420" height="100"></canvas></div></section><style>#dashboard{background:linear-gradient(145deg,#171d27,#0b0f16);border:1px solid var(--line);border-radius:.75rem;padding:1rem;margin:1rem 0}.live{float:right;color:var(--accent);font-size:.68rem}.stats{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.65rem}.stats div{background:#090d13;border:1px solid #242d3a;padding:.7rem;border-radius:.45rem}.stats small,.stats strong{display:block}.stats small{color:var(--muted);font-size:.72rem}.stats strong{margin-top:.25rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.visuals{display:flex;gap:.65rem;flex-wrap:wrap;margin-top:.65rem}.visuals canvas{max-width:100%;background:#090d13;border:1px solid #242d3a;border-radius:.45rem}</style><script>(()=>{let rates=[];const $=id=>document.getElementById(id),draw=()=>{const g=$("gauge").getContext("2d"),c=$("chart").getContext("2d"),r=rates.at(-1)||0,max=Math.max(1,...rates);g.clearRect(0,0,180,100);g.lineWidth=12;g.strokeStyle="#252f3d";g.beginPath();g.arc(90,90,65,Math.PI,2*Math.PI);g.stroke();g.strokeStyle="#41e6a1";g.shadowColor="#41e6a1";g.shadowBlur=10;g.beginPath();g.arc(90,90,65,Math.PI,Math.PI+Math.min(1,r/max)*Math.PI);g.stroke();g.shadowBlur=0;g.fillStyle="#eff4fa";g.textAlign="center";g.fillText(r.toFixed(1)+" H/s",90,82);c.clearRect(0,0,420,100);c.strokeStyle="#39a9ff";c.lineWidth=2;c.beginPath();rates.forEach((v,i)=>{const x=i*420/Math.max(1,rates.length-1),y=92-v/max*70;i?c.lineTo(x,y):c.moveTo(x,y)});c.stroke();c.fillStyle="#94a3b8";c.textAlign="left";c.fillText("HASH RATE · LAST 60 SECONDS",10,16)};const connect=()=>{const ws=new WebSocket(`ws://${location.hostname}:81/`);ws.onmessage=e=>{const s=JSON.parse(e.data);$("connection").textContent=s.network+" / "+s.pool;$("job").textContent=s.job||"—";$("hashes").textContent=Number(s.hashes).toLocaleString();$("rate").textContent=s.rate.toFixed(1)+" H/s";rates.push(s.rate);if(rates.length>60)rates.shift();draw()};ws.onclose=()=>setTimeout(connect,2000)};connect()})()</script>)HTML";
  page += R"HTML(<style>#dashboard{display:none}.tabs{display:flex;gap:.5rem;margin:1rem 0}.tabs button{margin:0;background:#202938;color:#94a3b8}.tabs button.active{background:var(--accent);color:#03120c}.tab{display:none}.tab.active{display:block}.metric-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:.55rem}.metric{background:#090d13;border:1px solid #242d3a;border-radius:.45rem;padding:.65rem}.metric small,.metric strong{display:block}.metric small{color:var(--muted);font-size:.68rem}.metric strong{font-size:.95rem;margin-top:.25rem}.gauges{display:flex;flex-wrap:wrap;gap:.55rem;margin-top:.6rem}.gauges canvas{background:#090d13;border:1px solid #242d3a;border-radius:.45rem;max-width:100%}</style><div class="tabs"><button id="dashTab" class="active" type="button">Dashboard</button><button id="configTab" type="button">Configuration</button></div><section id="telemetry" class="tab active"><h2>Live telemetry <span class="live">&#9679; LIVE</span></h2><div class="metric-grid"><div class=metric><small>Network / pool</small><strong id=tconnection>connecting</strong></div><div class=metric><small>Job</small><strong id=tjob>—</strong></div><div class=metric><small>Total hashes</small><strong id=thashes>0</strong></div><div class=metric><small>Uptime</small><strong id=tuptime>0s</strong></div><div class=metric><small>Templates received</small><strong id=ttemplates>0</strong></div><div class=metric><small>Free memory</small><strong id=tmem>0 KB</strong></div><div class=metric><small>ESP32 temperature</small><strong id=ttemp>0 °C</strong></div><div class=metric><small>Supply voltage</small><strong id=tvolt>0 V</strong></div><div class=metric><small>Hash rate</small><strong id=trate>0 H/s</strong></div></div><div class=gauges><canvas id=hashGauge width=200 height=110></canvas><canvas id=tempGauge width=200 height=110></canvas><canvas id=voltGauge width=200 height=110></canvas><canvas id=rateChart width=420 height=110></canvas></div></section><script>(()=>{let rates=[];const $=x=>document.getElementById(x),tab=x=>{telemetry.classList.toggle('active',x);config.classList.toggle('active',!x);dashTab.classList.toggle('active',x);configTab.classList.toggle('active',!x)};dashTab.onclick=()=>tab(1);configTab.onclick=()=>tab(0);const gauge=(id,v,max,label,color)=>{let c=$(id),x=c.getContext('2d'),p=Math.max(0,Math.min(1,v/max));x.clearRect(0,0,200,110);x.lineWidth=12;x.strokeStyle='#252f3d';x.beginPath();x.arc(100,94,70,Math.PI,2*Math.PI);x.stroke();x.strokeStyle=color;x.beginPath();x.arc(100,94,70,Math.PI,Math.PI+p*Math.PI);x.stroke();x.fillStyle='#eff4fa';x.textAlign='center';x.fillText(label,100,78);x.fillStyle='#94a3b8';x.fillText('0 — '+max,100,101)};const draw=s=>{gauge('hashGauge',s.rate,20000,s.rate.toFixed(0)+' H/s','#41e6a1');gauge('tempGauge',s.temperature,100,s.temperature.toFixed(1)+' °C','#ff9f43');gauge('voltGauge',s.voltage,5,s.voltage.toFixed(2)+' V','#39a9ff');let c=$('rateChart'),x=c.getContext('2d'),m=20000;x.clearRect(0,0,420,110);x.strokeStyle='#39a9ff';x.beginPath();rates.forEach((v,i)=>{let a=i*420/Math.max(1,rates.length-1),b=96-v/m*78;i?x.lineTo(a,b):x.moveTo(a,b)});x.stroke();x.fillStyle='#94a3b8';x.fillText('HASH RATE · FIXED SCALE 0–20,000 H/s',10,16)};const ws=new WebSocket(`ws://${location.hostname}:81/`);ws.onmessage=e=>{let s=JSON.parse(e.data);tconnection.textContent=s.network+' / '+s.pool;tjob.textContent=s.job||'—';thashes.textContent=Number(s.hashes).toLocaleString();tuptime.textContent=Math.floor(s.uptime/3600)+'h '+Math.floor(s.uptime%3600/60)+'m';ttemplates.textContent=s.templates;tmem.textContent=Math.round(s.free_mem/1024)+' KB';ttemp.textContent=s.temperature.toFixed(1)+' °C';tvolt.textContent=s.voltage.toFixed(2)+' V';trate.textContent=s.rate.toFixed(1)+' H/s';rates.push(s.rate);if(rates.length>60)rates.shift();draw(s)}})()</script>)HTML";
  page += "<form id=config class=tab method=post action=/save><h2>Device</h2>" + input("device_name", "Device name (.local address)", settings.device_name) + "<h2>Wi-Fi</h2>" + input("ssid", "Network name (SSID)", settings.wifi_ssid) + input("wifi_pw", "Wi-Fi password (leave blank to keep saved password)", "", "password") + "<h2>Pool</h2>" + input("pool_host", "Host", settings.pool_host) + input("pool_port", "Port", String(settings.pool_port), "number") + input("pool_user", "Username / payout address", settings.pool_username) + input("pool_pw", "Pool password", settings.pool_password, "password") + pow_mode_input() + "<button type=submit>Save and restart</button></form>";
  page += R"HTML(<style>#virtualLed{display:inline-block;width:.7rem;height:.7rem;margin-left:.45rem;border-radius:50%;background:#123a66;border:1px solid #287bc7;box-shadow:0 0 .2rem #123a66;vertical-align:middle}#virtualLed.on{background:#38aaff;box-shadow:0 0 .9rem #168cff}</style><script>(()=>{document.querySelector('h1').insertAdjacentHTML('beforeend','<span id="virtualLed" title="Virtual status LED"></span>');let led,clientAt=0;const ws=new WebSocket(`ws://${location.hostname}:81/`);ws.onmessage=e=>{const s=JSON.parse(e.data);led=s;clientAt=Date.now()};setInterval(()=>{if(!led)return;const p=(led.uptime_ms+Date.now()-clientAt)%1000;const on=led.led_mode===0?p<500:led.led_mode===1?p<80:(p%250)<125;virtualLed.classList.toggle('on',on)},40)})()</script></main>)HTML";
  page += R"HTML(<script>(()=>{const t=x=>document.getElementById(x),old=document.querySelector('.gauges');if(old)old.style.display='none';const box=document.createElement('div');box.className='gauges';box.innerHTML='<canvas id="cleanHash" width="200" height="110"></canvas><canvas id="cleanTemp" width="200" height="110"></canvas><canvas id="cleanVolt" width="200" height="110"></canvas><canvas id="cleanChart" width="420" height="110"></canvas>';t('telemetry').append(box);let s,r=[];const gauge=(id,v,max,label,col)=>{const c=t(id),x=c.getContext('2d'),p=Math.max(0,Math.min(1,v/max));x.clearRect(0,0,200,110);x.lineWidth=12;x.strokeStyle='#252f3d';x.beginPath();x.arc(100,94,70,Math.PI,2*Math.PI);x.stroke();x.strokeStyle=col;x.beginPath();x.arc(100,94,70,Math.PI,Math.PI+p*Math.PI);x.stroke();x.fillStyle='#eff4fa';x.textAlign='center';x.fillText(label,100,78);x.fillStyle='#94a3b8';x.fillText('0 - '+max,100,101)};const draw=()=>{if(!s)return;gauge('cleanHash',s.rate,20000,s.rate.toFixed(0)+' H/s','#41e6a1');gauge('cleanTemp',s.temperature,100,s.temperature.toFixed(1)+' deg C','#ff9f43');gauge('cleanVolt',Math.max(0,s.voltage),5,s.voltage<0?'not configured':s.voltage.toFixed(2)+' V','#39a9ff');const c=t('cleanChart'),x=c.getContext('2d');x.clearRect(0,0,420,110);x.strokeStyle='#39a9ff';x.beginPath();r.forEach((v,i)=>{const a=i*420/Math.max(1,r.length-1),b=96-v/20000*78;i?x.lineTo(a,b):x.moveTo(a,b)});x.stroke();x.fillStyle='#94a3b8';x.fillText('HASH RATE - FIXED SCALE 0 - 20000 H/s',10,16);t('ttemp').textContent=s.temperature.toFixed(1)+' deg C';t('tvolt').textContent=s.voltage<0?'not configured':s.voltage.toFixed(2)+' V'};const ws=new WebSocket(`ws://${location.hostname}:81/`);ws.onmessage=e=>{s=JSON.parse(e.data);r.push(s.rate);if(r.length>60)r.shift();draw()};setInterval(draw,250)})()</script>)HTML";
  page += R"HTML(<script>(()=>{const t=x=>document.getElementById(x),host=t('cleanChart').parentElement,add=(id,w=420)=>{const c=document.createElement('canvas');c.id=id;c.width=w;c.height=110;host.append(c)};add('memGauge',200);add('tempChart');add('voltChart');add('memChart');let ts=[],vs=[],ms=[];const gauge=(id,v,max,label,col)=>{const c=t(id),x=c.getContext('2d'),p=Math.max(0,Math.min(1,v/max));x.clearRect(0,0,200,110);x.lineWidth=12;x.strokeStyle='#252f3d';x.beginPath();x.arc(100,94,70,Math.PI,2*Math.PI);x.stroke();x.strokeStyle=col;x.beginPath();x.arc(100,94,70,Math.PI,Math.PI+p*Math.PI);x.stroke();x.fillStyle='#eff4fa';x.textAlign='center';x.fillText(label,100,78);x.fillStyle='#94a3b8';x.fillText('0 - '+max+' KB',100,101)};const chart=(id,a,max,label,col)=>{const c=t(id),x=c.getContext('2d');x.clearRect(0,0,420,110);x.strokeStyle=col;x.lineWidth=2;x.beginPath();a.forEach((v,i)=>{const px=i*420/Math.max(1,a.length-1),py=96-v/max*78;i?x.lineTo(px,py):x.moveTo(px,py)});x.stroke();x.fillStyle='#94a3b8';x.fillText(label,10,16)};const ws=new WebSocket(`ws://${location.hostname}:81/`);ws.onmessage=e=>{const s=JSON.parse(e.data);ts.push(s.temperature);vs.push(Math.max(0,s.voltage));ms.push(s.free_mem/1024);[ts,vs,ms].forEach(a=>{if(a.length>60)a.shift()});gauge('memGauge',ms.at(-1),320,Math.round(ms.at(-1))+' KB','#b783ff');chart('tempChart',ts,100,'TEMPERATURE - FIXED SCALE 0 - 100 deg C','#ff9f43');chart('voltChart',vs,5,'SUPPLY VOLTAGE - FIXED SCALE 0 - 5 V','#39a9ff');chart('memChart',ms,320,'FREE MEMORY - FIXED SCALE 0 - 320 KB','#b783ff')}})()</script>)HTML";
  page += R"HTML(<style>.telemetry-lines{display:grid;gap:.65rem;margin-top:.65rem}.telemetry-line{display:grid;grid-template-columns:200px minmax(0,420px);gap:.65rem;align-items:center}.telemetry-line canvas{width:100%;height:auto}@media(max-width:42rem){.telemetry-line{grid-template-columns:1fr}.telemetry-line canvas{max-width:420px}}</style><script>(()=>{const host=document.getElementById('cleanChart').parentElement,lines=document.createElement('div');lines.className='telemetry-lines';[['cleanHash','cleanChart'],['cleanTemp','tempChart'],['cleanVolt','voltChart'],['memGauge','memChart']].forEach(pair=>{const line=document.createElement('div');line.className='telemetry-line';pair.forEach(id=>line.append(document.getElementById(id)));lines.append(line)});host.append(lines)})()</script>)HTML";
  page += R"HTML(<script>(()=>{const button=document.createElement('button'),note=document.createElement('p');button.id='templateButton';note.id='templateNote';let ws,pending=false,awaiting=false,statusReady=false,lastTemplates=0,requestedTemplates=0;button.type='button';button.textContent='Request new template';note.className='hint';note.textContent='Connecting to board telemetry...';document.getElementById('telemetry').append(button,note);const send=()=>{if(!pending||!statusReady||!ws||ws.readyState!==WebSocket.OPEN)return;pending=false;awaiting=true;requestedTemplates=lastTemplates;ws.send(JSON.stringify({method:'dashboard.request_template'}));note.textContent='New template requested; waiting for the pool.'};const connect=()=>{ws=new WebSocket(`ws://${location.hostname}:81/`);ws.onopen=send;ws.onmessage=e=>{try{const s=JSON.parse(e.data);if(typeof s.templates!=='number')return;const firstStatus=!statusReady;if(awaiting&&s.templates>requestedTemplates){awaiting=false;note.textContent='New template received.'}lastTemplates=s.templates;statusReady=true;if(firstStatus&&!pending&&!awaiting)note.textContent='Ask the pool for a new mining template.';send()}catch(_){}};ws.onclose=()=>{statusReady=false;setTimeout(connect,1000)};ws.onerror=()=>ws.close()};button.onclick=()=>{pending=true;note.textContent=statusReady?'Request queued...':'Waiting for board telemetry...';send()};connect()})()</script>)HTML";
  page += R"HTML(<script>(()=>{document.getElementById('tvolt')?.closest('.metric')?.remove();document.getElementById('cleanVolt')?.closest('.telemetry-line')?.remove()})()</script>)HTML";
  page += R"HTML(<script>(()=>{const grid=document.querySelector('.metric-grid'),fields=[['healthRssi','Wi-Fi signal'],['healthTemplate','Last template'],['healthPool','Pool session'],['healthShares','Shares A / R / sent'],['healthHeap','Heap min / max block'],['healthPsram','PSRAM free / total'],['healthChip','ESP32'],['healthFlash','Flash / sketch']],out={};fields.forEach(([id,label])=>{const box=document.createElement('div');box.className='metric';box.innerHTML='<small>'+label+'</small><strong id="'+id+'">waiting</strong>';grid.append(box);out[id]=box.querySelector('strong')});const kb=n=>Math.round(n/1024)+' KB',dur=s=>s<60?s+'s':Math.floor(s/60)+'m '+s%60+'s';const connect=()=>{const ws=new WebSocket(`ws://${location.hostname}:81/`);ws.onmessage=e=>{const s=JSON.parse(e.data);out.healthRssi.textContent=s.wifi_rssi?s.wifi_rssi+' dBm / ch '+s.wifi_channel:'offline';out.healthTemplate.textContent=s.template_age<0?'none':dur(s.template_age)+' ago';out.healthPool.textContent=s.pool_uptime?dur(s.pool_uptime)+' / '+s.pool_sessions+' sessions':'disconnected';out.healthShares.textContent=s.shares_accepted+' / '+s.shares_rejected+' / '+s.shares_submitted;out.healthHeap.textContent=kb(s.min_free_mem)+' / '+kb(s.max_alloc_mem);out.healthPsram.textContent=s.psram_total?kb(s.psram_free)+' / '+kb(s.psram_total):'not fitted';out.healthChip.textContent=s.chip+' r'+s.chip_revision+' / '+s.cpu_mhz+' MHz';out.healthFlash.textContent=kb(s.flash_bytes)+' / '+kb(s.sketch_bytes)+' used'};ws.onclose=()=>setTimeout(connect,1000);ws.onerror=()=>ws.close()};connect()})()</script>)HTML";
  page += R"HTML(<script>(()=>{document.querySelectorAll('.gauges').forEach(x=>x.style.display='none');document.getElementById('trate')?.closest('.metric')?.remove();const rateBox=document.createElement('div');rateBox.className='metric';rateBox.innerHTML='<small>Hash rate</small><strong id="fixedRate">waiting</strong>';document.querySelector('.metric-grid').append(rateBox);const panel=document.createElement('section');panel.innerHTML='<h2>Performance history</h2><div class="telemetry-lines"><div class="telemetry-line"><canvas id="fixedHashChart" width="200" height="110"></canvas><canvas id="fixedMemChart" width="420" height="110"></canvas></div></div>';document.getElementById('telemetry').append(panel);let rates=[],mem=[],lastHashes,lastAt;const chart=(id,values,max,label,color)=>{const c=document.getElementById(id),x=c.getContext('2d');x.clearRect(0,0,c.width,c.height);x.strokeStyle=color;x.lineWidth=2;x.beginPath();values.forEach((v,i)=>{const px=i*c.width/Math.max(1,values.length-1),py=96-(v/max)*78;i?x.lineTo(px,py):x.moveTo(px,py)});x.stroke();x.fillStyle='#94a3b8';x.fillText(label,10,16)};const connect=()=>{const ws=new WebSocket(`ws://${location.hostname}:81/`);ws.onmessage=e=>{const s=JSON.parse(e.data),now=Date.now();let rate=Number(s.rate)||0;if(lastHashes!==undefined&&now>lastAt){const measured=(Number(s.hashes)-lastHashes)*1000/(now-lastAt);if(measured>=0)rate=measured}lastHashes=Number(s.hashes);lastAt=now;fixedRate.textContent=rate.toFixed(1)+' H/s';rates.push(rate);mem.push(Number(s.free_mem)/1024);if(rates.length>60){rates.shift();mem.shift()}chart('fixedHashChart',rates,20000,'HASH RATE - 0 to 20000 H/s','#41e6a1');chart('fixedMemChart',mem,Math.max(320,...mem),'FREE MEMORY - KB','#b783ff')};ws.onclose=()=>setTimeout(connect,1000);ws.onerror=()=>ws.close()};connect()})()</script>)HTML";
  page += R"HTML(<style>.vital-lines{display:grid;gap:.75rem}.vital-line{display:grid;grid-template-columns:200px minmax(0,420px);gap:.65rem;align-items:center}.vital-line canvas{width:100%;height:auto;background:#090d13;border:1px solid #242d3a;border-radius:.45rem}@media(max-width:42rem){.vital-line{grid-template-columns:1fr}}</style><script>(()=>{document.getElementById('fixedRate')?.closest('.metric')?.remove();document.getElementById('tmem')?.closest('.metric')?.remove();document.getElementById('fixedHashChart')?.closest('section')?.remove();const grid=document.querySelector('.metric-grid'),summary={};[['summaryRate','Hash rate'],['summaryMem','Free memory']].forEach(([id,label])=>{const box=document.createElement('div');box.className='metric';box.innerHTML='<small>'+label+'</small><strong>waiting</strong>';grid.append(box);summary[id]=box.querySelector('strong')});const panel=document.createElement('section');panel.id='vitalPanel';panel.innerHTML='<h2>Live performance</h2><div class="vital-lines"><div class="vital-line"><canvas id="hashGaugeNew" width="200" height="110"></canvas><canvas id="hashChartNew" width="420" height="110"></div><div class="vital-line"><canvas id="memGaugeNew" width="200" height="110"></canvas><canvas id="memChartNew" width="420" height="110"></div><div class="vital-line"><canvas id="tempGaugeNew" width="200" height="110"></canvas><canvas id="tempChartNew" width="420" height="110"></div></div>';document.getElementById('telemetry').append(panel);const el=id=>document.getElementById(id),gauge=(id,value,max,label,color,unit)=>{const c=el(id),x=c.getContext('2d'),p=Math.max(0,Math.min(1,value/max));x.clearRect(0,0,200,110);x.lineWidth=12;x.strokeStyle='#252f3d';x.beginPath();x.arc(100,94,70,Math.PI,2*Math.PI);x.stroke();x.strokeStyle=color;x.beginPath();x.arc(100,94,70,Math.PI,Math.PI+p*Math.PI);x.stroke();x.fillStyle='#eff4fa';x.textAlign='center';x.fillText(label,100,78);x.fillStyle='#94a3b8';x.fillText('0 - '+max+' '+unit,100,101)},chart=(id,values,max,label,color)=>{const c=el(id),x=c.getContext('2d');x.clearRect(0,0,420,110);x.strokeStyle=color;x.lineWidth=2;x.beginPath();values.forEach((v,i)=>{const px=i*420/Math.max(1,values.length-1),py=96-v/max*78;i?x.lineTo(px,py):x.moveTo(px,py)});x.stroke();x.fillStyle='#94a3b8';x.fillText(label,10,16)};let rates=[],mem=[],temps=[],lastHashes,lastAt;const connect=()=>{const ws=new WebSocket(`ws://${location.hostname}:81/`);ws.onmessage=e=>{const s=JSON.parse(e.data),now=Date.now();let rate=Number(s.rate)||0;if(lastHashes!==undefined&&now>lastAt){const measured=(Number(s.hashes)-lastHashes)*1000/(now-lastAt);if(measured>=0)rate=measured}lastHashes=Number(s.hashes);lastAt=now;const free=Number(s.free_mem)/1024,temp=Number(s.temperature);summary.summaryRate.textContent=rate.toFixed(1)+' H/s';summary.summaryMem.textContent=Math.round(free)+' KB';rates.push(rate);mem.push(free);temps.push(temp);[rates,mem,temps].forEach(a=>{if(a.length>60)a.shift()});gauge('hashGaugeNew',rate,20000,rate.toFixed(1)+' H/s','#41e6a1','H/s');gauge('memGaugeNew',free,320,Math.round(free)+' KB','#b783ff','KB');gauge('tempGaugeNew',temp,100,temp.toFixed(1)+' deg C','#ff9f43','deg C');chart('hashChartNew',rates,20000,'HASH RATE - 0 to 20000 H/s','#41e6a1');chart('memChartNew',mem,320,'FREE MEMORY - 0 to 320 KB','#b783ff');chart('tempChartNew',temps,100,'TEMPERATURE - 0 to 100 deg C','#ff9f43')};ws.onclose=()=>setTimeout(connect,1000);ws.onerror=()=>ws.close()};connect()})()</script>)HTML";
  page += R"HTML(<style>#boardActions{margin-top:1.5rem;display:grid;gap:.6rem}#boardActions button{margin:0}#resetBoard{background:linear-gradient(135deg,#ef4444,#991b1b);color:#fff}</style><script>(()=>{const actions=document.createElement('div'),request=document.getElementById('templateButton'),note=document.getElementById('templateNote'),reset=document.createElement('button');actions.id='boardActions';reset.id='resetBoard';reset.type='button';reset.textContent='Reset board';actions.append(request,note,reset);document.getElementById('telemetry').append(actions);let ws;const connect=()=>{ws=new WebSocket(`ws://${location.hostname}:81/`);ws.onclose=()=>setTimeout(connect,1000);ws.onerror=()=>ws.close()};reset.onclick=()=>{if(!confirm('Restart the ESP32 board now?'))return;if(ws&&ws.readyState===WebSocket.OPEN){reset.textContent='Restarting...';ws.send(JSON.stringify({method:'dashboard.reset'}))}else reset.textContent='Board connection not ready'};connect()})()</script>)HTML";
  page += R"HTML(<style>.share-line{display:grid;grid-template-columns:200px minmax(0,420px);gap:.65rem;align-items:center}.share-line canvas{width:100%;height:auto;background:#090d13;border:1px solid #242d3a;border-radius:.45rem}@media(max-width:42rem){.share-line{grid-template-columns:1fr}}</style><script>(()=>{const grid=document.querySelector('.metric-grid'),paint=(name,color)=>{const box=[...grid.querySelectorAll('.metric')].find(x=>x.querySelector('small')?.textContent===name);if(box){box.style.borderColor=color;box.querySelector('strong').style.color=color}};paint('Hash rate','#41e6a1');paint('Free memory','#b783ff');paint('ESP32 temperature','#ff9f43');const shareBox=document.createElement('div');shareBox.className='metric';shareBox.innerHTML='<small>Shares sent to pool</small><strong id="shareTotal">waiting</strong>';shareBox.style.borderColor='#f59e0b';shareBox.querySelector('strong').style.color='#f59e0b';grid.append(shareBox);const line=document.createElement('div');line.className='share-line';line.innerHTML='<canvas id="shareGauge" width="200" height="110"></canvas><canvas id="shareChart" width="420" height="110"></canvas>';document.querySelector('#vitalPanel .vital-lines').append(line);const gauge=(value,max)=>{const c=document.getElementById('shareGauge'),x=c.getContext('2d'),p=Math.max(0,Math.min(1,value/max));x.clearRect(0,0,200,110);x.lineWidth=12;x.strokeStyle='#252f3d';x.beginPath();x.arc(100,94,70,Math.PI,2*Math.PI);x.stroke();x.strokeStyle='#f59e0b';x.beginPath();x.arc(100,94,70,Math.PI,Math.PI+p*Math.PI);x.stroke();x.fillStyle='#f59e0b';x.textAlign='center';x.fillText(value+' sent',100,78);x.fillStyle='#94a3b8';x.fillText('0 - '+max,100,101)},chart=values=>{const c=document.getElementById('shareChart'),x=c.getContext('2d'),max=Math.max(10,...values);x.clearRect(0,0,420,110);x.strokeStyle='#f59e0b';x.lineWidth=2;x.beginPath();values.forEach((v,i)=>{const px=i*420/Math.max(1,values.length-1),py=96-v/max*78;i?x.lineTo(px,py):x.moveTo(px,py)});x.stroke();x.fillStyle='#94a3b8';x.fillText('SHARES SENT TO POOL - TOTAL',10,16);return max};let values=[];const connect=()=>{const ws=new WebSocket(`ws://${location.hostname}:81/`);ws.onmessage=e=>{const s=JSON.parse(e.data),sent=Number(s.shares_submitted)||0;document.getElementById('shareTotal').textContent=sent.toLocaleString();values.push(sent);if(values.length>60)values.shift();const max=chart(values);gauge(sent,max)};ws.onclose=()=>setTimeout(connect,1000);ws.onerror=()=>ws.close()};connect()})()</script>)HTML";
  page += R"HTML(<script>(()=>{document.getElementById('ttemp')?.closest('.metric')?.remove();const box=document.createElement('div');box.className='metric';box.style.borderColor='#ff9f43';box.innerHTML='<small>ESP32 temperature</small><strong id="liveTemperature">waiting</strong>';box.querySelector('strong').style.color='#ff9f43';document.querySelector('.metric-grid').append(box);const connect=()=>{const ws=new WebSocket(`ws://${location.hostname}:81/`);ws.onmessage=e=>{const s=JSON.parse(e.data),value=Number(s.temperature);document.getElementById('liveTemperature').textContent=Number.isFinite(value)?value.toFixed(1)+' deg C':'unavailable'};ws.onclose=()=>setTimeout(connect,1000);ws.onerror=()=>ws.close()};connect()})()</script>)HTML";
  page.replace("</main>", brand_footer() + "</main>");
  web.send(200, "text/html; charset=utf-8", page);
}
void send_config_page(const String &notice = "") {
  String page = "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'><style>:root{color-scheme:dark;--bg:#080a0e;--card:#111827;--line:#293548;--text:#edf3fb;--muted:#94a3b8}*{box-sizing:border-box}body{max-width:56rem;margin:auto;padding:1rem;background:var(--bg);color:var(--text);font:15px system-ui,sans-serif}.shell{background:#10151e;border:1px solid var(--line);border-radius:1rem;padding:1rem}h1{margin:.2rem 0}h2{font-size:.85rem;color:var(--muted);letter-spacing:.1em;text-transform:uppercase;margin:1.4rem 0 .6rem}.tabs,.actions{display:flex;gap:.6rem;flex-wrap:wrap}.tabs button,.actions button{width:auto;margin:0}.tab{display:none}.tab.active{display:block}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.6rem}.metric{background:#090d13;border:1px solid var(--line);border-radius:.5rem;padding:.65rem}.metric small,.metric strong{display:block}.metric small{color:var(--muted);font-size:.72rem}.metric strong{margin-top:.25rem}.green{border-color:#41e6a1}.green strong{color:#41e6a1}.purple{border-color:#b783ff}.purple strong{color:#b783ff}.orange{border-color:#ff9f43}.orange strong{color:#ff9f43}.yellow{border-color:#f59e0b}.yellow strong{color:#f59e0b}.line{display:grid;grid-template-columns:200px minmax(0,420px);gap:.6rem;margin:.65rem 0}.line canvas{width:100%;height:auto;background:#090d13;border:1px solid var(--line);border-radius:.5rem}label{display:block;margin:.8rem 0;color:var(--muted)}input,select{width:100%;margin-top:.25rem;padding:.65rem;background:#090d13;color:var(--text);border:1px solid var(--line);border-radius:.4rem}button{border:0;border-radius:.45rem;padding:.7rem 1rem;background:#41e6a1;color:#062013;font-weight:700}.danger{background:#b91c1c;color:white}.hint{color:var(--muted)}@media(max-width:42rem){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.line{grid-template-columns:1fr}}</style><main class=shell><h1>ESP32 BLAKE2b Miner</h1><div class=tabs><button id=dashTab>Dashboard</button><button id=configTab>Configuration</button></div><section id=dashboard class='tab active'><div class=grid><div class=metric><small>Network / pool</small><strong id=network>connecting</strong></div><div class=metric><small>Job</small><strong id=job>-</strong></div><div class=metric><small>Total hashes</small><strong id=hashes>0</strong></div><div class='metric green'><small>Hash rate</small><strong id=rate>waiting</strong></div><div class='metric purple'><small>Free memory</small><strong id=memory>waiting</strong></div><div class='metric orange'><small>ESP32 temperature</small><strong id=temp>waiting</strong></div><div class='metric yellow'><small>Shares sent to pool</small><strong id=shares>0</strong></div><div class=metric><small>Templates / last</small><strong id=templates>0</strong></div><div class=metric><small>Wi-Fi signal</small><strong id=rssi>waiting</strong></div><div class=metric><small>Shares accepted / rejected</small><strong id=results>0 / 0</strong></div><div class=metric><small>Heap minimum</small><strong id=minheap>waiting</strong></div><div class=metric><small>Pool session</small><strong id=session>waiting</strong></div></div><h2>Live performance</h2><div class=line><canvas id=hashGauge width=200 height=110></canvas><canvas id=hashChart width=420 height=110></canvas></div><div class=line><canvas id=memGauge width=200 height=110></canvas><canvas id=memChart width=420 height=110></canvas></div><div class=line><canvas id=tempGauge width=200 height=110></canvas><canvas id=tempChart width=420 height=110></canvas></div><div class=line><canvas id=shareGauge width=200 height=110></canvas><canvas id=shareChart width=420 height=110></canvas></div><div class=actions><button id=requestTemplate>Request new template</button><button id=resetBoard class=danger>Reset board</button></div><p id=actionNote class=hint>Connecting to board...</p></section>";
  page.replace("<meta name=viewport", brand_document_head() + "<meta name=viewport");
  page.replace("</style>", ".brand{display:flex;align-items:center;gap:.7rem;margin-bottom:1rem}.brand-logo{width:3.25rem;height:3.25rem}.brand h1{margin:0;text-transform:lowercase}.brand-site,footer a{color:#41e6a1;text-decoration:none}.brand-site:hover,footer a:hover{text-decoration:underline}footer{margin-top:1.5rem;text-align:center;color:var(--muted)}</style>");
  page.replace("<h1>ESP32 BLAKE2b Miner</h1>", brand_header());
  page += "<form id=config class=tab method=post action=/save><h2>Device</h2>" + input("device_name", "Device name (.local address)", settings.device_name) + "<h2>Wi-Fi</h2>" + input("ssid", "Network name (SSID)", settings.wifi_ssid) + input("wifi_pw", "Wi-Fi password (leave blank to keep saved password)", "", "password") + "<h2>Pool</h2>" + input("pool_host", "Host", settings.pool_host) + input("pool_port", "Port", String(settings.pool_port), "number") + input("pool_user", "Username / payout address", settings.pool_username) + input("pool_pw", "Pool password", settings.pool_password, "password") + pow_mode_input() + "<p class=hint>Pool host and port fill in automatically for the selected proof-of-work mode; edit them afterwards if you're using a different endpoint.</p><button type=submit>Save and restart</button></form>";
  page += R"HTML(<script>(()=>{const modeHost={0:['sc.f2pool.com',7788],1:['pool.pyblock.xyz',4445]};const powSelect=document.getElementById('pow_mode'),hostInput=document.querySelector("input[name='pool_host']"),portInput=document.querySelector("input[name='pool_port']");if(powSelect&&hostInput&&portInput)powSelect.onchange=()=>{const preset=modeHost[powSelect.value];if(!preset)return;hostInput.value=preset[0];portInput.value=preset[1]}})()</script>)HTML";
  page += R"HTML(<script>(()=>{const $=id=>document.getElementById(id),hist={hash:[],mem:[],temp:[],share:[]};let ws,lastHashes,lastAt,lastTemplates=0;dashTab.onclick=()=>{dashboard.classList.add('active');config.classList.remove('active')};configTab.onclick=()=>{dashboard.classList.remove('active');config.classList.add('active')};const kb=n=>Math.round(n/1024)+' KB',dur=s=>s<60?s+'s':Math.floor(s/60)+'m '+s%60+'s';const gauge=(id,value,max,label,color,unit)=>{const c=$(id),x=c.getContext('2d'),p=Math.max(0,Math.min(1,value/max));x.clearRect(0,0,200,110);x.lineWidth=12;x.strokeStyle='#252f3d';x.beginPath();x.arc(100,94,70,Math.PI,2*Math.PI);x.stroke();x.strokeStyle=color;x.beginPath();x.arc(100,94,70,Math.PI,Math.PI+p*Math.PI);x.stroke();x.fillStyle=color;x.textAlign='center';x.fillText(label,100,78);x.fillStyle='#94a3b8';x.fillText('0 - '+max+' '+unit,100,101)};const chart=(id,values,max,label,color)=>{const c=$(id),x=c.getContext('2d');x.clearRect(0,0,420,110);x.strokeStyle=color;x.lineWidth=2;x.beginPath();values.forEach((v,i)=>{const px=i*420/Math.max(1,values.length-1),py=96-v/max*78;i?x.lineTo(px,py):x.moveTo(px,py)});x.stroke();x.fillStyle='#94a3b8';x.fillText(label,10,16)};const update=s=>{const now=Date.now();let rate=Number(s.rate)||0;if(lastHashes!==undefined&&now>lastAt){const measured=(Number(s.hashes)-lastHashes)*1000/(now-lastAt);if(measured>=0)rate=measured}lastHashes=Number(s.hashes);lastAt=now;const mem=Number(s.free_mem)/1024,tempValue=Number(s.temperature),sent=Number(s.shares_submitted)||0;network.textContent=s.network+' / '+s.pool;job.textContent=s.job||'-';hashes.textContent=Number(s.hashes).toLocaleString();rate.textContent=rate.toFixed(1)+' H/s';memory.textContent=Math.round(mem)+' KB';temp.textContent=tempValue.toFixed(1)+' deg C';shares.textContent=sent.toLocaleString();templates.textContent=s.templates+' / '+(s.template_age<0?'none':dur(s.template_age)+' ago');rssi.textContent=s.wifi_rssi?s.wifi_rssi+' dBm / ch '+s.wifi_channel:'offline';results.textContent=s.shares_accepted+' / '+s.shares_rejected;minheap.textContent=kb(s.min_free_mem);session.textContent=s.pool_uptime?dur(s.pool_uptime):'disconnected';[['hash',rate],['mem',mem],['temp',tempValue],['share',sent]].forEach(([key,value])=>{hist[key].push(value);if(hist[key].length>60)hist[key].shift()});const shareMax=Math.max(10,...hist.share);gauge('hashGauge',rate,20000,rate.toFixed(1)+' H/s','#41e6a1','H/s');gauge('memGauge',mem,320,Math.round(mem)+' KB','#b783ff','KB');gauge('tempGauge',tempValue,100,tempValue.toFixed(1)+' deg C','#ff9f43','deg C');gauge('shareGauge',sent,shareMax,sent+' sent','#f59e0b','');chart('hashChart',hist.hash,20000,'HASH RATE - 0 to 20000 H/s','#41e6a1');chart('memChart',hist.mem,320,'FREE MEMORY - 0 to 320 KB','#b783ff');chart('tempChart',hist.temp,100,'TEMPERATURE - 0 to 100 deg C','#ff9f43');chart('shareChart',hist.share,shareMax,'SHARES SENT TO POOL - TOTAL','#f59e0b');if(s.templates>lastTemplates&&lastTemplates)actionNote.textContent='New template received.';lastTemplates=s.templates};const connect=()=>{ws=new WebSocket(`ws://${location.hostname}:81/`);ws.onopen=()=>actionNote.textContent='Connected. Dashboard refreshes every 5 seconds.';ws.onmessage=e=>{try{update(JSON.parse(e.data))}catch(_){}};ws.onclose=()=>{actionNote.textContent='Board connection lost; retrying...';setTimeout(connect,1000)};ws.onerror=()=>ws.close()};requestTemplate.onclick=()=>{if(ws?.readyState!==WebSocket.OPEN){actionNote.textContent='Board connection not ready.';return}ws.send(JSON.stringify({method:'dashboard.request_template'}));actionNote.textContent='New template requested; waiting for the pool.'};resetBoard.onclick=()=>{if(!confirm('Restart the ESP32 board now?'))return;if(ws?.readyState===WebSocket.OPEN){resetBoard.textContent='Restarting...';ws.send(JSON.stringify({method:'dashboard.reset'}))}else actionNote.textContent='Board connection not ready.'};connect()})()</script></main>)HTML";
  page += R"HTML(<script>(()=>{const updateRate=s=>{document.getElementById('rate').textContent=(Number(s.rate)||0).toFixed(1)+' H/s'};const connect=()=>{const ws=new WebSocket(`ws://${location.hostname}:81/`);ws.onmessage=e=>{try{updateRate(JSON.parse(e.data))}catch(_){}};ws.onclose=()=>setTimeout(connect,1000);ws.onerror=()=>ws.close()};connect()})()</script>)HTML";
  page += R"HTML(<script>(()=>{const $=id=>document.getElementById(id),tabs=$('dashTab').parentElement,infoTab=document.createElement('button'),info=document.createElement('section');infoTab.type='button';infoTab.id='poolTab';infoTab.textContent='Pool activity';tabs.insertBefore(infoTab,$('configTab'));info.id='poolInfo';info.className='tab';info.innerHTML='<h2>Miner and pool information</h2><div class="grid"><div class="metric"><small>Endpoint</small><strong id="poolEndpoint">waiting</strong></div><div class="metric"><small>Proof of work</small><strong id="poolPow">waiting</strong></div><div class="metric"><small>Connection attempts / sessions</small><strong id="poolConnections">0 / 0</strong></div><div class="metric"><small>Current template</small><strong id="poolTemplate">waiting</strong></div><div class="metric"><small>Template header</small><strong id="poolHeader">waiting</strong></div><div class="metric"><small>Shares (accepted / rejected / sent)</small><strong id="poolShares">0 / 0 / 0</strong></div></div><h2>Recent pool messages</h2><p class="hint">Newest messages are shown first. This history is kept on the miner and updates through the WebSocket.</p><ol id="poolLogs" class="pool-logs"><li>Waiting for pool activity...</li></ol>';$('config').insertAdjacentElement('beforebegin',info);const select=which=>{['dashboard','config','poolInfo'].forEach(id=>$(id).classList.toggle('active',id===which))};$('dashTab').onclick=()=>select('dashboard');$('configTab').onclick=()=>select('config');infoTab.onclick=()=>select('poolInfo');const dur=s=>s<60?s+'s':Math.floor(s/60)+'m '+s%60+'s';let ws;const update=s=>{$('poolEndpoint').textContent=(s.pool_host||'not configured')+':'+(s.pool_port||'-')+' ('+s.pool+')';$('poolPow').textContent=s.pow_mode||'unknown';$('poolConnections').textContent=(s.pool_attempts||0)+' / '+(s.pool_sessions||0);$('poolTemplate').textContent=s.job||'no template';$('poolHeader').textContent=s.header_bytes?s.header_bytes+' bytes, '+(s.template_age<0?'age unknown':dur(s.template_age)+' old'):'waiting for a template';$('poolShares').textContent=(s.shares_accepted||0)+' / '+(s.shares_rejected||0)+' / '+(s.shares_submitted||0);const list=$('poolLogs');list.replaceChildren();const logs=Array.isArray(s.pool_logs)?s.pool_logs:[];if(!logs.length){const item=document.createElement('li');item.textContent='No pool messages yet.';list.append(item)}else logs.forEach(entry=>{const item=document.createElement('li');item.textContent=entry;list.append(item)})};const connect=()=>{ws=new WebSocket(`ws://${location.hostname}:81/`);ws.onmessage=e=>{try{update(JSON.parse(e.data))}catch(_){}};ws.onclose=()=>setTimeout(connect,1000);ws.onerror=()=>ws.close()};connect()})()</script><style>.pool-logs{margin:0;padding-left:1.4rem;max-height:26rem;overflow:auto;background:#090d13;border:1px solid var(--line);border-radius:.5rem}.pool-logs li{padding:.55rem .7rem;border-bottom:1px solid #202938;font:12px ui-monospace,SFMono-Regular,monospace;overflow-wrap:anywhere}.pool-logs li:last-child{border-bottom:0}</style>)HTML";
  page += R"HTML(<style>.tab-actions{display:flex;gap:.6rem;margin-left:auto}.tab-actions button{width:auto}.tab-actions #requestTemplate{background:#f59e0b;color:#201303}.tab-actions #requestTemplate:hover{background:#fbbf24}@media(max-width:42rem){.tab-actions{margin-left:0;width:100%}.tab-actions button{flex:1}}</style><script>(()=>{const tabs=document.querySelector('.tabs'),actions=document.createElement('div'),request=document.getElementById('requestTemplate'),reset=document.getElementById('resetBoard');if(!tabs||!request||!reset)return;actions.className='tab-actions';request.type='button';reset.type='button';actions.append(request,reset);tabs.append(actions)})()</script>)HTML";
  page += R"HTML(<script>(()=>{const info=document.getElementById('poolInfo'),logs=document.getElementById('poolLogs');if(!info||!logs)return;const heading=document.createElement('h2'),grid=document.createElement('div');heading.textContent='F2Pool Stratum information';grid.className='grid';grid.innerHTML='<div class="metric"><small>Pool difficulty</small><strong id="f2Difficulty">waiting</strong></div><div class="metric"><small>ExtraNonce1</small><strong id="f2ExtraNonce">waiting</strong></div><div class="metric"><small>ExtraNonce2 size</small><strong id="f2ExtraNonceSize">waiting</strong></div><div class="metric"><small>Block version</small><strong id="f2Version">waiting</strong></div><div class="metric"><small>Network nBits</small><strong id="f2NBits">waiting</strong></div><div class="metric"><small>Pool nTime</small><strong id="f2NTime">waiting</strong></div><div class="metric"><small>Last server message</small><strong id="f2ServerMessage">waiting</strong></div><div class="metric"><small>Last Stratum method</small><strong id="f2LastMethod">waiting</strong></div>';info.insertBefore(heading,logs.previousElementSibling);info.insertBefore(grid,logs.previousElementSibling);const set=(id,value,fallback='not received')=>document.getElementById(id).textContent=value||fallback;const connect=()=>{const ws=new WebSocket(`ws://${location.hostname}:81/`);ws.onmessage=e=>{try{const s=JSON.parse(e.data);set('f2Difficulty',s.stratum_difficulty);set('f2ExtraNonce',s.stratum_extranonce1);set('f2ExtraNonceSize',s.stratum_extranonce2_size||'', 'not received');set('f2Version',s.stratum_version);set('f2NBits',s.stratum_nbits);set('f2NTime',s.stratum_ntime);set('f2ServerMessage',s.pool_server_message);set('f2LastMethod',s.pool_last_message)}catch(_){}};ws.onclose=()=>setTimeout(connect,1000);ws.onerror=()=>ws.close()};connect()})()</script>)HTML";
  page.replace("item.textContent=entry;list.append(item)", "const stamp=/^(?:boot\\+)?([0-9]+)s\\s+(.*)$/.exec(entry);item.textContent=stamp?new Date(Date.now()-(Number(s.uptime||0)-Number(stamp[1]))*1000).toLocaleString()+'  '+stamp[2]:entry;if(String(entry).includes('ERROR:'))item.className='error';list.append(item)");
  page.replace(".pool-logs li:last-child", ".pool-logs li.error{color:#fecaca;background:#450a0a;border-left:3px solid #ef4444}.pool-logs li:last-child");
  page.replace("gauge('hashGauge',rate,20000", "gauge('hashGauge',rate,30000");
  page.replace("chart('hashChart',hist.hash,20000", "chart('hashChart',hist.hash,30000");
  page.replace("HASH RATE - 0 to 20000 H/s", "HASH RATE - 0 to 30000 H/s");
  page.replace("</main>", brand_footer() + "</main>");
  if (notice.length()) page += "<p class=hint>" + notice + "</p>";
  web.send(200, "text/html; charset=utf-8", page);
}
void configure_web_server() {
  if (web_started) return;
  web.on("/favicon.svg", HTTP_GET, []() { web.send_P(200, "image/svg+xml", POOP_ICON_SVG); });
  web.on("/favicon.ico", HTTP_GET, []() { web.send_P(200, "image/svg+xml", POOP_ICON_SVG); });
  web.on("/", HTTP_GET, []() { send_config_page(); });
  web.on("/generate_204", HTTP_GET, []() { send_config_page(); });
  web.on("/hotspot-detect.html", HTTP_GET, []() { send_config_page(); });
  web.on("/save", HTTP_POST, []() {
    Settings next = settings;
    next.wifi_ssid = web.arg("ssid"); if (web.arg("wifi_pw").length()) next.wifi_password = web.arg("wifi_pw");
    next.device_name = web.arg("device_name");
    next.pool_host = web.arg("pool_host"); next.pool_port = uint16_t(web.arg("pool_port").toInt());
    next.pool_username = web.arg("pool_user"); next.pool_password = web.arg("pool_pw");
    next.pow_mode = PowMode(web.arg("pow_mode").toInt());
    if (!valid_settings(next) || !valid_device_name(next.device_name)) { send_config_page("Enter a valid device name, Wi-Fi, pool host, username, and port."); return; }
    preferences.begin(SETTINGS_NAMESPACE, false);
    preferences.putString("ssid", next.wifi_ssid); preferences.putString("wifi_pw", next.wifi_password);
    preferences.putString("pool_host", next.pool_host); preferences.putUShort("pool_port", next.pool_port);
    preferences.putString("pool_user", next.pool_username); preferences.putString("pool_pw", next.pool_password);
    preferences.putString("device_name", next.device_name);
    preferences.putUChar("pow_mode", next.pow_mode);
    preferences.end();
    web.send(200, "text/html; charset=utf-8", "<!doctype html><meta charset=utf-8><title>retardminer</title><meta name=viewport content='width=device-width,initial-scale=1'><p>retardminer settings saved. Restarting…</p>"); delay(500); ESP.restart();
  });
  web.onNotFound([]() { send_config_page(); });
  web.begin();
  websocket.begin();
  websocket.onEvent([](uint8_t, WStype_t type, uint8_t *payload, size_t length) {
    if (type != WStype_TEXT) return;
    JsonDocument command;
    if (deserializeJson(command, payload, length)) return;
    const char *method = command["method"] | "";
    if (!strcmp(method, "dashboard.request_template")) request_new_template();
    else if (!strcmp(method, "dashboard.reset")) restart_requested = true;
  });
  websocket_started = true;
  web_started = true;
}
void start_portal() {
  if (portal_active) return;
  portal_active = true; pool.stop(); WiFi.disconnect(); WiFi.mode(WIFI_AP);
  WiFi.softAP(SETUP_SSID);
  dns.start(DNS_PORT, "*", WiFi.softAPIP());
  configure_web_server();
  Serial.printf("retardminer setup portal: connect to %s and open http://%s\n", SETUP_SSID, WiFi.softAPIP().toString().c_str());
}
bool connect_wifi() {
  if (!settings.wifi_ssid.length()) return false;
  WiFi.mode(WIFI_STA); WiFi.begin(settings.wifi_ssid.c_str(), settings.wifi_password.c_str());
  Serial.printf("Connecting to Wi-Fi: %s\n", settings.wifi_ssid.c_str());
  uint32_t started = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - started < WIFI_CONNECT_TIMEOUT_MS) delay(300);
  if (WiFi.status() == WL_CONNECTED) {
    // Avoid starting SNTP here. On this ESP32/Arduino core build, the DNS work
    // done by time sync can race with the pool connection path and trip the
    // lwIP TCPIP-core assert. The device works without local wall-clock time;
    // timestamps fall back to "time unavailable" until we add a safer sync path.
    Serial.printf("Wi-Fi connected: %s\n", WiFi.localIP().toString().c_str());
    return true;
  }
  Serial.println("ERROR: Wi-Fi connection failed."); return false;
}
void start_mdns() {
  if (mdns_started || WiFi.status() != WL_CONNECTED) return;
  if (MDNS.begin(settings.device_name.c_str())) {
    MDNS.addService("http", "tcp", 80);
    mdns_started = true;
    Serial.printf("Configuration page: http://%s.local\n", settings.device_name.c_str());
  } else Serial.println("mDNS setup failed; use the IP address instead.");
}
void service_status_led() {
  const uint32_t phase = millis() % 1000;
  const bool on = portal_active ? phase < 500 : (pool.connected() ? phase < 80 : (phase % 250) < 125);
  digitalWrite(STATUS_LED_PIN, on ? HIGH : LOW);
}
void service_dashboard() {
  // Status normally refreshes every five seconds, but pool events are pushed
  // promptly so the activity tab behaves as a live message stream.
  const uint32_t elapsed = millis() - last_dashboard;
  if (!websocket_started || (!dashboard_dirty && elapsed < 5000) || (dashboard_dirty && elapsed < 250)) return;
  last_dashboard = millis();
  dashboard_dirty = false;
  JsonDocument status;
  status["network"] = WiFi.status() == WL_CONNECTED ? WiFi.localIP().toString() : (portal_active ? "setup portal" : "Wi-Fi offline");
  status["pool"] = pool.connected() ? "connected" : "disconnected";
  status["pool_host"] = settings.pool_host;
  status["pool_port"] = settings.pool_port;
  status["pow_mode"] = settings.pow_mode == POW_PYBLOCK_BLAKE2B ? "BLAKE2b / Stratum V1 (PyBLOCK)" : "BLAKE2b-Sia";
  status["stratum_difficulty"] = pool_difficulty;
  status["stratum_extranonce1"] = stratum_extranonce1;
  status["stratum_extranonce2_size"] = stratum_extranonce2_size;
  status["stratum_version"] = stratum_version;
  status["stratum_nbits"] = stratum_nbits;
  status["stratum_ntime"] = stratum_ntime;
  status["pool_server_message"] = pool_server_message;
  status["pool_last_message"] = pool_last_message;
  status["job"] = job_id;
  status["header_bytes"] = header_len;
  status["hashes"] = hash_count();
  status["rate"] = current_hashrate;
  status["uptime"] = millis() / 1000;
  status["templates"] = templates_received;
  status["template_age"] = last_template_ms ? (millis() - last_template_ms) / 1000 : -1;
  status["free_mem"] = ESP.getFreeHeap();
  status["min_free_mem"] = ESP.getMinFreeHeap();
  status["max_alloc_mem"] = ESP.getMaxAllocHeap();
  status["heap_total"] = ESP.getHeapSize();
  status["psram_total"] = ESP.getPsramSize();
  status["psram_free"] = ESP.getFreePsram();
  status["temperature"] = temperatureRead();
  status["wifi_rssi"] = WiFi.status() == WL_CONNECTED ? WiFi.RSSI() : 0;
  status["wifi_channel"] = WiFi.status() == WL_CONNECTED ? WiFi.channel() : 0;
  status["pool_attempts"] = pool_connection_attempts;
  status["pool_sessions"] = pool_sessions;
  status["pool_uptime"] = pool.connected() && pool_connected_since ? (millis() - pool_connected_since) / 1000 : 0;
  status["shares_submitted"] = shares_submitted;
  status["shares_accepted"] = shares_accepted;
  status["shares_rejected"] = shares_rejected;
  status["chip"] = ESP.getChipModel();
  status["chip_revision"] = ESP.getChipRevision();
  status["cpu_mhz"] = ESP.getCpuFreqMHz();
  status["flash_bytes"] = ESP.getFlashChipSize();
  status["sketch_bytes"] = ESP.getSketchSize();
  status["free_sketch_bytes"] = ESP.getFreeSketchSpace();
  // Retained only for older dashboard clients; the current dashboard does not show voltage.
  status["voltage"] = -1.0f;
  status["led_mode"] = portal_active ? 0 : (pool.connected() ? 1 : 2);
  status["uptime_ms"] = millis();
  JsonArray logs = status["pool_logs"].to<JsonArray>();
  for (uint8_t i = 0; i < pool_log_count; ++i) {
    const uint8_t index = (pool_log_start + pool_log_count - 1 - i) % POOL_LOG_CAPACITY;
    logs.add(pool_logs[index]);
  }
  String message; serializeJson(status, message); websocket.broadcastTXT(message);
}

bool decode_hex(const char *text, uint8_t *out, size_t out_size, size_t &written) {
  size_t n = strlen(text); if ((n & 1) || n / 2 > out_size) return false;
  auto nibble = [](char c) -> int { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; if (c >= 'A' && c <= 'F') return c - 'A' + 10; return -1; };
  for (size_t i = 0; i < n; i += 2) { int a = nibble(text[i]), b = nibble(text[i + 1]); if (a < 0 || b < 0) return false; out[i / 2] = uint8_t((a << 4) | b); }
  written = n / 2; return true;
}
String hex_of(const uint8_t *data, size_t n) { const char *d = "0123456789abcdef"; String s; s.reserve(n * 2); for (size_t i = 0; i < n; ++i) { s += d[data[i] >> 4]; s += d[data[i] & 15]; } return s; }
void set_sia_stratum_target(double difficulty) {
  // F2Pool SC Stratum difficulty-1 target, big-endian:
  // 00000000ffffff000000000000000000000000000000000000000000000000
  const uint8_t diff1[32] = {0, 0, 0, 0, 0xff, 0xff, 0xff};
  // F2Pool advertises fractional difficulties such as 32767.5 (65535/2)
  // and 8191.875 (65535/8). Convert target = diff1 / difficulty to the
  // exact integer operation diff1 * scale / 65535.
  const uint32_t scale = difficulty > 0.0 ? uint32_t(65535.0 / difficulty + 0.5) : 1;
  uint8_t work[36] = {};
  uint32_t carry = 0;
  for (int i = 31; i >= 0; --i) { const uint32_t product = uint32_t(diff1[i]) * scale + carry; work[i + 4] = uint8_t(product); carry = product >> 8; }
  for (int i = 3; i >= 0 && carry; --i) { work[i] = uint8_t(carry); carry >>= 8; }
  uint64_t remainder = 0;
  for (size_t i = 0; i < sizeof(work); ++i) { remainder = remainder * 256 + work[i]; work[i] = uint8_t(remainder / 65535); remainder %= 65535; }
  memcpy(target, work + 4, sizeof(target));
}
bool meets_target(const uint8_t hash[32], const uint8_t goal[32]) { for (size_t i = 0; i < 32; ++i) { if (hash[i] < goal[i]) return true; if (hash[i] > goal[i]) return false; } return true; }
bool meets_target(const uint8_t hash[32]) { return meets_target(hash, target); }
// PyBLOCK's BLAKE2b/header-v2 Stratum extension (confirmed against the live pool and the
// DATUM gateway's bip110-pow-v2 branch, not the Knots PR #359 v2 header format): share
// difficulty 1 is the ~2^224 all-ones target below, same order of magnitude as Bitcoin's own
// diff-1, halved by each doubling of difficulty (mirrors DATUM's floorPoT/datum_u256_shr, just
// with this firmware's most-significant-byte-first target convention instead of DATUM's LE one).
void set_pyblock_blake2b_target(double difficulty) {
  uint64_t diff = difficulty >= 1.0 ? uint64_t(difficulty) : 1;
  uint8_t bits = 0; { uint64_t x = diff; while (x >>= 1) ++bits; }
  memset(target, 0, 4); memset(target + 4, 0xff, sizeof(target) - 4);
  const unsigned byte_shift = bits / 8, bit_shift = bits % 8;
  if (byte_shift >= sizeof(target)) { memset(target, 0, sizeof(target)); return; }
  if (byte_shift) { memmove(target + byte_shift, target, sizeof(target) - byte_shift); memset(target, 0, byte_shift); }
  if (bit_shift) { for (int i = 31; i > 0; --i) target[i] = uint8_t((target[i] >> bit_shift) | (target[i - 1] << (8 - bit_shift))); target[0] = uint8_t(target[0] >> bit_shift); }
}
// Assembles the 80-byte BLAKE2b work buffer for a PyBLOCK job: prevhash and ntime are used
// exactly as sent (no byte reversal - confirmed by the 6/3/4 leading/trailing zero bytes the
// gateway's tagged-hash and Sia-style wrappers leave in them, and by ntime's high 4 bytes
// decoding to the live wall-clock time), coinb1 is a 39-byte commitment (not a real Bitcoin
// coinbase fragment) the gateway already hashed for us, and the work root folds in our own
// extranonce2 - the only piece of the job we choose ourselves.
bool set_pyblock_blake2b_job(JsonArray job) {
  last_template_error = "";
  if (job.size() < 9) { last_template_error = "PyBLOCK BLAKE2b notify has fewer than 9 fields"; return false; }
  if (!stratum_extranonce1.length() || stratum_extranonce2_size != 8) { last_template_error = "PyBLOCK BLAKE2b requires a 4-byte extranonce1 and 8-byte extranonce2 from subscribe"; return false; }
  const char *id = job[0] | "";
  const char *prevhash_hex = job[1] | "";
  const char *coinb1_hex = job[2] | "";
  const char *coinb2_hex = job[3] | "";
  JsonArray branches = job[4].as<JsonArray>();
  const char *ntime_hex = job[7] | "";
  if (!id[0]) { last_template_error = "missing job id"; return false; }
  if (coinb2_hex[0] || branches.size()) { last_template_error = "PyBLOCK BLAKE2b job must have an empty coinb2 and no merkle branches"; return false; }
  uint8_t prevhash_raw[32], commitment_wire[39], ntime_raw[8] = {}, extranonce1_raw[4];
  size_t n = 0;
  if (!decode_hex(prevhash_hex, prevhash_raw, sizeof(prevhash_raw), n) || n != sizeof(prevhash_raw)) { last_template_error = "PyBLOCK prevhash is not exactly 32 bytes of hex"; return false; }
  if (!decode_hex(coinb1_hex, commitment_wire, sizeof(commitment_wire), n) || n != sizeof(commitment_wire)) { last_template_error = "PyBLOCK coinb1 is not exactly 39 bytes of hex"; return false; }
  const size_t ntime_len = strlen(ntime_hex);
  if (ntime_len == 16) { if (!decode_hex(ntime_hex, ntime_raw, sizeof(ntime_raw), n) || n != sizeof(ntime_raw)) { last_template_error = "PyBLOCK ntime is invalid hex"; return false; } }
  else if (ntime_len == 8) { if (!decode_hex(ntime_hex, ntime_raw, 4, n) || n != 4) { last_template_error = "PyBLOCK ntime is invalid hex"; return false; } }
  else { last_template_error = "PyBLOCK ntime must be 4 or 8 bytes of hex"; return false; }
  if (!decode_hex(stratum_extranonce1.c_str(), extranonce1_raw, sizeof(extranonce1_raw), n) || n != sizeof(extranonce1_raw)) { last_template_error = "PyBLOCK extranonce1 is not exactly 4 bytes of hex"; return false; }
  uint8_t extranonce2_raw[8];
  for (uint8_t i = 0; i < sizeof(extranonce2_raw); ++i) extranonce2_raw[i] = uint8_t(esp_random() >> ((i & 3) * 8));
  uint8_t leaf[52] = {};
  memcpy(leaf + 1, commitment_wire, sizeof(commitment_wire));
  memcpy(leaf + 40, extranonce1_raw, sizeof(extranonce1_raw));
  memcpy(leaf + 44, extranonce2_raw, sizeof(extranonce2_raw));
  uint8_t root[32]; blake2b_256(leaf, sizeof(leaf), root);
  uint8_t work[80];
  memcpy(work, prevhash_raw, 32); memset(work + 32, 0, 8); memcpy(work + 40, ntime_raw, 8); memcpy(work + 48, root, 32);
  job_id = id; stratum_ntime = ntime_hex; stratum_extranonce2 = hex_of(extranonce2_raw, sizeof(extranonce2_raw));
  header_len = 80; memcpy(header, work, 80); nonce = esp_random(); ++templates_received; last_template_ms = millis();
  set_pyblock_blake2b_target(pool_difficulty.toDouble());
  add_pool_log(String("Received PyBLOCK BLAKE2b template ") + job_id);
  Serial.print("PyBLOCK job: "); Serial.println(job_id);
  portENTER_CRITICAL(&mining_mux);
  memcpy(worker_job.header, work, 80); memcpy(worker_job.target, target, sizeof(target)); worker_job.header_len = 80; worker_job.mode = POW_PYBLOCK_BLAKE2B; worker_job.nonce_offset = 32; worker_job.nonce_size = 4; ++worker_job.generation;
  portEXIT_CRITICAL(&mining_mux);
  return true;
}
// The raw BLAKE2b-256 digest is compared to target as-is (most-significant byte first) - no
// reversal. set_pyblock_blake2b_target() already builds its target in that same orientation
// (mirroring the reference miner's target_be(), which pre-reverses the target instead of
// reversing the digest, since DATUM's own server-side check reverses the digest the other way).
void pyblock_blake2b_pow(const uint8_t *work, uint8_t output[32]) { blake2b_256(work, 80, output); }
void send_json(JsonDocument &doc) { String out; serializeJson(doc, out); pool.print(out); pool.print('\n'); }
void request_new_template() {
  if (!pool.connected()) { Serial.println("cannot request template: pool is disconnected"); add_pool_log("Template request skipped: pool is disconnected"); return; }
  DynamicJsonDocument d(192);
  d["id"] = request_id++;
  d["method"] = "mining.request_template";
  d["params"].add(settings.pool_username);
  send_json(d);
  add_pool_log("Requested a new template from the pool");
}
void subscribe() { DynamicJsonDocument d(256); subscribe_request_id = request_id; d["id"] = request_id++; d["method"] = "mining.subscribe"; d["params"].add("retardminer/0.1"); send_json(d); d.clear(); authorize_request_id = request_id; d["id"] = request_id++; d["method"] = "mining.authorize"; JsonArray p = d["params"].to<JsonArray>(); p.add(settings.pool_username); p.add(settings.pool_password); send_json(d); add_pool_log("Sent subscribe and authorize"); }
void submit_share(uint64_t share_nonce, const uint8_t hash[32]) { DynamicJsonDocument d(512); last_share_request_id = request_id; d["id"] = request_id++; d["method"] = "mining.submit"; JsonArray p = d["params"].to<JsonArray>(); p.add(settings.pool_username); p.add(job_id); if (settings.pow_mode == POW_PYBLOCK_BLAKE2B || (settings.pow_mode == POW_SIA && stratum_extranonce2.length())) { p.add(stratum_extranonce2); p.add(stratum_ntime); String nonce_hex = String(share_nonce, HEX); while (nonce_hex.length() < (settings.pow_mode == POW_SIA ? 16 : 8)) nonce_hex = "0" + nonce_hex; p.add(nonce_hex); } else { p.add(String(share_nonce)); p.add(hex_of(hash, 32)); } send_json(d); ++shares_submitted; add_pool_log(String("Submitted share for job ") + job_id + ", nonce " + String(share_nonce)); }
bool set_job(const char *id, const char *header_hex, const char *target_hex) {
  size_t target_len = 0;
  last_template_error = "";
  if (!id || !header_hex || !target_hex) { last_template_error = "missing job id, header, or target"; Serial.println("ignored notify: missing job id, header, or target"); return false; }
  if (!decode_hex(header_hex, header, MAX_HEADER, header_len)) { last_template_error = "header is invalid hex or exceeds 256 bytes"; Serial.println("ignored notify: invalid or oversized header hex"); return false; }
  if (header_len != 80) { last_template_error = "BLAKE2b-Sia requires an 80-byte header"; Serial.println("ignored notify: BLAKE2b-Sia mode requires an 80-byte Sia header"); return false; }
  if (!decode_hex(target_hex, target, sizeof(target), target_len) || target_len != sizeof(target)) { last_template_error = "target is not exactly 32 bytes of hex"; Serial.println("ignored notify: target must be exactly 32 bytes of hex"); return false; }
  job_id = id; nonce = esp_random(); ++templates_received; last_template_ms = millis();
  add_pool_log(String("Received template ") + job_id + " (" + String(header_len) + " byte header)");
  portENTER_CRITICAL(&mining_mux);
  memcpy(worker_job.header, header, header_len); memcpy(worker_job.target, target, sizeof(target)); worker_job.header_len = header_len; worker_job.mode = POW_SIA;
  worker_job.nonce_offset = 32; worker_job.nonce_size = 8; ++worker_job.generation;
  portEXIT_CRITICAL(&mining_mux);
  return true;
}
bool set_f2pool_sia_job(JsonArray job) {
  last_template_error = "";
  if (job.size() < 9 || !stratum_extranonce1.length() || !stratum_extranonce2_size) { last_template_error = "missing F2Pool Sia notify or extranonce fields"; return false; }
  const char *id = job[0] | "", *parent = job[1] | "", *coinb1 = job[2] | "", *coinb2 = job[3] | ""; stratum_nbits = job[6] | ""; stratum_ntime = job[7] | "";
  String extra2; for (uint8_t i = 0; i < stratum_extranonce2_size; ++i) { uint8_t byte = uint8_t(esp_random() >> ((i & 3) * 8)); if (byte < 16) extra2 += '0'; extra2 += String(byte, HEX); }
  String coinbase_hex = String(coinb1) + stratum_extranonce1 + extra2 + coinb2; const size_t coinbase_size = coinbase_hex.length() / 2; uint8_t *coinbase = static_cast<uint8_t *>(malloc(coinbase_size)); size_t used = 0;
  if (!id[0] || !coinbase || !decode_hex(coinbase_hex.c_str(), coinbase, coinbase_size, used) || used != coinbase_size) { last_template_error = "invalid F2Pool Sia coinbase"; if (coinbase) free(coinbase); return false; }
  uint8_t root[32]; blake2b_256(coinbase, coinbase_size, root); free(coinbase); JsonArray branches = job[4].as<JsonArray>();
  for (JsonVariant branch : branches) { uint8_t next[64]; size_t n = 0; if (!decode_hex(branch.as<const char *>(), next + 32, 32, n) || n != 32) { last_template_error = "invalid F2Pool Sia merkle branch"; return false; } memcpy(next, root, 32); blake2b_256(next, sizeof(next), root); }
  size_t n = 0; if (!decode_hex(parent, header, 32, n) || n != 32 || !decode_hex(stratum_ntime.c_str(), header + 40, 8, n) || n != 8) { last_template_error = "invalid Sia parent ID or timestamp"; return false; }
  memset(header + 32, 0, 8); memcpy(header + 48, root, 32); header_len = 80; job_id = id; stratum_extranonce2 = extra2; nonce = esp_random(); ++templates_received; last_template_ms = millis(); set_sia_stratum_target(pool_difficulty.toDouble());
  portENTER_CRITICAL(&mining_mux); memcpy(worker_job.header, header, 80); memcpy(worker_job.target, target, 32); worker_job.header_len = 80; worker_job.mode = POW_SIA; worker_job.nonce_offset = 32; worker_job.nonce_size = 8; ++worker_job.generation; portEXIT_CRITICAL(&mining_mux); add_pool_log(String("Received F2Pool Siacoin template ") + job_id); return true;
}
void process_line(const String &line) {
  DynamicJsonDocument d(1536); if (deserializeJson(d, line)) { add_pool_log("ERROR: Received invalid JSON from pool"); return; }
  if (last_share_request_id && d["id"].as<uint32_t>() == last_share_request_id) {
    if ((d["result"] | false) && d["error"].isNull()) { ++shares_accepted; add_pool_log("Pool accepted submitted share"); }
    else { String detail; if (!d["error"].isNull()) serializeJson(d["error"], detail); ++shares_rejected; add_pool_log(String("ERROR: Pool rejected submitted share") + (detail.length() ? ": " + detail : "")); }
    last_share_request_id = 0;
    return;
  }
  if (subscribe_request_id && d["id"].as<uint32_t>() == subscribe_request_id) {
    JsonArray result = d["result"].as<JsonArray>();
    stratum_extranonce1 = result[1] | "";
    stratum_extranonce2_size = result[2] | 0;
    add_pool_log(String("Pool subscription: extranonce1=") + stratum_extranonce1 + ", extranonce2 size=" + String(stratum_extranonce2_size));
    subscribe_request_id = 0;
    return;
  }
  if (authorize_request_id && d["id"].as<uint32_t>() == authorize_request_id) {
    const bool accepted = (d["result"] | false) && d["error"].isNull();
    add_pool_log(accepted ? "Pool authorization accepted" : "ERROR: Pool authorization rejected");
    authorize_request_id = 0;
    return;
  }
  if (!d["id"].isNull()) {
    String detail;
    const bool failed = !d["error"].isNull();
    if (failed) serializeJson(d["error"], detail); else serializeJson(d["result"], detail);
    add_pool_log(String(failed ? "ERROR: Pool reply #" : "Pool reply #") + String(d["id"].as<uint32_t>()) + ": " + detail);
    return;
  }
  const char *method = d["method"] | ""; JsonVariant params = d["params"];
  pool_last_message = method;
  if (!d["error"].isNull()) { String detail; serializeJson(d["error"], detail); add_pool_log(String("ERROR: Pool message ") + (method[0] ? method : "without method") + ": " + detail); return; }
  if (!strcmp(method, "mining.set_difficulty")) { pool_difficulty = String(params[0].as<double>(), 6); if (settings.pow_mode == POW_SIA) set_sia_stratum_target(pool_difficulty.toDouble()); else set_pyblock_blake2b_target(pool_difficulty.toDouble()); portENTER_CRITICAL(&mining_mux); memcpy(worker_job.target, target, sizeof(target)); portEXIT_CRITICAL(&mining_mux); add_pool_log(String("Pool set difficulty to ") + pool_difficulty); return; }
  if (!strcmp(method, "mining.set_extranonce")) { stratum_extranonce1 = params[0] | ""; stratum_extranonce2_size = params[1] | 0; add_pool_log(String("Pool changed extranonce: ") + stratum_extranonce1); return; }
  if (!strcmp(method, "client.show_message")) { pool_server_message = params[0] | ""; add_pool_log(String("Pool says: ") + pool_server_message); return; }
  // Supported pool notification forms: {params:[jobId,headerHex,targetHex]}
  // or {params:{id,header,target}}. Extend here if a pool uses another format.
  if (!strcmp(method, "mining.notify")) {
    bool ok;
    if (params.is<JsonArray>()) {
      JsonArray array = params.as<JsonArray>();
      if (array.size() >= 9) { stratum_version = array[5] | ""; stratum_nbits = array[6] | ""; stratum_ntime = array[7] | ""; }
      ok = settings.pow_mode == POW_PYBLOCK_BLAKE2B ? set_pyblock_blake2b_job(array) : settings.pow_mode == POW_SIA && array.size() >= 9 ? set_f2pool_sia_job(array) : set_job(array[0].as<const char *>(), array[1].as<const char *>(), array[2].as<const char *>());
    } else {
      ok = set_job(params["id"].as<const char *>(), params["header"].as<const char *>(), params["target"].as<const char *>());
    }
    if (!ok) { Serial.print("ignored notify: "); Serial.println(last_template_error.length() ? last_template_error : "Stratum fields are incomplete or malformed"); add_pool_log(String("ERROR: Rejected invalid template notification: ") + (last_template_error.length() ? last_template_error : "Stratum fields are incomplete or malformed")); }
  } else if (method[0]) { String detail; serializeJson(params, detail); add_pool_log(String("Pool message ") + method + ": " + detail); }
  else add_pool_log(String("Pool message: ") + line);
}
void service_pool() {
  if (!pool.connected()) {
    if (pool_was_connected) {
      Serial.println("Pool connection closed"); add_pool_log("Pool connection closed");
      // A session that never got a single reply looks like the pool (or something upstream) is
      // rejecting/rate-limiting us - back off harder so we don't keep hammering it. Any real
      // reply means the pool is talking to us, so a normal disconnect (e.g. idle timeout) just
      // retries at the base interval.
      if (!session_got_reply) { reconnect_backoff_ms = min(reconnect_backoff_ms * 2, RECONNECT_BACKOFF_MAX_MS); Serial.print("No reply this session; backing off to "); Serial.print(reconnect_backoff_ms / 1000); Serial.println("s"); }
      else reconnect_backoff_ms = RECONNECT_BACKOFF_MIN_MS;
    }
    pool_was_connected = false;
    if (millis() - last_connect_attempt < reconnect_backoff_ms) return;
    last_connect_attempt = millis(); ++pool_connection_attempts; session_got_reply = false;
    Serial.print("Connecting to "); Serial.print(settings.pool_host); Serial.print(":"); Serial.print(settings.pool_port);
    Serial.print(" mode="); Serial.print(settings.pow_mode); Serial.print(" wifi="); Serial.println(WiFi.status() == WL_CONNECTED ? "up" : "down");
    if (pool.connect(settings.pool_host.c_str(), settings.pool_port)) {
      pool_was_connected = true; pool_connected_since = millis(); ++pool_sessions;
      Serial.println("Connected"); add_pool_log(String("Connected to ") + settings.pool_host + ":" + String(settings.pool_port));
      subscribe();
    } else { Serial.println("Connection attempt failed"); add_pool_log(String("Connection attempt failed: ") + settings.pool_host + ":" + String(settings.pool_port)); }
    return;
  }
  while (pool.available()) { String line = pool.readStringUntil('\n'); if (line.length()) { session_got_reply = true; process_line(line); } }
}
void mine_slice() {
  if (!header_len) return;
  const bool pyblock = settings.pow_mode == POW_PYBLOCK_BLAKE2B;
  const uint16_t nonce_offset = 32;
  const uint8_t nonce_size = pyblock ? 4 : 8;
  for (unsigned i = 0; i < 256; ++i) {
    uint64_t n = nonce++;
    for (unsigned b = 0; b < nonce_size; ++b) header[nonce_offset + b] = uint8_t(n >> (8 * b)); // Bitcoin-style little-endian nonce
    uint8_t hash[32];
    if (pyblock) pyblock_blake2b_pow(header, hash);
    else blake2b_256(header, header_len, hash);
    add_hashes(1);
    if (meets_target(hash)) submit_share(n, hash);
  }
}
void miner_worker(void *) {
  WorkerJob local{}; uint32_t generation = 0; uint64_t worker_nonce = esp_random() ^ 0x80000000ULL;
  for (;;) {
    if (portal_active) { vTaskDelay(5); continue; }
    portENTER_CRITICAL(&mining_mux);
    if (worker_job.generation != generation) { local = worker_job; generation = worker_job.generation; worker_nonce = esp_random() ^ 0x80000000ULL; }
    portEXIT_CRITICAL(&mining_mux);
    if (!local.header_len) { vTaskDelay(1); continue; }
    for (unsigned i = 0; i < 4096; ++i) {
      const uint64_t n = worker_nonce++;
      for (unsigned b = 0; b < local.nonce_size; ++b) local.header[local.nonce_offset + b] = uint8_t(n >> (8 * b));
      uint8_t hash[32];
      if (local.mode == POW_PYBLOCK_BLAKE2B) pyblock_blake2b_pow(local.header, hash); else blake2b_256(local.header, local.header_len, hash);
      if (meets_target(hash, local.target) && found_shares) { FoundShare share{n, {}, generation}; memcpy(share.hash, hash, sizeof(hash)); xQueueSend(found_shares, &share, 0); }
    }
    add_hashes(4096);
    vTaskDelay(1); // Leave core 0 time for Wi-Fi and the web server transport.
  }
}
void service_found_shares() {
  FoundShare share;
  while (found_shares && xQueueReceive(found_shares, &share, 0) == pdTRUE) {
    portENTER_CRITICAL(&mining_mux); const bool current = share.generation == worker_job.generation; portEXIT_CRITICAL(&mining_mux);
    if (current) submit_share(share.nonce, share.hash);
  }
}
} // namespace

#ifndef UNIT_TEST
void setup() {
  Serial.begin(115200); pinMode(STATUS_LED_PIN, OUTPUT); digitalWrite(STATUS_LED_PIN, LOW); delay(200); load_settings();
  Serial.print("Loaded settings: device="); Serial.print(settings.device_name);
  Serial.print(" host="); Serial.print(settings.pool_host); Serial.print(":"); Serial.print(settings.pool_port);
  Serial.print(" user="); Serial.print(settings.pool_username);
  Serial.print(" pow_mode="); Serial.print(settings.pow_mode);
  Serial.print(" valid="); Serial.println(valid_settings(settings) ? "yes" : "no");
  found_shares = xQueueCreate(8, sizeof(FoundShare));
  xTaskCreatePinnedToCore(miner_worker, "miner-worker", 4096, nullptr, 1, nullptr, 0);
  pinMode(CONFIG_BUTTON_PIN, INPUT_PULLUP);
  if (digitalRead(CONFIG_BUTTON_PIN) == LOW || !valid_settings(settings) || !connect_wifi()) start_portal();
  else { start_mdns(); configure_web_server(); Serial.printf("Configuration page: http://%s\n", WiFi.localIP().toString().c_str()); }
}
void loop() {
  web.handleClient();
  websocket.loop();
  if (restart_requested) { delay(100); ESP.restart(); }
  service_status_led();
  service_dashboard();
  if (portal_active) { dns.processNextRequest(); return; }
  service_pool(); service_found_shares(); mine_slice();
  const uint32_t now = millis();
  if (now - last_report > 5000) {
    const uint64_t total_hashes = hash_count();
    const uint64_t delta = total_hashes - last_report_hashes;
    current_hashrate = delta * 1000.0 / (now - last_report);
    last_report_hashes = total_hashes;
    last_report = now;
    Serial.print("heartbeat: pool="); Serial.print(pool.connected() ? "up" : "down");
    Serial.print(" header_len="); Serial.print(header_len);
    Serial.print(" job="); Serial.print(job_id);
    Serial.print(" rate="); Serial.print(current_hashrate);
    Serial.print(" H/s submitted="); Serial.print(shares_submitted);
    Serial.print(" accepted="); Serial.print(shares_accepted);
    Serial.print(" rejected="); Serial.println(shares_rejected);
  }
}
#endif
