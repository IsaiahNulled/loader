#pragma once
// Embedded HTML UI for the web-based loader.
// Split into chunks with custom raw string delimiters to avoid MSVC limits.

#include <fstream>
#include <string>

static bool WriteLoaderHTML(const std::wstring& path) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;

    // ── Chunk 1: Head + CSS part 1 ──
    f << R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Jew Ware</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#0a0a0f;height:100vh;overflow:hidden;display:flex;align-items:center;justify-content:center;user-select:none}
input,button,select{-webkit-app-region:no-drag}
#rain-canvas{position:fixed;top:0;left:0;width:100%;height:100%;z-index:0;pointer-events:none}
.lightning-flash{position:fixed;top:0;left:0;width:100%;height:100%;z-index:1;pointer-events:none;background:white;opacity:0}
.lightning-flash.strike{animation:lightningStrike .3s ease-out}
@keyframes lightningStrike{0%{opacity:0}5%{opacity:.8}10%{opacity:.1}15%{opacity:.6}20%{opacity:0}25%{opacity:.4}30%{opacity:0}100%{opacity:0}}
.ambient-glow{position:fixed;width:600px;height:600px;border-radius:50%;filter:blur(120px);z-index:0;pointer-events:none}
.glow-1{top:-200px;left:-100px;background:rgba(139,92,246,.08);animation:gp1 8s ease-in-out infinite}
.glow-2{bottom:-200px;right:-100px;background:rgba(59,130,246,.06);animation:gp2 10s ease-in-out infinite}
@keyframes gp1{0%,100%{opacity:.4;transform:scale(1)}50%{opacity:.7;transform:scale(1.1)}}
@keyframes gp2{0%,100%{opacity:.3;transform:scale(1)}50%{opacity:.6;transform:scale(1.15)}}
.window-controls{position:fixed;top:8px;right:10px;z-index:100;display:flex;gap:6px}
.wc-btn{width:28px;height:28px;border:none;border-radius:6px;background:rgba(255,255,255,.05);color:rgba(255,255,255,.4);font-size:14px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s}
.wc-btn:hover{background:rgba(255,255,255,.1);color:rgba(255,255,255,.7)}
.wc-btn.close:hover{background:rgba(239,68,68,.3);color:#fca5a5}
.screen{display:none;position:relative;z-index:10;width:400px;animation:cardIn .6s cubic-bezier(.16,1,.3,1)}
.screen.active{display:block}
@keyframes cardIn{0%{opacity:0;transform:translateY(24px) scale(.97)}100%{opacity:1;transform:translateY(0) scale(1)}}
)HTM";

    // ── Chunk 2: CSS part 2 ──
    f << R"HTM(.card{background:rgba(15,15,25,.85);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,.06);border-radius:16px;padding:36px 32px;box-shadow:0 0 0 1px rgba(139,92,246,.05),0 20px 60px rgba(0,0,0,.5),0 0 80px rgba(139,92,246,.03)}
.brand{text-align:center;margin-bottom:28px}
.brand-icon{width:48px;height:48px;margin:0 auto 14px;background:linear-gradient(135deg,#8b5cf6,#6366f1);border-radius:12px;display:flex;align-items:center;justify-content:center;box-shadow:0 8px 24px rgba(139,92,246,.3);animation:iconPulse 3s ease-in-out infinite}
@keyframes iconPulse{0%,100%{box-shadow:0 8px 24px rgba(139,92,246,.3)}50%{box-shadow:0 8px 32px rgba(139,92,246,.5)}}
.brand-icon svg{width:24px;height:24px;fill:white}
.brand h1{font-size:22px;font-weight:600;color:#fff;letter-spacing:-.02em}
.brand h1 span{color:#c084fc}
.brand p{font-size:13px;color:rgba(255,255,255,.35);margin-top:5px}
.form-group{margin-bottom:18px}
.form-group label{display:block;font-size:12px;font-weight:500;color:rgba(255,255,255,.5);margin-bottom:7px;text-transform:uppercase;letter-spacing:.05em}
.input-wrapper{position:relative}
.input-wrapper input{width:100%;padding:12px 16px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:10px;color:#fff;font-size:14px;font-family:'Inter',sans-serif;outline:none;transition:all .25s}
.input-wrapper input::placeholder{color:rgba(255,255,255,.2)}
.input-wrapper input:focus{border-color:rgba(139,92,246,.5);background:rgba(139,92,246,.04);box-shadow:0 0 0 3px rgba(139,92,246,.1)}
.submit-btn{width:100%;padding:13px;background:linear-gradient(135deg,#8b5cf6,#6366f1);border:none;border-radius:10px;color:white;font-size:14px;font-weight:600;font-family:'Inter',sans-serif;cursor:pointer;transition:all .25s;position:relative;overflow:hidden}
.submit-btn:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(139,92,246,.4)}
.submit-btn:active{transform:translateY(0)}
.submit-btn:disabled{opacity:.5;cursor:not-allowed;transform:none!important;box-shadow:none!important}
.submit-btn::after{content:'';position:absolute;top:0;left:-100%;width:100%;height:100%;background:linear-gradient(90deg,transparent,rgba(255,255,255,.15),transparent);transition:left .5s}
.submit-btn:hover::after{left:100%}
.error-msg{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.2);border-radius:8px;padding:10px 14px;margin-bottom:18px;font-size:13px;color:#fca5a5;text-align:center;animation:errShake .4s ease}
@keyframes errShake{0%,100%{transform:translateX(0)}20%{transform:translateX(-6px)}40%{transform:translateX(6px)}60%{transform:translateX(-4px)}80%{transform:translateX(4px)}}
.footer{text-align:center;margin-top:18px;font-size:11px;color:rgba(255,255,255,.15)}
)HTM";

    // ── Chunk 3: CSS part 3 ──
    f << R"HTM(.build-cards{display:flex;gap:12px;margin-bottom:20px}
.build-card{flex:1;padding:20px 16px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:12px;cursor:pointer;transition:all .2s;text-align:center}
.build-card:hover{border-color:rgba(139,92,246,.3);background:rgba(139,92,246,.04)}
.build-card.lite.selected{border-color:rgba(74,222,128,.5);background:rgba(74,222,128,.06);box-shadow:0 0 20px rgba(74,222,128,.1)}
.build-card.full.selected{border-color:rgba(250,204,21,.5);background:rgba(250,204,21,.06);box-shadow:0 0 20px rgba(250,204,21,.1)}
.build-card h3{font-size:15px;font-weight:600;color:#fff;margin-bottom:4px}
.build-card .build-tag{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600;margin-bottom:8px}
.build-card.lite .build-tag{background:rgba(74,222,128,.12);color:#4ade80}
.build-card.full .build-tag{background:rgba(250,204,21,.12);color:#facc15}
.build-card p{font-size:11px;color:rgba(255,255,255,.35);line-height:1.5}
.progress-section{margin:20px 0}
.progress-bar-bg{width:100%;height:6px;background:rgba(255,255,255,.06);border-radius:3px;overflow:hidden}
.progress-bar-fill{height:100%;background:linear-gradient(90deg,#8b5cf6,#6366f1);border-radius:3px;transition:width .3s ease;width:0%}
.progress-text{display:flex;justify-content:space-between;margin-top:8px;font-size:11px;color:rgba(255,255,255,.4)}
.status-line{font-size:13px;color:rgba(255,255,255,.6);text-align:center;margin-top:16px}
.status-line .dot{display:inline-block;width:6px;height:6px;border-radius:50%;margin-right:6px;vertical-align:middle}
.dot-green{background:#4ade80;box-shadow:0 0 8px rgba(74,222,128,.5)}
.dot-yellow{background:#facc15;box-shadow:0 0 8px rgba(250,204,21,.5)}
.dot-red{background:#f87171;box-shadow:0 0 8px rgba(248,113,113,.5)}
.dot-purple{background:#a78bfa;box-shadow:0 0 8px rgba(167,139,250,.5)}
.done-icon{width:64px;height:64px;margin:0 auto 16px;background:rgba(74,222,128,.1);border:2px solid rgba(74,222,128,.3);border-radius:50%;display:flex;align-items:center;justify-content:center}
.done-icon svg{width:32px;height:32px;stroke:#4ade80;fill:none;stroke-width:2.5}
.spinner{display:inline-block;width:16px;height:16px;border:2px solid rgba(255,255,255,.2);border-top-color:#a78bfa;border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle;margin-right:8px}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="ambient-glow glow-1"></div>
<div class="ambient-glow glow-2"></div>
<canvas id="rain-canvas"></canvas>
<div class="lightning-flash" id="lightning-flash"></div>
)HTM";

    // ── Chunk 4: HTML screens part 1 ──
    f << R"HTM(<div class="window-controls">
  <button class="wc-btn" onclick="sendMsg({action:'minimize'})" title="Minimize">&#x2013;</button>
  <button class="wc-btn close" onclick="sendMsg({action:'close'})" title="Close">&#x2715;</button>
</div>

<div class="screen active" id="screen-auth">
  <div class="card">
    <div class="brand">
      <div class="brand-icon"><svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v4.7c0 4.83-3.4 9.37-7 10.5-3.6-1.13-7-5.67-7-10.5V6.3l7-3.12z"/></svg></div>
      <h1>Jew <span>Ware</span></h1>
      <p>Enter your license key to continue</p>
    </div>
    <div id="auth-error" class="error-msg" style="display:none"></div>
    <div class="form-group">
      <label>License Key</label>
      <div class="input-wrapper">
        <input type="text" id="key-input" placeholder="EXT-XXXX-XXXX-XXXX" autocomplete="off" spellcheck="false">
      </div>
    </div>
    <button class="submit-btn" id="auth-btn" onclick="doAuth()">Authenticate</button>
    <div class="footer">Secured Connection &middot; HMAC Signed</div>
  </div>
</div>

<div class="screen" id="screen-build">
  <div class="card">
    <div class="brand">
      <div class="brand-icon"><svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v4.7c0 4.83-3.4 9.37-7 10.5-3.6-1.13-7-5.67-7-10.5V6.3l7-3.12z"/></svg></div>
      <h1>Select <span>Build</span></h1>
      <p>Choose your feature set</p>
    </div>
    <div class="build-cards">
      <div class="build-card lite" onclick="selectBuild('safe',this)">
        <span class="build-tag">LITE</span>
        <h3>Read-Only</h3>
        <p>ESP and visual features only.<br>Lower detection risk.</p>
      </div>
      <div class="build-card full" onclick="selectBuild('full',this)">
        <span class="build-tag">FULL</span>
        <h3>All Features</h3>
        <p>Aimbot, no recoil, chams.<br>Higher detection risk.</p>
      </div>
    </div>
    <button class="submit-btn" id="build-btn" onclick="confirmBuild()" disabled>Continue</button>
    <div class="footer" id="auth-info"></div>
  </div>
</div>
)HTM";

    // ── Chunk 5: Progress + Done + Error screens ──
    f << R"HTM(<div class="screen" id="screen-progress">
  <div class="card">
    <div class="brand">
      <div class="brand-icon"><svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v4.7c0 4.83-3.4 9.37-7 10.5-3.6-1.13-7-5.67-7-10.5V6.3l7-3.12z"/></svg></div>
      <h1>Jew <span>Ware</span></h1>
      <p id="progress-subtitle">Preparing...</p>
    </div>
    <div class="progress-section">
      <div class="progress-bar-bg"><div class="progress-bar-fill" id="progress-fill"></div></div>
      <div class="progress-text"><span id="progress-label">Initializing...</span><span id="progress-pct">0%</span></div>
    </div>
    <div class="status-line" id="status-line"><span class="dot dot-purple"></span>Connecting...</div>
  </div>
</div>

<div class="screen" id="screen-done">
  <div class="card" style="text-align:center">
    <div class="done-icon"><svg viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg></div>
    <h2 style="color:#fff;font-size:20px;margin-bottom:6px">Injection Complete</h2>
    <p style="color:rgba(255,255,255,.4);font-size:13px;margin-bottom:20px">You may close this window. Enjoy!</p>
    <button class="submit-btn" onclick="sendMsg({action:'close'})" style="max-width:200px;margin:0 auto">Close</button>
  </div>
</div>

<div class="screen" id="screen-error">
  <div class="card" style="text-align:center">
    <div class="done-icon" style="background:rgba(248,113,113,.1);border-color:rgba(248,113,113,.3)">
      <svg viewBox="0 0 24 24" stroke="#f87171" fill="none" stroke-width="2.5" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </div>
    <h2 style="color:#fff;font-size:20px;margin-bottom:6px">Something went wrong</h2>
    <p id="error-detail" style="color:rgba(255,255,255,.4);font-size:13px;margin-bottom:20px"></p>
    <button class="submit-btn" onclick="showScreen('screen-auth')" style="max-width:200px;margin:0 auto">Try Again</button>
  </div>
</div>
)HTM";

    // ── Chunk 6: App logic JS ──
    f << R"HTM(<script>
var selectedBuild = '';
function sendMsg(obj) {
  if (window.chrome && window.chrome.webview)
    window.chrome.webview.postMessage(JSON.stringify(obj));
}
function showScreen(id) {
  var screens = document.querySelectorAll('.screen');
  for (var i = 0; i < screens.length; i++) screens[i].classList.remove('active');
  document.getElementById(id).classList.add('active');
}
function doAuth() {
  var key = document.getElementById('key-input').value.trim();
  if (!key) return;
  document.getElementById('auth-btn').disabled = true;
  document.getElementById('auth-btn').innerHTML = '<span class="spinner"></span>Authenticating...';
  document.getElementById('auth-error').style.display = 'none';
  sendMsg({action: 'auth', key: key});
}
function selectBuild(build, el) {
  selectedBuild = build;
  var cards = document.querySelectorAll('.build-card');
  for (var i = 0; i < cards.length; i++) cards[i].classList.remove('selected');
  el.classList.add('selected');
  document.getElementById('build-btn').disabled = false;
}
function confirmBuild() {
  if (!selectedBuild) return;
  document.getElementById('build-btn').disabled = true;
  document.getElementById('build-btn').innerHTML = '<span class="spinner"></span>Starting...';
  sendMsg({action: 'select-build', build: selectedBuild});
}
if (window.chrome && window.chrome.webview) {
  window.chrome.webview.addEventListener('message', function(e) {
    var msg = JSON.parse(e.data);
    if (msg.type === 'auth-success') {
      document.getElementById('auth-info').textContent = 'Expires: ' + (msg.expiry || 'N/A');
      showScreen('screen-build');
    } else if (msg.type === 'auth-fail') {
      document.getElementById('auth-error').textContent = msg.message || 'Authentication failed';
      document.getElementById('auth-error').style.display = 'block';
      document.getElementById('auth-btn').disabled = false;
      document.getElementById('auth-btn').textContent = 'Authenticate';
    } else if (msg.type === 'progress') {
      showScreen('screen-progress');
      document.getElementById('progress-fill').style.width = msg.pct + '%';
      document.getElementById('progress-pct').textContent = msg.pct + '%';
      if (msg.label) document.getElementById('progress-label').textContent = msg.label;
      if (msg.status) document.getElementById('status-line').innerHTML =
        '<span class="dot dot-' + (msg.dot||'purple') + '"></span>' + msg.status;
      if (msg.subtitle) document.getElementById('progress-subtitle').textContent = msg.subtitle;
    } else if (msg.type === 'done') {
      showScreen('screen-done');
    } else if (msg.type === 'error') {
      document.getElementById('error-detail').textContent = msg.message || 'Unknown error';
      showScreen('screen-error');
    }
  });
}
document.getElementById('key-input').addEventListener('keydown', function(e) {
  if (e.key === 'Enter') doAuth();
});
</script>
)HTM";

    // ── Chunk 7: Rain effect JS ──
    f << R"HTM(<script>
var canvas = document.getElementById('rain-canvas');
var ctx = canvas.getContext('2d');
var W, H;
function resize() { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; }
resize(); window.addEventListener('resize', resize);
function Drop() { this.reset(true); }
Drop.prototype.reset = function(init) {
  this.x = Math.random() * W; this.y = init ? Math.random() * -H : -10;
  this.len = 12 + Math.random() * 20; this.speed = 8 + Math.random() * 12;
  this.opacity = 0.05 + Math.random() * 0.15; this.width = 0.5 + Math.random() * 0.8;
};
Drop.prototype.update = function() { this.y += this.speed; if (this.y > H + this.len) this.reset(false); };
Drop.prototype.draw = function() {
  ctx.beginPath(); ctx.moveTo(this.x, this.y); ctx.lineTo(this.x + 0.5, this.y - this.len);
  ctx.strokeStyle = 'rgba(174,194,224,' + this.opacity + ')'; ctx.lineWidth = this.width; ctx.stroke();
};
var drops = []; for (var i = 0; i < 250; i++) drops.push(new Drop());
function Splash(x, y) { this.x=x;this.y=y;this.vx=(Math.random()-.5)*2;this.vy=-Math.random()*2-.5;this.life=1;this.decay=.03+Math.random()*.04; }
Splash.prototype.update = function() { this.x+=this.vx;this.y+=this.vy;this.vy+=.08;this.life-=this.decay; };
Splash.prototype.draw = function() { if(this.life<=0)return;ctx.beginPath();ctx.arc(this.x,this.y,.8,0,Math.PI*2);ctx.fillStyle='rgba(174,194,224,'+this.life*.3+')';ctx.fill(); };
var splashes = [];
var activeBolt = null, boltAlpha = 0;
var flashEl = document.getElementById('lightning-flash');
</script>
)HTM";

    // ── Chunk 8: Lightning + animation loop JS ──
    f << R"HTM(<script>
function generateBolt(sx, sy, ey) {
  var pts=[{x:sx,y:sy}], x=sx, y=sy, segs=12+Math.floor(Math.random()*8), step=(ey-sy)/segs;
  for(var i=0;i<segs;i++){x+=(Math.random()-.5)*80;y+=step+(Math.random()-.5)*10;pts.push({x:x,y:y});
    if(Math.random()<.3){var bx=x,by=y,bl=2+Math.floor(Math.random()*3),bp=[{x:bx,y:by}];
      for(var j=0;j<bl;j++){bx+=(Math.random()-.5)*60;by+=step*.6;bp.push({x:bx,y:by});}pts.push({branch:bp});}}
  return pts;
}
function drawBolt(pts,a){
  ctx.save();ctx.globalCompositeOperation='lighter';
  function ds(p,w,c){ctx.beginPath();ctx.moveTo(p[0].x,p[0].y);for(var i=1;i<p.length;i++){if(p[i].branch)continue;ctx.lineTo(p[i].x,p[i].y);}ctx.strokeStyle=c;ctx.lineWidth=w;ctx.shadowColor='rgba(180,200,255,.8)';ctx.shadowBlur=w*8;ctx.stroke();}
  ds(pts,6,'rgba(100,150,255,'+a*.15+')');ds(pts,3,'rgba(180,200,255,'+a*.4+')');ds(pts,1.2,'rgba(255,255,255,'+a*.9+')');
  for(var k=0;k<pts.length;k++){if(pts[k].branch){ctx.beginPath();ctx.moveTo(pts[k].branch[0].x,pts[k].branch[0].y);for(var j=1;j<pts[k].branch.length;j++)ctx.lineTo(pts[k].branch[j].x,pts[k].branch[j].y);ctx.strokeStyle='rgba(180,200,255,'+a*.3+')';ctx.lineWidth=.8;ctx.shadowBlur=6;ctx.stroke();}}
  ctx.restore();
}
function triggerLightning(){
  var sx=W*.2+Math.random()*W*.6;activeBolt=generateBolt(sx,-20,H*(.4+Math.random()*.3));boltAlpha=1;
  flashEl.classList.remove('strike');void flashEl.offsetWidth;flashEl.classList.add('strike');
  var fd=setInterval(function(){boltAlpha-=.06;if(boltAlpha<=0){boltAlpha=0;activeBolt=null;clearInterval(fd);}},16);
  if(Math.random()<.4)setTimeout(function(){activeBolt=generateBolt(sx+(Math.random()-.5)*40,-20,H*(.3+Math.random()*.4));boltAlpha=.8;flashEl.classList.remove('strike');void flashEl.offsetWidth;flashEl.classList.add('strike');},120+Math.random()*80);
}
function animate(){
  ctx.clearRect(0,0,W,H);
  for(var i=0;i<drops.length;i++){var d=drops[i],wa=d.y<H;d.update();d.draw();if(wa&&d.y>=H&&Math.random()<.3)for(var s=0;s<3;s++)splashes.push(new Splash(d.x,H));}
  var ns=[];for(var i=0;i<splashes.length;i++){if(splashes[i].life>0){splashes[i].update();splashes[i].draw();ns.push(splashes[i]);}}splashes=ns;
  if(activeBolt&&boltAlpha>0)drawBolt(activeBolt,boltAlpha);
  requestAnimationFrame(animate);
}
animate();
function schedLightning(){setTimeout(function(){triggerLightning();schedLightning();},4000+Math.random()*8000);}
setTimeout(function(){triggerLightning();schedLightning();},2000+Math.random()*3000);
setTimeout(function(){document.getElementById('key-input').focus();},500);
</script>
</body>
</html>)HTM";

    f.close();
    return true;
}
