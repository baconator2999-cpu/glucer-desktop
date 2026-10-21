/* Glucer Agent: lets Glucer work with files, apps, your screen and clipboard on this computer.
   Website version:  node glucer-agent.js     (add --strict to approve in this window instead of in Glucer)
   Desktop app:      loaded by the app itself (no server, nothing to run).                                  */
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { exec, execFile, execSync, spawn } = require('child_process');

const IS_ELECTRON = !!process.versions.electron;
const AS_SERVER = require.main === module;
const STRICT = AS_SERVER && process.argv.includes('--strict');
const PORT = 4777;
const HOME = os.homedir();
const DATA_DIR = path.join(HOME, '.glucer');
const ALLOWED_ORIGINS = ['https://glucer.com', 'https://www.glucer.com', 'https://glucer.pages.dev', 'https://glucer.netlify.app'];

/* ---------- Small helpers ---------- */
function lib(name, spec) {
  try { return require(name); } catch (e) {}
  if (IS_ELECTRON) throw new Error('A part of Glucer (' + name + ') is missing. Please reinstall the Glucer app.');
  console.log('Installing a helper (' + spec + '), one moment...');
  try {
    execSync('npm install --prefix "' + __dirname + '" ' + spec + ' --no-audit --no-fund --loglevel=error', { stdio: 'inherit' });
    return require(name);
  } catch (e) { throw new Error('Could not install ' + spec + '. Check your internet connection and try again.'); }
}
const ok = (result, summary, extra) => Object.assign({ ok: true, result, summary }, extra || {});
class Denied extends Error {}
const short = (full) => (full.startsWith(HOME) ? '~' + full.slice(HOME.length) : full);
const newId = () => crypto.randomBytes(6).toString('hex');
const arr = (v) => (Array.isArray(v) ? v : []).slice(0, 200);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const runCmd = (cmd, args, opts) => new Promise((resolve, reject) => {
  execFile(cmd, args, Object.assign({ maxBuffer: 20 * 1024 * 1024 }, opts || {}), (err, stdout) => (err ? reject(err) : resolve(String(stdout))));
});

/* ---------- Protected places (always ask first) ---------- */
const SENSITIVE_DIRS = [
  '.ssh', '.gnupg', '.aws', '.azure', '.kube', '.config/gcloud', '.mozilla', '.config/google-chrome', '.glucer',
  'AppData/Roaming/Mozilla', 'AppData/Local/Google/Chrome', 'AppData/Local/Microsoft/Edge',
  'AppData/Roaming/Microsoft/Credentials', 'Library/Keychains',
  'Library/Application Support/Google/Chrome', 'Library/Application Support/Firefox'
].map((s) => path.join(HOME, ...s.split('/')).toLowerCase());
const SENSITIVE_NAMES = /^(\.env.*|id_rsa.*|id_ed25519.*|.*\.pem|.*\.key|.*\.kdbx|.*\.pfx|.*\.p12)$/i;
function isSensitive(full) {
  const low = full.toLowerCase();
  if (SENSITIVE_NAMES.test(path.basename(full))) return true;
  return SENSITIVE_DIRS.some((d) => low === d || low.startsWith(d + path.sep));
}
const gate = (fulls) => {
  const bad = fulls.filter(isSensitive);
  return bad.length ? { lines: ['Look inside a protected place: ' + bad.map(short).join(', ')], risk: 'high' } : {};
};
const sens = (fulls) => (fulls.some(isSensitive) ? 'high' : undefined);

/* ---------- Paths ---------- */
const KNOWN = ['desktop', 'documents', 'downloads', 'pictures', 'music', 'videos'];
function resolveP(p) {
  p = String(p == null ? '.' : p).trim() || '.';
  if (p === '~') p = '.'; else if (/^~[\\/]/.test(p)) p = p.slice(2);
  let full = path.resolve(HOME, p);
  const rel = path.relative(HOME, full);
  const first = rel.split(path.sep)[0];
  // Windows often keeps Desktop/Documents inside OneDrive
  if (rel && !rel.startsWith('..') && KNOWN.includes(first.toLowerCase()) && !fs.existsSync(path.join(HOME, first)) && fs.existsSync(path.join(HOME, 'OneDrive', first))) {
    full = path.join(HOME, 'OneDrive', rel);
  }
  return full;
}

/* ---------- Undo history and activity log ---------- */
const HIST_FILE = path.join(DATA_DIR, 'history.json');
const ACT_FILE = path.join(DATA_DIR, 'activity.jsonl');
function loadHist() { try { return JSON.parse(fs.readFileSync(HIST_FILE, 'utf8')); } catch (e) { return []; } }
function saveHist(h) { try { fs.mkdirSync(DATA_DIR, { recursive: true }); fs.writeFileSync(HIST_FILE, JSON.stringify(h.slice(-200))); } catch (e) {} }
function logOp(op) { op.id = op.id || newId(); op.time = Date.now(); const h = loadHist(); h.push(op); saveHist(h); return op.id; }
function logActivity(entry) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.appendFileSync(ACT_FILE, JSON.stringify(entry) + '\n');
    if (fs.statSync(ACT_FILE).size > 600000) {
      const lines = fs.readFileSync(ACT_FILE, 'utf8').trim().split('\n');
      fs.writeFileSync(ACT_FILE, lines.slice(-800).join('\n') + '\n');
    }
  } catch (e) {}
}
function readActivity(n) {
  try { return fs.readFileSync(ACT_FILE, 'utf8').trim().split('\n').slice(-n).map((l) => JSON.parse(l)).reverse(); } catch (e) { return []; }
}

function movePath(from, to) {
  try { fs.renameSync(from, to); }
  catch (e) {
    if (e.code !== 'EXDEV') throw e;
    fs.cpSync(from, to, { recursive: true });
    fs.rmSync(from, { recursive: true });
  }
}
function trashOne(full) {
  return new Promise((resolve, reject) => {
    const done = (err) => (err ? reject(new Error('Could not move to the Trash: ' + short(full))) : resolve());
    if (process.platform === 'win32') {
      const fn = fs.statSync(full).isDirectory() ? 'DeleteDirectory' : 'DeleteFile';
      const script = "Add-Type -AssemblyName Microsoft.VisualBasic; [Microsoft.VisualBasic.FileIO.FileSystem]::" + fn + "($env:GLUCER_P,'OnlyErrorDialogs','SendToRecycleBin')";
      execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { env: Object.assign({}, process.env, { GLUCER_P: full }) }, done);
    } else if (process.platform === 'darwin') {
      execFile('osascript', ['-e', 'on run argv', '-e', 'tell application "Finder" to delete (POSIX file (item 1 of argv))', '-e', 'end run', full], done);
    } else {
      execFile('gio', ['trash', full], done);
    }
  });
}

async function undoOp(id) {
  const hist = loadHist();
  const op = hist.find((o) => o.id === id);
  if (!op) throw new Error('That action is too old to undo.');
  if (op.undone) throw new Error('That was already undone.');
  let n = 0;
  const problems = [];
  if (op.kind === 'move') {
    for (const m of op.moves.slice().reverse()) {
      try {
        if (!fs.existsSync(m.to)) throw new Error('Not found: ' + short(m.to));
        if (fs.existsSync(m.from)) throw new Error('Something is already at ' + short(m.from));
        fs.mkdirSync(path.dirname(m.from), { recursive: true });
        movePath(m.to, m.from); n++;
      } catch (e) { problems.push(e.message); }
    }
  } else if (op.kind === 'copy') {
    for (const c of op.created) { try { if (fs.existsSync(c)) { await trashOne(c); n++; } } catch (e) { problems.push(e.message); } }
  } else if (op.kind === 'mkdir') {
    for (const d of op.created.slice().sort((a, b) => b.length - a.length)) {
      try { fs.rmdirSync(d); n++; } catch (e) { problems.push('Kept (not empty): ' + short(d)); }
    }
  } else if (op.kind === 'write') {
    try {
      if (op.backup) { fs.copyFileSync(op.backup, op.path); n++; }
      else if (fs.existsSync(op.path)) { await trashOne(op.path); n++; }
    } catch (e) { problems.push(e.message); }
  }
  if (!n && problems.length) return { ok: false, error: problems[0], summary: problems[0] };
  op.undone = true; saveHist(hist);
  return { ok: true, result: { undone: n, problems }, summary: 'Undone (' + n + ' item' + (n === 1 ? '' : 's') + ')' + (problems.length ? ', ' + problems.length + ' couldn\'t be undone' : '') };
}

/* ---------- Screen and clipboard ---------- */
let lastShot = null; // most recent screenshot, used to convert mouse coordinates
async function takeScreenshot() {
  if (IS_ELECTRON) {
    const { desktopCapturer, screen } = require('electron');
    const d = screen.getPrimaryDisplay();
    const w = Math.min(1600, Math.round(d.size.width * d.scaleFactor));
    const h = Math.round(w * d.size.height / d.size.width);
    const sources = await desktopCapturer.getSources({ types: ['screen'], thumbnailSize: { width: w, height: h } });
    const src = sources.find((s) => s.display_id === String(d.id)) || sources[0];
    if (!src || src.thumbnail.isEmpty()) throw new Error('Could not capture the screen.');
    const size = src.thumbnail.getSize();
    return { mime: 'image/jpeg', data: src.thumbnail.toJPEG(75).toString('base64'), imgW: size.width, imgH: size.height, screenW: Math.round(d.size.width * d.scaleFactor), screenH: Math.round(d.size.height * d.scaleFactor) };
  }
  const jpg = process.platform === 'win32' || process.platform === 'darwin';
  let shotDims = null; // [screenW, screenH, imgW, imgH]
  const tmp = path.join(os.tmpdir(), 'glucer-shot-' + newId() + (jpg ? '.jpg' : '.png'));
  try {
    if (process.platform === 'win32') {
      const script = [
        "Add-Type -AssemblyName System.Windows.Forms,System.Drawing",
        "Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public class GD { [DllImport(\"user32.dll\")] public static extern bool SetProcessDPIAware(); }'",
        "[void][GD]::SetProcessDPIAware()",
        "$b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds",
        "$bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height",
        "$g = [System.Drawing.Graphics]::FromImage($bmp)",
        "$g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)",
        "$w = [Math]::Min(1600, $b.Width); $h = [int]($b.Height * $w / $b.Width)",
        "$out = New-Object System.Drawing.Bitmap $w, $h",
        "$g2 = [System.Drawing.Graphics]::FromImage($out)",
        "$g2.InterpolationMode = 'HighQualityBicubic'",
        "$g2.DrawImage($bmp, 0, 0, $w, $h)",
        "$out.Save($env:GLUCER_OUT, [System.Drawing.Imaging.ImageFormat]::Jpeg)",
        'Write-Output ("{0} {1} {2} {3}" -f $b.Width, $b.Height, $w, $h)'
      ].join('; ');
      const out = await runCmd('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], { env: Object.assign({}, process.env, { GLUCER_OUT: tmp }) });
      const d4 = out.trim().split(/\s+/).map(Number);
      if (d4.length >= 4 && d4.every(Number.isFinite)) shotDims = d4;
    } else if (process.platform === 'darwin') {
      await runCmd('screencapture', ['-x', '-t', 'jpg', tmp]);
      const dims = (s) => s.split(/\r?\n/).filter((l) => l.includes('pixel')).map((l) => Number(l.split(':')[1])).filter(Number.isFinite);
      const orig = dims(await runCmd('sips', ['-g', 'pixelWidth', '-g', 'pixelHeight', tmp]));
      await runCmd('sips', ['-Z', '1600', tmp]);
      const small = dims(await runCmd('sips', ['-g', 'pixelWidth', '-g', 'pixelHeight', tmp]));
      if (orig.length >= 2 && small.length >= 2) shotDims = [orig[0], orig[1], small[0], small[1]];
    } else {
      let done = false;
      for (const t of [['grim', [tmp]], ['gnome-screenshot', ['-f', tmp]], ['scrot', ['-o', tmp]], ['import', ['-window', 'root', tmp]]]) {
        try { await runCmd(t[0], t[1]); if (fs.existsSync(tmp)) { done = true; break; } } catch (e) {}
      }
      if (!done) throw new Error('No screenshot tool found. Install gnome-screenshot, scrot or grim.');
    }
    const buf = fs.readFileSync(tmp);
    if (!buf.length) throw new Error('The screenshot came out empty.');
    if (buf.length > 6 * 1024 * 1024) throw new Error('The screenshot is too large.');
    let imgW = shotDims ? shotDims[2] : 0, imgH = shotDims ? shotDims[3] : 0;
    if (!imgW && !jpg) { try { imgW = buf.readUInt32BE(16); imgH = buf.readUInt32BE(20); } catch (e) {} }
    return { mime: jpg ? 'image/jpeg' : 'image/png', data: buf.toString('base64'), imgW: imgW || 0, imgH: imgH || 0, screenW: shotDims ? shotDims[0] : (imgW || 0), screenH: shotDims ? shotDims[1] : (imgH || 0) };
  } finally { try { fs.unlinkSync(tmp); } catch (e) {} }
}

async function clipRead() {
  let t;
  if (IS_ELECTRON) t = require('electron').clipboard.readText();
  else if (process.platform === 'win32') t = await runCmd('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', '[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-Clipboard -Raw']);
  else if (process.platform === 'darwin') t = await runCmd('pbpaste', []);
  else { try { t = await runCmd('wl-paste', ['--no-newline']); } catch (e) { t = await runCmd('xclip', ['-selection', 'clipboard', '-o']); } }
  return String(t || '').replace(/^\uFEFF/, '');
}
function clipWrite(text) {
  if (IS_ELECTRON) { require('electron').clipboard.writeText(text); return Promise.resolve(); }
  return new Promise((resolve, reject) => {
    let cmd, args;
    if (process.platform === 'win32') { cmd = 'powershell.exe'; args = ['-NoProfile', '-NonInteractive', '-Command', '[Console]::InputEncoding=[Text.Encoding]::UTF8; Set-Clipboard -Value ([Console]::In.ReadToEnd())']; }
    else if (process.platform === 'darwin') { cmd = 'pbcopy'; args = []; }
    else { cmd = 'xclip'; args = ['-selection', 'clipboard']; }
    const bad = () => reject(new Error('Could not use the clipboard on this computer.'));
    const p = spawn(cmd, args, { stdio: ['pipe', 'ignore', 'ignore'] });
    p.on('error', bad);
    p.on('close', (code) => (code === 0 ? resolve() : bad()));
    p.stdin.end(text, 'utf8');
  });
}

/* ---------- Mouse and keyboard (the "hands") ----------
   Mouse coordinates always come from the LAST screenshot, in the pixels of
   that picture. We convert them to real screen coordinates here, which also
   handles the picture having been resized down before the AI saw it. */
function toScreen(x, y) {
  const nx = Number(x), ny = Number(y);
  if (!Number.isFinite(nx) || !Number.isFinite(ny)) throw new Error('Those coordinates are not numbers.');
  if (!lastShot || !lastShot.imgW) throw new Error('Look at the screen first (call screenshot), then use coordinates from that picture.');
  const cx = Math.max(0, Math.min(lastShot.screenW - 1, Math.round(nx * lastShot.screenW / lastShot.imgW)));
  const cy = Math.max(0, Math.min(lastShot.screenH - 1, Math.round(ny * lastShot.screenH / lastShot.imgH)));
  return { cx, cy };
}
function winPS(script) {
  return runCmd('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], { timeout: 60000 });
}
const GM_CSHARP = [
  'using System;',
  'using System.Runtime.InteropServices;',
  'public class GM {',
  '  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();',
  '  [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);',
  '  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, int d, UIntPtr e);',
  '}'
].join('\n');
function mouseScript(x, y, actions) {
  return ["$src = @'", GM_CSHARP, "'@", 'Add-Type -TypeDefinition $src', '[void][GM]::SetProcessDPIAware()',
    '[void][GM]::SetCursorPos(' + x + ', ' + y + ')', 'Start-Sleep -Milliseconds 120', actions, 'Start-Sleep -Milliseconds 80'].join('\n');
}
const GT_CSHARP = [
  'using System;',
  'using System.Runtime.InteropServices;',
  'using System.Threading;',
  'public class GT {',
  '  [StructLayout(LayoutKind.Sequential)] public struct MOUSEINPUT { public int dx; public int dy; public uint mouseData; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }',
  '  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }',
  '  [StructLayout(LayoutKind.Explicit)] public struct UN { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }',
  '  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public UN u; }',
  '  [DllImport("user32.dll", SetLastError = true)] public static extern uint SendInput(uint n, INPUT[] p, int size);',
  '  public static string TypeText(string s) {',
  '    int done = 0;',
  '    foreach (char c in s) {',
  '      INPUT d = new INPUT(); d.type = 1; d.u.ki.wScan = c; d.u.ki.dwFlags = 4;',
  '      INPUT u = new INPUT(); u.type = 1; u.u.ki.wScan = c; u.u.ki.dwFlags = 6;',
  '      INPUT[] two = new INPUT[] { d, u };',
  '      if (SendInput(2, two, Marshal.SizeOf(typeof(INPUT))) == 2) done++;',
  '      Thread.Sleep(8);',
  '    }',
  '    return done + " of " + s.Length + " characters typed";',
  '  }',
  '}'
].join('\n');
async function mouseClick(pos, btn) {
  if (process.platform === 'win32') {
    const acts = btn === 'right'
      ? '[GM]::mouse_event(8,0,0,0,[UIntPtr]::Zero); Start-Sleep -Milliseconds 50; [GM]::mouse_event(16,0,0,0,[UIntPtr]::Zero)'
      : btn === 'double'
      ? '[GM]::mouse_event(2,0,0,0,[UIntPtr]::Zero); [GM]::mouse_event(4,0,0,0,[UIntPtr]::Zero); Start-Sleep -Milliseconds 70; [GM]::mouse_event(2,0,0,0,[UIntPtr]::Zero); [GM]::mouse_event(4,0,0,0,[UIntPtr]::Zero)'
      : '[GM]::mouse_event(2,0,0,0,[UIntPtr]::Zero); Start-Sleep -Milliseconds 50; [GM]::mouse_event(4,0,0,0,[UIntPtr]::Zero)';
    await winPS(mouseScript(pos.cx, pos.cy, acts));
  } else if (process.platform === 'darwin') {
    await runCmd('osascript', ['-e', 'tell application "System Events" to click at {' + pos.cx + ', ' + pos.cy + '}']);
  } else {
    const clickArg = btn === 'double' ? ['click', '--repeat', '2', '--delay', '90', '1'] : ['click', btn === 'right' ? '3' : '1'];
    try { await runCmd('xdotool', ['mousemove', String(pos.cx), String(pos.cy)].concat(clickArg)); }
    catch (e) { throw new Error('Could not control the mouse. On Linux, Glucer needs the xdotool package installed.'); }
  }
}
async function mouseScroll(pos, dir, clicks) {
  const delta = (dir === 'up' ? 1 : -1) * 120 * clicks;
  if (process.platform === 'win32') {
    const scroll = '[GM]::mouse_event(0x0800,0,0,' + delta + ',[UIntPtr]::Zero)';
    if (pos) await winPS(mouseScript(pos.cx, pos.cy, scroll));
    else await winPS(["$src = @'", GM_CSHARP, "'@", 'Add-Type -TypeDefinition $src', '[void][GM]::SetProcessDPIAware()', 'Start-Sleep -Milliseconds 50', scroll].join('\n'));
  } else if (process.platform === 'darwin') {
    throw new Error('Scrolling is not supported on the Mac yet.');
  } else {
    try { await runCmd('xdotool', ['click', '--repeat', String(clicks), '--delay', '60', dir === 'up' ? '4' : '5']); }
    catch (e) { throw new Error('Could not scroll. On Linux, Glucer needs the xdotool package installed.'); }
  }
}
async function keyboardType(text) {
  if (process.platform === 'win32') {
    const b64 = Buffer.from(text, 'utf8').toString('base64');
    const script = ["$src = @'", GT_CSHARP, "'@", 'Add-Type -TypeDefinition $src',
      "$text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + b64 + "'))",
      '[void][GT]::TypeText($text)'].join('\n');
    await winPS(script);
  } else if (process.platform === 'darwin') {
    await runCmd('osascript', ['-e', 'on run argv', '-e', 'tell application "System Events" to keystroke (item 1 of argv)', '-e', 'end run', text]);
  } else {
    try { await runCmd('xdotool', ['type', '--delay', '12', '--', text]); }
    catch (e) { throw new Error('Could not type. On Linux, Glucer needs the xdotool package installed.'); }
  }
}
const SK_KEY = { enter: '{ENTER}', tab: '{TAB}', esc: '{ESC}', backspace: '{BS}', del: '{DEL}', insert: '{INS}', home: '{HOME}', end: '{END}', pageup: '{PGUP}', pagedown: '{PGDN}', up: '{UP}', down: '{DOWN}', left: '{LEFT}', right: '{RIGHT}', space: ' ', capslock: '{CAPSLOCK}' };
const MAC_CODE = { enter: 36, tab: 48, esc: 53, backspace: 51, del: 117, home: 115, end: 119, pageup: 116, pagedown: 121, up: 126, down: 125, left: 123, right: 124, space: 49, f1: 122, f2: 120, f3: 99, f4: 118, f5: 96, f6: 97, f7: 98, f8: 100, f9: 101, f10: 109, f11: 103, f12: 111 };
function parseCombo(key) {
  const parts = String(key || '').toLowerCase().split('+').map((s) => s.trim()).filter(Boolean);
  const NAMES = new Set(['enter', 'return', 'tab', 'esc', 'escape', 'backspace', 'space', 'capslock', 'del', 'delete', 'insert', 'home', 'end', 'pageup', 'pagedown', 'up', 'down', 'left', 'right']);
  const mods = [];
  let main = null;
  for (const p of parts) {
    if (p === 'ctrl' || p === 'control') { if (!mods.includes('ctrl')) mods.push('ctrl'); continue; }
    if (p === 'alt' || p === 'option') { if (!mods.includes('alt')) mods.push('alt'); continue; }
    if (p === 'shift') { if (!mods.includes('shift')) mods.push('shift'); continue; }
    if (main) throw new Error('Use one main key, like ctrl+s or enter.');
    if (p === 'win' || p === 'windows') throw new Error("The Windows key can't be sent — use ctrl+esc instead, which opens the Start menu.");
    if (/^f([1-9]|1[0-2])$/.test(p) || NAMES.has(p) || /^[a-z0-9]$/.test(p)) { main = p === 'return' ? 'enter' : p === 'escape' ? 'esc' : p === 'delete' ? 'del' : p; continue; }
    if (p.length === 1) { main = p; continue; }
    throw new Error('Unknown key "' + p + '". Examples: enter, tab, esc, backspace, delete, up, down, left, right, home, end, pageup, pagedown, space, f5, or single letters — with ctrl, alt or shift, like ctrl+s or alt+f4.');
  }
  if (!main) throw new Error('Say which key to press (examples: enter, ctrl+s, alt+f4).');
  return { mods, main };
}
const comboLabel = (c) => (c.mods.length ? c.mods.join('+') + '+' : '') + c.main;
async function keyPress(c) {
  if (process.platform === 'win32') {
    const mods = (c.mods.includes('ctrl') ? '^' : '') + (c.mods.includes('alt') ? '%' : '') + (c.mods.includes('shift') ? '+' : '');
    let main;
    if (/^[a-z0-9]$/.test(c.main)) main = c.main.toUpperCase();
    else if (/^f\d+$/.test(c.main)) main = '{' + c.main.toUpperCase() + '}';
    else main = SK_KEY[c.main];
    if (!main) throw new Error('That key is not supported on Windows yet.');
    await runCmd('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', 'Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait(\'' + mods + main + '\')'], { timeout: 30000 });
  } else if (process.platform === 'darwin') {
    const use = c.mods.length ? ' using {' + c.mods.map((m) => ({ ctrl: 'control down', alt: 'option down', shift: 'shift down' })[m]).join(', ') + '}' : '';
    let line;
    if (/^[a-z0-9]$/.test(c.main)) line = 'tell application "System Events" to keystroke "' + c.main + '"' + use;
    else if (MAC_CODE[c.main]) line = 'tell application "System Events" to key code ' + MAC_CODE[c.main] + use;
    else throw new Error('That key is not supported on the Mac yet.');
    await runCmd('osascript', ['-e', line]);
  } else {
    const X = { enter: 'Return', tab: 'Tab', esc: 'Escape', backspace: 'BackSpace', del: 'Delete', insert: 'Insert', home: 'Home', end: 'End', pageup: 'Prior', pagedown: 'Next', space: 'space', capslock: 'Caps_Lock' };
    const name = /^[a-z0-9]$/.test(c.main) || /^f\d+$/.test(c.main) ? c.main : X[c.main];
    if (!name) throw new Error('That key is not supported on Linux yet.');
    try { await runCmd('xdotool', ['key', c.mods.concat([name]).join('+')]); }
    catch (e) { throw new Error('Could not press keys. On Linux, Glucer needs the xdotool package installed.'); }
  }
}

/* ---------- Tools ---------- */
const SKIP = new Set(['node_modules', '.git', 'AppData', 'Library', '$Recycle.Bin', 'System Volume Information', 'Windows', 'Program Files', 'Program Files (x86)', '.cache', '.npm']);
const BINARY_EXT = /^(png|jpe?g|gif|webp|ico|bmp|pdf|zip|rar|7z|gz|tar|exe|dll|msi|iso|dmg|mp3|mp4|mov|avi|mkv|wav|flac|ttf|otf|woff2?|bin|dat|db|sqlite|class|jar|so|dylib|docx|xlsx|pptx)$/i;
const RISKY_OPEN = /\.(exe|bat|cmd|ps1|sh|msi|app|command|scr|vbs|jar|lnk)$/i;
const BLOCKED = [
  /\brm\s+-[a-z]*r[a-z]*\s+(\/|~|\$HOME|\*)(\s|$)/i, /\bmkfs/i, /\bdd\s+.*of=\/dev\//i, /\bformat\s+[a-z]:/i,
  /\b(rd|rmdir)\s+\/s.*\b[a-z]:\\?(\s|$)/i, /\bdel\s+.*\b[a-z]:\\\*?(\s|$)/i, /\bdiskpart\b/i, /\bshutdown\b/i, /:\(\)\s*\{/
];
// Tools that only look. Read-only mode allows only these.
const READ_OK_TOOLS = new Set(['system_info', 'list_folder', 'find_files', 'search_in_files', 'read_text_file', 'read_document', 'reveal_item', 'screenshot', 'clipboard_read', '__activity']);

const TOOLS = {
  system_info: {
    plan: () => ({}),
    run: async () => {
      const folders = {};
      ['Desktop', 'Documents', 'Downloads', 'Pictures'].forEach((n) => { folders[n.toLowerCase()] = resolveP(n); });
      return ok({
        platform: process.platform, system: os.type() + ' ' + os.release(), user: os.userInfo().username, home: HOME, folders,
        commandShell: process.platform === 'win32' ? 'Windows Command Prompt (cmd.exe)' : (process.env.SHELL || '/bin/sh'),
        now: new Date().toString()
      }, 'Checked this computer');
    }
  },

  screenshot: {
    plan: (a) => {
      const d = Math.max(0, Math.min(10, Number(a.delay_seconds) || 0));
      return { d, risk: 'high', lines: ['Take a screenshot of your main screen' + (d ? ' in ' + d + ' seconds (switch to the window you want Glucer to see)' : ''), 'The picture is sent to the AI service to answer you. Close anything private first.'] };
    },
    run: async (a, p) => {
      if (p.d) await sleep(p.d * 1000);
      const image = await takeScreenshot();
      if (image.imgW) lastShot = image;
      return ok({ note: 'The screenshot is attached to this message as an image. Mouse tool coordinates are pixels in THIS picture (' + image.imgW + 'x' + image.imgH + ').' }, 'Looked at your screen', { image });
    }
  },

  clipboard_read: {
    plan: () => ({ lines: ['Read what you last copied (your clipboard)'] }),
    run: async () => {
      const t = await clipRead();
      return ok({ text: t.slice(0, 20000), truncated: t.length > 20000, empty: !t.trim() }, 'Read your clipboard (' + t.length + ' characters)');
    }
  },

  clipboard_write: {
    plan: (a) => {
      if (typeof a.text !== 'string' || !a.text) throw new Error('No text given.');
      if (a.text.length > 200000) throw new Error('That text is too long.');
      return { lines: ['Put this on your clipboard (' + a.text.length + ' characters):', a.text.slice(0, 200) + (a.text.length > 200 ? '...' : '')] };
    },
    run: async (a) => { await clipWrite(a.text); return ok({ copied: true }, 'Copied to your clipboard'); }
  },

  list_folder: {
    plan: (a) => { const full = resolveP(a.path); return Object.assign({ full }, gate([full])); },
    run: async (a, p) => {
      const all = fs.readdirSync(p.full, { withFileTypes: true });
      const items = all.slice(0, 500).map((d) => {
        let size;
        if (d.isFile()) { try { size = fs.statSync(path.join(p.full, d.name)).size; } catch (e) {} }
        return { name: d.name, type: d.isDirectory() ? 'folder' : 'file', size };
      });
      return ok({ path: p.full, items, truncated: all.length > 500 }, 'Looked in ' + short(p.full) + ' (' + all.length + ' items)');
    }
  },

  find_files: {
    plan: (a) => { const full = resolveP(a.path || '.'); return Object.assign({ full }, gate([full])); },
    run: async (a, p) => {
      const q = String(a.query || '').toLowerCase().trim();
      if (!q) throw new Error('Nothing to search for.');
      const out = [], todo = [p.full];
      let visited = 0;
      while (todo.length && visited < 30000 && out.length < 100) {
        const dir = todo.shift();
        let entries;
        try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { continue; }
        for (const d of entries) {
          visited++;
          const full = path.join(dir, d.name);
          if (isSensitive(full)) continue;
          if (d.name.toLowerCase().includes(q)) { out.push(full + (d.isDirectory() ? path.sep : '')); if (out.length >= 100) break; }
          if (d.isDirectory() && !SKIP.has(d.name)) todo.push(full);
        }
      }
      return ok({ matches: out, searched: visited }, 'Searched for "' + q + '" (' + out.length + ' found)');
    }
  },

  search_in_files: {
    plan: (a) => { const full = resolveP(a.path || '.'); return Object.assign({ full }, gate([full])); },
    run: async (a, p) => {
      const q = String(a.query || '').toLowerCase().trim();
      if (!q) throw new Error('Nothing to search for.');
      const exts = Array.isArray(a.extensions) && a.extensions.length ? a.extensions.map((e) => String(e).toLowerCase().replace(/^\./, '')) : null;
      const out = [], todo = [p.full], t0 = Date.now();
      let files = 0;
      while (todo.length && out.length < 60 && files < 4000 && Date.now() - t0 < 15000) {
        const dir = todo.shift();
        let entries;
        try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { continue; }
        for (const d of entries) {
          const full = path.join(dir, d.name);
          if (isSensitive(full)) continue;
          if (d.isDirectory()) { if (!SKIP.has(d.name)) todo.push(full); continue; }
          if (!d.isFile()) continue;
          const ext = path.extname(d.name).slice(1).toLowerCase();
          if (exts ? !exts.includes(ext) : BINARY_EXT.test(ext)) continue;
          try {
            if (fs.statSync(full).size > 1500000) continue;
            const buf = fs.readFileSync(full);
            if (buf.subarray(0, 2000).includes(0)) continue;
            files++;
            let hits = 0;
            buf.toString('utf8').split(/\r?\n/).some((line, i) => {
              if (line.toLowerCase().includes(q)) { out.push({ file: full, line: i + 1, text: line.trim().slice(0, 200) }); hits++; }
              return hits >= 3 || out.length >= 60;
            });
          } catch (e) {}
        }
      }
      return ok({ matches: out, filesChecked: files }, 'Searched inside files for "' + q + '" (' + out.length + ' found)');
    }
  },

  read_text_file: {
    plan: (a) => { const full = resolveP(a.path); return Object.assign({ full }, gate([full])); },
    run: async (a, p) => {
      const st = fs.statSync(p.full);
      if (!st.isFile()) throw new Error('That is not a file.');
      const len = Math.min(st.size, 60000);
      const buf = Buffer.alloc(len);
      const fd = fs.openSync(p.full, 'r');
      fs.readSync(fd, buf, 0, len, 0);
      fs.closeSync(fd);
      if (buf.includes(0)) throw new Error('This looks like a binary file, not text. Try read_document for PDF, Word or Excel files.');
      const text = buf.toString('utf8');
      return ok({ path: p.full, text: text.slice(0, 20000), truncated: text.length > 20000 || st.size > len }, 'Read ' + path.basename(p.full));
    }
  },

  read_document: {
    plan: (a) => { const full = resolveP(a.path); return Object.assign({ full }, gate([full])); },
    run: async (a, p) => {
      const st = fs.statSync(p.full);
      if (!st.isFile()) throw new Error('That is not a file.');
      if (st.size > 25 * 1024 * 1024) throw new Error('That file is too large to read (over 25 MB).');
      const ext = path.extname(p.full).slice(1).toLowerCase();
      let text = '', pages;
      if (ext === 'pdf') {
        const pdf = lib('pdf-parse/lib/pdf-parse.js', 'pdf-parse@1.1.1');
        const data = await pdf(fs.readFileSync(p.full));
        text = data.text; pages = data.numpages;
      } else if (ext === 'docx') {
        const mammoth = lib('mammoth', 'mammoth');
        text = (await mammoth.extractRawText({ path: p.full })).value;
      } else if (/^(xlsx|xls|xlsm|ods)$/.test(ext)) {
        const X = lib('xlsx', 'xlsx@0.18.5');
        const wb = X.readFile(p.full);
        text = wb.SheetNames.map((n) => '## Sheet: ' + n + '\n' + X.utils.sheet_to_csv(wb.Sheets[n])).join('\n\n');
      } else if (BINARY_EXT.test(ext)) {
        throw new Error('I can read PDF, Word (.docx), Excel and plain text files, but not .' + ext + ' files.');
      } else {
        text = fs.readFileSync(p.full, 'utf8');
      }
      text = text.trim();
      if (!text) throw new Error('No readable text found in that file (it may be a scanned image).');
      return ok({ path: p.full, pages, text: text.slice(0, 20000), truncated: text.length > 20000 }, 'Read ' + path.basename(p.full));
    }
  },

  create_folders: {
    plan: (a) => {
      const fulls = arr(a.paths).map(resolveP);
      if (!fulls.length) throw new Error('No folders given.');
      return { fulls, lines: fulls.map((f) => 'Create folder: ' + short(f)), risk: sens(fulls) };
    },
    run: async (a, p) => {
      const missing = [];
      for (const f of p.fulls) {
        let d = f;
        while (!fs.existsSync(d) && d !== path.dirname(d)) { missing.push(d); d = path.dirname(d); }
        fs.mkdirSync(f, { recursive: true });
      }
      const id = missing.length ? logOp({ kind: 'mkdir', created: missing }) : undefined;
      return ok({ created: p.fulls.length }, 'Created ' + p.fulls.length + ' folder(s)', { undoId: id });
    }
  },

  move_items: {
    plan: (a) => {
      const ms = arr(a.moves).map((m) => ({ from: resolveP(m && m.from), to: resolveP(m && m.to) }));
      if (!ms.length) throw new Error('No moves given.');
      return { ms, lines: ms.map((m) => 'Move ' + short(m.from) + '  ->  ' + short(m.to)), risk: sens(ms.flatMap((m) => [m.from, m.to])) };
    },
    run: async (a, p) => {
      const done = [], errors = [];
      for (const m of p.ms) {
        try {
          if (!fs.existsSync(m.from)) throw new Error('Not found: ' + short(m.from));
          if (fs.existsSync(m.to)) throw new Error('Already exists, not overwritten: ' + short(m.to));
          if (m.to === m.from || m.to.startsWith(m.from + path.sep)) throw new Error('Cannot move something into itself: ' + short(m.from));
          fs.mkdirSync(path.dirname(m.to), { recursive: true });
          movePath(m.from, m.to);
          done.push(m);
        } catch (e) { errors.push(e.message); }
      }
      const id = done.length ? logOp({ kind: 'move', moves: done }) : undefined;
      return ok({ moved: done.length, errors }, 'Moved ' + done.length + ' of ' + p.ms.length + (errors.length ? ' (' + errors.length + ' problem(s))' : ''), { undoId: id });
    }
  },

  copy_items: {
    plan: (a) => {
      const cs = arr(a.copies).map((m) => ({ from: resolveP(m && m.from), to: resolveP(m && m.to) }));
      if (!cs.length) throw new Error('No copies given.');
      return { cs, lines: cs.map((m) => 'Copy ' + short(m.from) + '  ->  ' + short(m.to)), risk: sens(cs.flatMap((m) => [m.from, m.to])) };
    },
    run: async (a, p) => {
      const created = [], errors = [];
      for (const m of p.cs) {
        try {
          if (!fs.existsSync(m.from)) throw new Error('Not found: ' + short(m.from));
          if (fs.existsSync(m.to)) throw new Error('Already exists, not overwritten: ' + short(m.to));
          fs.mkdirSync(path.dirname(m.to), { recursive: true });
          fs.cpSync(m.from, m.to, { recursive: true });
          created.push(m.to);
        } catch (e) { errors.push(e.message); }
      }
      const id = created.length ? logOp({ kind: 'copy', created }) : undefined;
      return ok({ copied: created.length, errors }, 'Copied ' + created.length + ' of ' + p.cs.length + (errors.length ? ' (' + errors.length + ' problem(s))' : ''), { undoId: id });
    }
  },

  write_text_file: {
    plan: (a) => {
      const full = resolveP(a.path);
      if (typeof a.content !== 'string') throw new Error('No content given.');
      if (a.content.length > 2000000) throw new Error('That file is too large.');
      const exists = fs.existsSync(full);
      if (exists && a.overwrite !== true) throw new Error('That file already exists, so it was not replaced.');
      return { full, exists, lines: [(exists ? 'REPLACE the existing file ' : 'Create the file ') + short(full) + ' (' + a.content.length + ' characters)'], risk: sens([full]) };
    },
    run: async (a, p) => {
      const id = newId();
      let backup = null;
      if (p.exists) {
        backup = path.join(DATA_DIR, 'backups', id, path.basename(p.full));
        fs.mkdirSync(path.dirname(backup), { recursive: true });
        fs.copyFileSync(p.full, backup);
      }
      fs.mkdirSync(path.dirname(p.full), { recursive: true });
      fs.writeFileSync(p.full, a.content);
      logOp({ id, kind: 'write', path: p.full, backup });
      return ok({ path: p.full }, (p.exists ? 'Replaced ' : 'Created ') + path.basename(p.full), { undoId: id });
    }
  },

  trash_items: {
    plan: (a) => {
      const fulls = arr(a.paths).map(resolveP);
      if (!fulls.length) throw new Error('No items given.');
      return { fulls, lines: fulls.map((f) => 'Move to the Trash / Recycle Bin: ' + short(f)), risk: 'high' };
    },
    run: async (a, p) => {
      let n = 0;
      const errors = [];
      for (const f of p.fulls) {
        try { if (!fs.existsSync(f)) throw new Error('Not found: ' + short(f)); await trashOne(f); n++; }
        catch (e) { errors.push(e.message); }
      }
      return ok({ trashed: n, errors }, 'Moved ' + n + ' item(s) to the Trash (restore from the Recycle Bin or Trash)' + (errors.length ? ', ' + errors.length + ' problem(s)' : ''));
    }
  },

  reveal_item: {
    plan: () => ({}),
    run: async (a) => {
      const full = resolveP(a.path);
      if (!fs.existsSync(full)) throw new Error('Not found: ' + short(full));
      if (process.platform === 'win32') execFile('explorer.exe', ['/select,' + full], () => {});
      else if (process.platform === 'darwin') execFile('open', ['-R', full], () => {});
      else execFile('xdg-open', [path.dirname(full)], () => {});
      return ok({ shown: full }, 'Showed ' + path.basename(full));
    }
  },

  open_item: {
    plan: (a) => {
      const t = String(a.target || '').trim();
      if (!t) throw new Error('Nothing to open.');
      if (/^(https?:\/\/|mailto:)/i.test(t)) return { kind: 'url', target: t, lines: ['Open this link: ' + t.slice(0, 200)] };
      const full = resolveP(t);
      if (fs.existsSync(full)) return { kind: 'path', target: full, lines: ['Open ' + short(full)], risk: RISKY_OPEN.test(full) || isSensitive(full) ? 'high' : undefined };
      if (/^[\w .()\-]{1,60}$/.test(t)) return { kind: 'app', target: t, lines: ['Start the app: ' + t] };
      throw new Error('Could not find that file, folder or app.');
    },
    run: async (a, p) => {
      let cmd, args;
      if (process.platform === 'win32') {
        if (p.kind === 'app') { cmd = 'cmd.exe'; args = ['/c', 'start', '', p.target]; } else { cmd = 'explorer.exe'; args = [p.target]; }
      } else if (process.platform === 'darwin') {
        cmd = 'open'; args = p.kind === 'app' ? ['-a', p.target] : [p.target];
      } else if (p.kind === 'app') { cmd = p.target; args = []; }
      else { cmd = 'xdg-open'; args = [p.target]; }
      spawn(cmd, args, { detached: true, stdio: 'ignore' }).on('error', () => {}).unref();
      return ok({ opened: p.target }, 'Opened ' + short(p.target));
    }
  },

  run_command: {
    plan: (a) => {
      const cmd = String(a.command || '').trim();
      if (!cmd) throw new Error('No command given.');
      if (cmd.length > 2000) throw new Error('That command is too long.');
      if (BLOCKED.some((re) => re.test(cmd))) throw new Error('That command is blocked for safety.');
      const cwd = resolveP(a.folder || '.');
      if (!fs.existsSync(cwd)) throw new Error('That folder does not exist.');
      return { cmd, cwd, lines: ['RUN THIS COMMAND: ' + cmd, 'In the folder: ' + short(cwd)], risk: 'high' };
    },
    run: async (a, p) => new Promise((resolve) => {
      exec(p.cmd, { cwd: p.cwd, timeout: 60000, maxBuffer: 1024 * 1024, windowsHide: true }, (err, stdout, stderr) => {
        resolve(ok({
          exitCode: err ? (typeof err.code === 'number' ? err.code : 1) : 0,
          timedOut: !!(err && err.killed),
          stdout: String(stdout).slice(-8000), stderr: String(stderr).slice(-4000)
        }, 'Ran: ' + p.cmd.slice(0, 60)));
      });
    })
  },

  mouse_click: {
    plan: (a) => {
      const p = toScreen(a.x, a.y);
      const btn = ['left', 'right', 'double'].includes(a.button) ? a.button : 'left';
      return { p, btn, lines: [(btn === 'double' ? 'DOUBLE-click' : 'Click the ' + btn.toUpperCase() + ' mouse button') + ' at screen position (' + p.cx + ', ' + p.cy + ')'] };
    },
    run: async (a, p) => {
      await mouseClick(p.p, p.btn);
      return ok({ x: p.p.cx, y: p.p.cy, button: p.btn }, 'Clicked ' + p.btn + ' at (' + p.p.cx + ', ' + p.p.cy + ')');
    }
  },

  mouse_scroll: {
    plan: (a) => {
      const dir = a.direction === 'up' ? 'up' : 'down';
      const n = Math.max(1, Math.min(10, Math.round(Number(a.clicks) || 3)));
      const pos = (a.x != null && a.y != null) ? toScreen(a.x, a.y) : null;
      return { dir, n, pos, lines: ['Scroll ' + dir + ' ' + n + ' notches' + (pos ? ' at (' + pos.cx + ', ' + pos.cy + ')' : ' where the mouse pointer is')] };
    },
    run: async (a, p) => {
      await mouseScroll(p.pos, p.dir, p.n);
      return ok({ direction: p.dir, clicks: p.n }, 'Scrolled ' + p.dir + ' ' + p.n + ' notches');
    }
  },

  keyboard_type: {
    plan: (a) => {
      const t = String(a.text == null ? '' : a.text);
      if (!t.trim()) throw new Error('No text given.');
      if (t.length > 500) throw new Error('Too long to type. For long text, use clipboard_write, then key_press with ctrl+v.');
      return { t, lines: ['Type this with the keyboard into whatever window is active:', t.slice(0, 200) + (t.length > 200 ? '...' : '')] };
    },
    run: async (a, p) => {
      await keyboardType(p.t);
      return ok({ typed: p.t.length }, 'Typed ' + p.t.length + ' characters');
    }
  },

  key_press: {
    plan: (a) => {
      const c = parseCombo(a && a.key);
      return { c, lines: ['Press keys: ' + comboLabel(c)] };
    },
    run: async (a, p) => {
      await keyPress(p.c);
      return ok({ key: comboLabel(p.c) }, 'Pressed ' + comboLabel(p.c));
    }
  }
};

/* ---------- Approvals (only used with --strict) ---------- */
let rl = null, askQueue = Promise.resolve();
function termAsk(lines) {
  if (!rl) rl = require('readline').createInterface({ input: process.stdin, output: process.stdout });
  const p = askQueue.then(() => new Promise((res) => {
    console.log('\n======== Glucer wants to do this ========');
    lines.slice(0, 25).forEach((l) => console.log('  ' + l));
    rl.question('Allow this? Type y for yes (anything else = no): ', (a) => res(/^y(es)?$/i.test(a.trim())));
  }));
  askQueue = p.catch(() => {});
  return p;
}

/* ---------- One entry point for everything ---------- */
async function handleCall(name, args, approved, readOnly) {
  try {
    if (name === '__activity') return ok({ entries: readActivity(200) }, 'Loaded the activity log');
    if (readOnly === true && !READ_OK_TOOLS.has(name)) return { ok: false, error: 'Read-only mode is on, so Glucer can look but not change anything.', summary: 'Blocked by read-only mode' };
    if (name === '__undo') return await undoOp(args && args.id);
    if (!Object.prototype.hasOwnProperty.call(TOOLS, name)) throw new Error('Unknown tool: ' + String(name).slice(0, 40));
    args = args && typeof args === 'object' ? args : {};
    const tool = TOOLS[name];
    const plan = tool.plan(args);
    if (plan.lines) {
      if (STRICT) { if (!(await termAsk(plan.lines))) throw new Denied(); }
      else if (approved !== true) return { ok: false, needsApproval: true, lines: plan.lines.slice(0, 40), risk: plan.risk || 'normal', summary: 'Waiting for your OK' };
    }
    const r = await tool.run(args, plan);
    logActivity({ t: Date.now(), tool: name, what: plan.lines ? plan.lines.slice(0, 3).join(' | ') : ((r && r.summary) || name), ok: !!(r && r.ok), result: r && (r.summary || r.error) });
    return r;
  } catch (e) {
    if (e instanceof Denied) return { ok: false, denied: true, error: 'The user declined this action.', summary: 'You declined this' };
    const msg = (e && e.message) || 'Something went wrong';
    return { ok: false, error: msg, summary: msg };
  }
}
module.exports = { handleCall };

/* ---------- Website version: a small server that only your Glucer page can talk to ---------- */
if (AS_SERVER) {
  let WebSocket;
  try { WebSocket = lib('ws', 'ws'); } catch (e) { console.log('\n' + e.message); process.exit(1); }
  const TOKEN = crypto.randomBytes(4).toString('hex');
  const wss = new WebSocket.Server({
    port: PORT, host: '127.0.0.1', maxPayload: 2 * 1024 * 1024,
    verifyClient: ({ origin }) => ALLOWED_ORIGINS.includes(origin) || /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin || '')
  });
  wss.on('error', (e) => {
    console.log(e.code === 'EADDRINUSE' ? '\nGlucer Agent is already running in another window. Close that one first, then try again.' : '\nProblem starting the agent: ' + e.message);
    process.exit(1);
  });
  let current = null, failures = 0;
  wss.on('connection', (ws) => {
    let authed = false;
    ws.on('message', async (raw) => {
      let msg;
      try { msg = JSON.parse(raw); } catch (e) { return; }
      if (!authed) {
        if (failures >= 5) { ws.close(); return; }
        if (msg.type === 'auth' && String(msg.token || '').toLowerCase() === TOKEN) {
          authed = true;
          if (current && current !== ws) { try { current.close(); } catch (e) {} }
          current = ws;
          ws.send(JSON.stringify({ type: 'ready', home: HOME, platform: process.platform }));
          console.log('\nGlucer is connected. Leave this window open.');
        } else { failures++; ws.close(); }
        return;
      }
      if (msg.type === 'call') {
        const r = await handleCall(String(msg.name || ''), msg.args, msg.approved === true, msg.readOnly === true);
        try { ws.send(JSON.stringify({ type: 'result', id: msg.id, r })); } catch (e) {}
      }
    });
    ws.on('close', () => { if (current === ws) { current = null; if (authed) console.log('\nGlucer disconnected.'); } });
  });
  console.log('\n=============== Glucer Agent ===============');
  console.log('Your connection code:   ' + TOKEN);
  console.log('\nGo back to Glucer, click "Connect to computer", and type this code.');
  console.log(STRICT ? 'Strict mode: you will approve every action in THIS window.' : 'You will approve actions inside the Glucer chat.');
  console.log('Keep this window open. Close it (or press Ctrl+C) to disconnect.\n');
}
