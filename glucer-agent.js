/* Glucer Agent: lets Glucer work with files, apps, your screen and clipboard on this computer.
   Website version:  node glucer-agent.js     (add --strict to approve in this window instead of in Glucer)
   Desktop app:      loaded by the app itself (no server, nothing to run).                                  */
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { exec, execFile, execSync, spawn } = require('child_process');
// In the desktop app, web links are opened by Electron's shell (the real
// browser launcher) - never by explorer.exe, which can pop a File Explorer
// window instead of the browser on some machines.
let shellOpen = null;
if (process.versions.electron) { try { shellOpen = (u) => require('electron').shell.openExternal(u); } catch (e) {} }

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
/* Multi-monitor: this asks Windows itself which monitors exist (in physical
   pixels), which one has the active window, and returns the rectangle of the
   one to photograph. That rectangle is the monitor's true position on the
   whole desktop — so clicks can reach the second monitor and beyond. */
const GMON_CSHARP = [
  'using System;',
  'using System.Collections.Generic;',
  'using System.Runtime.InteropServices;',
  'public class GMON {',
  '  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();',
  '  [DllImport("user32.dll")] public static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr clip, MCB cb, IntPtr data);',
  '  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();',
  '  [DllImport("user32.dll")] public static extern IntPtr MonitorFromWindow(IntPtr h, uint f);',
  '  [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern bool GetMonitorInfo(IntPtr hMon, ref MONITORINFOEX mi);',
  '  [DllImport("user32.dll")] public static extern int GetSystemMetrics(int n);',
  '  public delegate bool MCB(IntPtr hMon, IntPtr hdc, ref RECT rc, IntPtr data);',
  '  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L; public int T; public int R; public int B; }',
  '  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]',
  '  public struct MONITORINFOEX {',
  '    public int cbSize; public RECT rcMonitor; public RECT rcWork; public uint dwFlags;',
  '    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dev;',
  '  }',
  '  public struct MON { public IntPtr h; public MONITORINFOEX mi; }',
  '  static List<MON> mons = new List<MON>();',
  '  static bool Collect(IntPtr h, IntPtr dc, ref RECT rc, IntPtr data) {',
  '    MON m = new MON(); m.h = h; m.mi = new MONITORINFOEX(); m.mi.cbSize = Marshal.SizeOf(typeof(MONITORINFOEX));',
  '    try { GetMonitorInfo(h, ref m.mi); } catch (Exception) {}',
  '    mons.Add(m); return true;',
  '  }',
  '  public static string Select(string disp) {',
  '    SetProcessDPIAware();',
  '    mons.Clear();',
  '    EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, Collect, IntPtr.Zero);',
  '    if (mons.Count == 0) return "1 1 0 0 " + GetSystemMetrics(0) + " " + GetSystemMetrics(1);',
  '    int pick = -1;',
  '    int d = 0;',
  '    if (int.TryParse(disp == null ? "" : disp.Trim(), out d) && d >= 1 && d <= mons.Count) pick = d - 1;',
  '    if (pick < 0) {',
  '      IntPtr fg = GetForegroundWindow();',
  '      if (fg != IntPtr.Zero) {',
  '        IntPtr hm = MonitorFromWindow(fg, 2);',
  '        if (hm != IntPtr.Zero) for (int i = 0; i < mons.Count; i++) if (mons[i].h == hm) { pick = i; break; }',
  '      }',
  '    }',
  '    if (pick < 0) for (int i = 0; i < mons.Count; i++) if ((mons[i].mi.dwFlags & 1) != 0) { pick = i; break; }',
  '    if (pick < 0) pick = 0;',
  '    RECT r = mons[pick].mi.rcMonitor;',
  '    return (pick + 1) + " " + mons.Count + " " + r.L + " " + r.T + " " + (r.R - r.L) + " " + (r.B - r.T);',
  '  }',
  '}'
].join('\n');
/* Speed: every PowerShell spawn used to re-compile its C# helper from source
   (1-3 s each time, paid on EVERY click, key press and screenshot). Now each
   helper is compiled ONCE into a small DLL in %TEMP% and simply loaded on
   later calls, so every action starts seconds faster. The DLL name embeds a
   hash of the C# source, so an updated app always recompiles cleanly. */
function asmProlog(key, className, cs, refs) {
  const hash = crypto.createHash('sha256').update(cs).digest('hex').slice(0, 12);
  const refA = refs ? ' -ReferencedAssemblies ' + refs : '';
  return [
    "$gsrc = @'", cs, "'@",
    "$gdir = Join-Path $env:TEMP 'glucer-asm'; New-Item -ItemType Directory -Force -Path $gdir | Out-Null",
    "$gdll = Join-Path $gdir '" + key + '-' + hash + ".dll'",
    "if (-not ('" + className + "' -as [type])) {",
    "  $gok = $false",
    "  if (Test-Path $gdll) { try { [void][Reflection.Assembly]::LoadFrom($gdll); $gok = $true } catch {} }",
    "  if (-not $gok) { try { Add-Type -TypeDefinition $gsrc" + refA + " -OutputAssembly $gdll -ErrorAction Stop } catch { Add-Type -TypeDefinition $gsrc" + refA + " } }",
    "  if (-not ('" + className + "' -as [type])) { Add-Type -TypeDefinition $gsrc" + refA + " }",
    "}"
  ];
}
const GD_CSHARP = 'using System.Runtime.InteropServices; public class GD { [DllImport("user32.dll")] public static extern bool SetProcessDPIAware(); }';

async function winCaptureMonitor(displayArg, noGrid) {
  const tmp = path.join(os.tmpdir(), 'glucer-shot-' + newId() + '.jpg');
  try {
    const script = [
      ...asmProlog('gmon', 'GMON', GMON_CSHARP),
      "$sel = ([GMON]::Select($env:GLUCER_DISP) -split '\\s+')",
      '$L = [int]$sel[2]; $T = [int]$sel[3]; $W = [int]$sel[4]; $H = [int]$sel[5]',
      'Add-Type -AssemblyName System.Windows.Forms,System.Drawing',
      '$bmp = New-Object System.Drawing.Bitmap $W, $H',
      '$g = [System.Drawing.Graphics]::FromImage($bmp)',
      '$g.CopyFromScreen($L, $T, 0, 0, (New-Object System.Drawing.Size($W, $H)))',
      '# PS vars are case-INSENSITIVE, so use fresh names ($iw/$ih) - reusing $w/$W made the height formula divide by the resized width and SQUASHED every picture horizontally, wrecking the AI aim.',
      '$iw = [Math]::Min(1600, $W); $ih = [int][Math]::Round($H * $iw / $W)',
      '$out = New-Object System.Drawing.Bitmap $iw, $ih',
      '$g2 = [System.Drawing.Graphics]::FromImage($out)',
      "$g2.InterpolationMode = 'HighQualityBicubic'",
      '$g2.DrawImage($bmp, 0, 0, $iw, $ih)',
      // Coordinate grid: thin red lines every 200 px of THIS picture, with
      // yellow number labels every 400 px, so the AI can READ coordinates off
      // the image instead of guessing them — the #1 cure for mis-clicks.
      '$gp = New-Object System.Drawing.Pen -ArgumentList ([System.Drawing.Color]::FromArgb(' + (noGrid ? 0 : 120) + ', 255, 60, 60))',
      'for ($gx = 200; $gx -lt $iw; $gx += 200) { $g2.DrawLine($gp, $gx, 0, $gx, $ih) }',
      'for ($gy = 200; $gy -lt $ih; $gy += 200) { $g2.DrawLine($gp, 0, $gy, $iw, $gy) }',
      '$gf = New-Object System.Drawing.Font -ArgumentList "Arial", 14, ([System.Drawing.FontStyle]::Bold)',
      '$gbs = New-Object System.Drawing.SolidBrush -ArgumentList ([System.Drawing.Color]::FromArgb(' + (noGrid ? 0 : 160) + ', 0, 0, 0))',
      '$gfs = New-Object System.Drawing.SolidBrush -ArgumentList ([System.Drawing.Color]::FromArgb(' + (noGrid ? 0 : 235) + ', 255, 220, 60))',
      'for ($gx = 400; $gx -lt $iw; $gx += 400) { $gtxt = [string]$gx; $gsz = $g2.MeasureString($gtxt, $gf); $g2.FillRectangle($gbs, $gx + 3, 3, $gsz.Width, $gsz.Height); $g2.DrawString($gtxt, $gf, $gfs, $gx + 3, 3) }',
      'for ($gy = 400; $gy -lt $ih; $gy += 400) { $gtxt = [string]$gy; $gsz = $g2.MeasureString($gtxt, $gf); $g2.FillRectangle($gbs, 3, $gy + 3, $gsz.Width, $gsz.Height); $g2.DrawString($gtxt, $gf, $gfs, 3, $gy + 3) }',
      '$out.Save($env:GLUCER_OUT, [System.Drawing.Imaging.ImageFormat]::Jpeg)',
      'Write-Output ("{0} {1} {2} {3} {4} {5} {6} {7}" -f $sel[0], $sel[1], $L, $T, $W, $H, $iw, $ih)'
    ].join('\n');
    const out = await runCmd('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
      { env: Object.assign({}, process.env, { GLUCER_OUT: tmp, GLUCER_DISP: displayArg == null ? '' : String(displayArg) }), timeout: 60000 });
    const n = out.trim().split(/\s+/).map(Number);
    if (n.length < 8 || !n.every(Number.isFinite)) throw new Error('bad shot output');
    const buf = fs.readFileSync(tmp);
    if (!buf.length) throw new Error('The screenshot came out empty.');
    return { mime: 'image/jpeg', data: buf.toString('base64'), imgW: n[6], imgH: n[7], screenW: n[4], screenH: n[5], originX: n[2], originY: n[3], scale: 1, mon: n[0], monCount: n[1], at: Date.now() };
  } finally { try { fs.unlinkSync(tmp); } catch (e) {} }
}
/* Zoom: photograph an EXACT physical rectangle at native resolution (no
   shrinking) with its own coordinate grid. Used by the screenshot_region tool
   and by the automatic re-aim before clicks, so the AI aims on a sharp
   close-up instead of the whole-desktop picture. Windows only. */
async function winCaptureRect(L, T, W, H, srcShot) {
  W = Math.max(120, Math.min(1400, Math.round(W)));
  H = Math.max(90, Math.min(1000, Math.round(H)));
  const tmp = path.join(os.tmpdir(), 'glucer-zoom-' + newId() + '.jpg');
  try {
    const script = [
      ...asmProlog('gd', 'GD', GD_CSHARP),
      '[void][GD]::SetProcessDPIAware()',
      'Add-Type -AssemblyName System.Windows.Forms,System.Drawing',
      '$L = ' + Math.round(L) + '; $T = ' + Math.round(T) + '; $W = ' + W + '; $H = ' + H,
      '$bmp = New-Object System.Drawing.Bitmap $W, $H',
      '$g = [System.Drawing.Graphics]::FromImage($bmp)',
      '$g.CopyFromScreen($L, $T, 0, 0, (New-Object System.Drawing.Size($W, $H)))',
      '# Grid on the close-up too: 100 px lines, labels every 200 px, counting from the close-up own top-left corner.',
      '$gp = New-Object System.Drawing.Pen -ArgumentList ([System.Drawing.Color]::FromArgb(120, 255, 60, 60))',
      'for ($gx = 100; $gx -lt $W; $gx += 100) { $g.DrawLine($gp, $gx, 0, $gx, $H) }',
      'for ($gy = 100; $gy -lt $H; $gy += 100) { $g.DrawLine($gp, 0, $gy, $W, $gy) }',
      '$gf = New-Object System.Drawing.Font -ArgumentList "Arial", 12, ([System.Drawing.FontStyle]::Bold)',
      '$gbs = New-Object System.Drawing.SolidBrush -ArgumentList ([System.Drawing.Color]::FromArgb(160, 0, 0, 0))',
      '$gfs = New-Object System.Drawing.SolidBrush -ArgumentList ([System.Drawing.Color]::FromArgb(235, 255, 220, 60))',
      'for ($gx = 200; $gx -lt $W; $gx += 200) { $gtxt = [string]$gx; $gsz = $g.MeasureString($gtxt, $gf); $g.FillRectangle($gbs, $gx + 3, 3, $gsz.Width, $gsz.Height); $g.DrawString($gtxt, $gf, $gfs, $gx + 3, 3) }',
      'for ($gy = 200; $gy -lt $H; $gy += 200) { $gtxt = [string]$gy; $gsz = $g.MeasureString($gtxt, $gf); $g.FillRectangle($gbs, 3, $gy + 3, $gsz.Width, $gsz.Height); $g.DrawString($gtxt, $gf, $gfs, 3, $gy + 3) }',
      '$bmp.Save($env:GLUCER_OUT, [System.Drawing.Imaging.ImageFormat]::Jpeg)',
      'Write-Output ("{0} {1}" -f $W, $H)'
    ].join('\n');
    const out = await runCmd('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
      { env: Object.assign({}, process.env, { GLUCER_OUT: tmp }), timeout: 60000 });
    const n = out.trim().split(/\s+/).map(Number);
    if (n.length < 2 || !n.every(Number.isFinite)) throw new Error('bad zoom output');
    const buf = fs.readFileSync(tmp);
    if (!buf.length) throw new Error('The zoom picture came out empty.');
    return { mime: 'image/jpeg', data: buf.toString('base64'), imgW: n[0], imgH: n[1], screenW: n[0], screenH: n[1], originX: Math.round(L), originY: Math.round(T), scale: 1, mon: (srcShot && srcShot.mon) || 1, monCount: (srcShot && srcShot.monCount) || 1, region: true, at: Date.now() };
  } finally { try { fs.unlinkSync(tmp); } catch (e) {} }
}
async function takeScreenshot(displayArg, noGrid) {
  if (IS_ELECTRON) {
    const { desktopCapturer, screen } = require('electron');
    const displays = screen.getAllDisplays();
    // On Windows, ALWAYS photograph through Windows itself so every picture
    // has the red coordinate grid, true physical coordinates and the monitor
    // origin — that is what lets the mouse reach every display accurately.
    if (process.platform === 'win32') {
      try { return await winCaptureMonitor(displayArg, noGrid); } catch (e) {}
    }
    const d = screen.getPrimaryDisplay();
    const physW = Math.round(d.size.width * d.scaleFactor), physH = Math.round(d.size.height * d.scaleFactor);
    const w = Math.min(1600, physW);
    const h = Math.max(1, Math.round(w * physH / physW));
    const sources = await desktopCapturer.getSources({ types: ['screen'], thumbnailSize: { width: w, height: h } });
    // display_id is empty on some Windows drivers, so fall back to the source
    // whose picture has the same shape as the primary display.
    const aspect = physW / Math.max(1, physH);
    const src = sources.find((s) => s.display_id === String(d.id)) ||
      sources.find((s) => { const z = s.thumbnail.getSize(); return z.width > 0 && Math.abs(z.width / z.height - aspect) < 0.03; }) ||
      sources[0];
    if (!src || src.thumbnail.isEmpty()) throw new Error('Could not capture the screen.');
    const size = src.thumbnail.getSize();
    return { mime: 'image/jpeg', data: src.thumbnail.toJPEG(75).toString('base64'), imgW: size.width, imgH: size.height, screenW: physW, screenH: physH, originX: 0, originY: 0, mon: displays.findIndex((x) => x.id === d.id) + 1 || 1, monCount: displays.length, scale: d.scaleFactor, at: Date.now() };
  }
  if (process.platform === 'win32') { try { return await winCaptureMonitor(displayArg, noGrid); } catch (e) {} }
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
    return { mime: jpg ? 'image/jpeg' : 'image/png', data: buf.toString('base64'), imgW: imgW || 0, imgH: imgH || 0, screenW: shotDims ? shotDims[0] : (imgW || 0), screenH: shotDims ? shotDims[1] : (imgH || 0), scale: 1, at: Date.now() };
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
  if (!lastShot || !lastShot.imgW) throw new Error('I could not check the screen to aim the mouse.');
  // Mac clicking works in points, not pixels, so divide Retina captures down.
  const divide = process.platform === 'darwin' && lastShot.scale > 1 ? lastShot.scale : 1;
  // The picture may belong to a monitor that does not sit at the desktop's
  // top-left corner (second monitor, or one placed to the left), so add its
  // true position on the desktop before aiming.
  const ox = Number(lastShot.originX) || 0, oy = Number(lastShot.originY) || 0;
  const cx = ox + Math.max(0, Math.min(Math.round(lastShot.screenW / divide) - 1, Math.round(nx * lastShot.screenW / lastShot.imgW / divide)));
  const cy = oy + Math.max(0, Math.min(Math.round(lastShot.screenH / divide) - 1, Math.round(ny * lastShot.screenH / lastShot.imgH / divide)));
  return { cx, cy };
}
// Before any mouse action, if the last look at the screen is older than this,
// silently re-capture it so the coordinates are aimed at the CURRENT screen.
const SHOT_MAX_AGE = 8000;
async function ensureShot() {
  if (lastShot && lastShot.imgW && Date.now() - (lastShot.at || 0) <= SHOT_MAX_AGE) return false;
  // Re-capture the SAME view the AI is aiming with: a zoomed region stays the
  // SAME exact rectangle (its coordinates are crop-local), and a monitor shot
  // re-shoots that monitor — never swap one for the other mid-task.
  try {
    const img = lastShot && lastShot.region
      ? await winCaptureRect(lastShot.originX, lastShot.originY, lastShot.screenW, lastShot.screenH, lastShot)
      : await takeScreenshot(lastShot && lastShot.monCount > 1 ? lastShot.mon : undefined);
    if (img && img.imgW) { lastShot = img; return true; }
  } catch (e) {}
  return false;
}
function winPS(script, extraEnv) {
  return runCmd('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
    extraEnv ? { env: Object.assign({}, process.env, extraEnv), timeout: 60000 } : { timeout: 60000 });
}
const GM_CSHARP = [
  'using System;',
  'using System.Runtime.InteropServices;',
  'public class GM {',
  '  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();',
  '  [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);',
  '  [DllImport("user32.dll")] public static extern int GetSystemMetrics(int n);',
  '  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, int d, UIntPtr e);',
  '}'
].join('\n');
/* Close-up used after a click AND before a click (aim preview). It is cropped at
   native resolution, enlarged 2x so small text is readable, and its yellow grid
   numbers are in the SAME coordinates as the full screenshot - so whatever the AI
   reads off the close-up can be fed straight back into mouse_click. (Before, the
   close-up had no numbers at all, so a "correction" got read in close-up pixels and
   was then applied to the full picture: the click jumped to the wrong place.) */
const CLOSE_W = 480, CLOSE_H = 300, CLOSE_ZOOM = 2, CLOSE_STEP = 50;
function aimLines(x, y, move) {
  const origin = lastShot && (lastShot.region || Number(lastShot.originX) || Number(lastShot.originY));
  const out = [];
  if (origin) {
    out.push('$sx = 1.0; $sy = 1.0', '$px = ' + Math.round(x) + '; $py = ' + Math.round(y));
  } else {
    // Self-calibration: the process that clicks measures the real screen size
    // itself and rescales, so a wrong scale report from Electron can never steer
    // the cursor to the wrong place.
    const eW = Math.max(1, (lastShot && lastShot.screenW) || 0);
    const eH = Math.max(1, (lastShot && lastShot.screenH) || 0);
    out.push('$sx = [double][GM]::GetSystemMetrics(0) / ' + eW, '$sy = [double][GM]::GetSystemMetrics(1) / ' + eH,
      '$px = [int][Math]::Round(' + x + ' * $sx); $py = [int][Math]::Round(' + y + ' * $sy)');
  }
  if (move) out.push('[void][GM]::SetCursorPos($px, $py)');
  return out;
}
function closeupLines() {
  const o = lastShot || {};
  const hasMon = o.region || ((Number(o.originX) || Number(o.originY)) && Number(o.screenW) > 0 && Number(o.screenH) > 0);
  const orgX = hasMon ? Math.round(Number(o.originX) || 0) : 0, orgY = hasMon ? Math.round(Number(o.originY) || 0) : 0;
  const imgW = Math.max(1, Number(o.imgW) || 1), imgH = Math.max(1, Number(o.imgH) || 1);
  const scrW = Math.max(1, Number(o.screenW) || 1), scrH = Math.max(1, Number(o.screenH) || 1);
  // PS variable names are case-INSENSITIVE - every name below is distinct on purpose.
  return [
    'Add-Type -AssemblyName System.Drawing',
    '$mnL = ' + orgX + '; $mnT = ' + orgY,
    hasMon ? '$mnW = ' + Math.round(scrW) + '; $mnH = ' + Math.round(scrH) : '$mnW = [GM]::GetSystemMetrics(0); $mnH = [GM]::GetSystemMetrics(1)',
    '$cw = [Math]::Min(' + CLOSE_W + ', $mnW); $ch = [Math]::Min(' + CLOSE_H + ', $mnH)',
    '$bx = [Math]::Max($mnL, [Math]::Min($mnL + $mnW - $cw, $px - [int]($cw / 2)))',
    '$by = [Math]::Max($mnT, [Math]::Min($mnT + $mnH - $ch, $py - [int]($ch / 2)))',
    '$zm = ' + CLOSE_ZOOM + '; $vw = $cw * $zm; $vh = $ch * $zm',
    '$src = New-Object System.Drawing.Bitmap $cw, $ch',
    '$sg = [System.Drawing.Graphics]::FromImage($src)',
    '$sg.CopyFromScreen($bx, $by, 0, 0, (New-Object System.Drawing.Size($cw, $ch)))',
    '$v = New-Object System.Drawing.Bitmap $vw, $vh',
    '$vg = [System.Drawing.Graphics]::FromImage($v)',
    "$vg.InterpolationMode = 'HighQualityBicubic'",
    '$vg.DrawImage($src, 0, 0, $vw, $vh)',
    // Grid lines every CLOSE_STEP px of the FULL screenshot, labelled in that picture's coordinates.
    '$kfx = ' + imgW + ' / ' + scrW + '; $kfy = ' + imgH + ' / ' + scrH + '; $orgX = ' + orgX + '; $orgY = ' + orgY,
    '$gpn = New-Object System.Drawing.Pen -ArgumentList ([System.Drawing.Color]::FromArgb(110, 255, 60, 60))',
    '$gfn = New-Object System.Drawing.Font -ArgumentList "Arial", 10, ([System.Drawing.FontStyle]::Bold)',
    '$gbr = New-Object System.Drawing.SolidBrush -ArgumentList ([System.Drawing.Color]::FromArgb(170, 0, 0, 0))',
    '$gyl = New-Object System.Drawing.SolidBrush -ArgumentList ([System.Drawing.Color]::FromArgb(240, 255, 220, 60))',
    '$ia = (($bx / $sx) - $orgX) * $kfx; $ib = ((($bx + $cw) / $sx) - $orgX) * $kfx',
    '$ja = (($by / $sy) - $orgY) * $kfy; $jb = ((($by + $ch) / $sy) - $orgY) * $kfy',
    'for ($gi = [Math]::Ceiling($ia / ' + CLOSE_STEP + ') * ' + CLOSE_STEP + '; $gi -lt $ib; $gi += ' + CLOSE_STEP + ') { $gxp = [int]((($orgX + $gi / $kfx) * $sx - $bx) * $zm); $vg.DrawLine($gpn, $gxp, 0, $gxp, $vh); $gtx = [string][int]$gi; $gz = $vg.MeasureString($gtx, $gfn); $vg.FillRectangle($gbr, $gxp + 2, 2, $gz.Width, $gz.Height); $vg.DrawString($gtx, $gfn, $gyl, $gxp + 2, 2) }',
    'for ($gj = [Math]::Ceiling($ja / ' + CLOSE_STEP + ') * ' + CLOSE_STEP + '; $gj -lt $jb; $gj += ' + CLOSE_STEP + ') { $gyp = [int]((($orgY + $gj / $kfy) * $sy - $by) * $zm); $vg.DrawLine($gpn, 0, $gyp, $vw, $gyp); $gtx = [string][int]$gj; $gz = $vg.MeasureString($gtx, $gfn); $vg.FillRectangle($gbr, 2, $gyp + 2, $gz.Width, $gz.Height); $vg.DrawString($gtx, $gfn, $gyl, 2, $gyp + 2) }',
    // Red cross + ring on the exact aim point.
    '$lx = [int](($px - $bx) * $zm); $ly = [int](($py - $by) * $zm)',
    '$vg.DrawLine([System.Drawing.Pens]::Red, $lx - 24, $ly, $lx + 24, $ly)',
    '$vg.DrawLine([System.Drawing.Pens]::Red, $lx, $ly - 24, $lx, $ly + 24)',
    '$vg.DrawEllipse([System.Drawing.Pens]::Red, $lx - 8, $ly - 8, 16, 16)',
    '$vg.FillRectangle([System.Drawing.Brushes]::Red, $lx - 2, $ly - 2, 5, 5)',
    '$v.Save($env:GLUCER_SHOT, [System.Drawing.Imaging.ImageFormat]::Jpeg)'
  ];
}
function mouseScript(x, y, actions, shotPath) {
  const head = asmProlog('gm', 'GM', GM_CSHARP).concat(['[void][GM]::SetProcessDPIAware()']);
  const tail = ['Start-Sleep -Milliseconds 80'].concat(shotPath ? closeupLines() : []);
  return head.concat(aimLines(x, y, true), ['Start-Sleep -Milliseconds 120', actions], tail).join('\n');
}
/* AIM PREVIEW: look at the exact spot BEFORE clicking. The AI guesses pixels from a
   shrunken screenshot (a 30 px button on a 1600 px picture is easy to miss by 20 px),
   so the first mouse_click only shows a sharp close-up with a red cross and clicks
   nothing. The AI then re-sends the same x,y to fire, or sends corrected numbers read
   off the close-up's yellow grid. Set AIM_PREVIEW = false to go back to one-step clicks. */
const AIM_PREVIEW = true;
const AIM_CONFIRM_PX = 3;     // same spot (within this many screenshot px) = "yes, fire"
const AIM_MAX_PREVIEWS = 3;   // after this many previews in a row, fire anyway (no endless loops)
let pendingAim = null;        // { x, y, at, n } in screenshot coordinates
function aimState(ax, ay) {
  if (pendingAim && Date.now() - pendingAim.at > 120000) pendingAim = null;
  const confirmed = !!(pendingAim && Math.hypot(pendingAim.x - Number(ax), pendingAim.y - Number(ay)) <= AIM_CONFIRM_PX);
  const exhausted = !!(pendingAim && pendingAim.n >= AIM_MAX_PREVIEWS);
  return { needPreview: AIM_PREVIEW && process.platform === 'win32' && !confirmed && !exhausted };
}
async function aimPreview(pos) {
  const tmp = path.join(os.tmpdir(), 'glucer-aim-' + newId() + '.jpg');
  try {
    const script = asmProlog('gm', 'GM', GM_CSHARP).concat(['[void][GM]::SetProcessDPIAware()'], aimLines(pos.cx, pos.cy, false), closeupLines()).join('\n');
    await winPS(script, { GLUCER_SHOT: tmp });
    const b = fs.readFileSync(tmp);
    return b.length ? { mime: 'image/jpeg', data: b.toString('base64') } : null;
  } finally { try { fs.unlinkSync(tmp); } catch (e) {} }
}
const GT_BODY = [
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
const GT_CSHARP = ['using System;', 'using System.Runtime.InteropServices;', 'using System.Threading;'].concat(GT_BODY).join('\n');
async function mouseClick(pos, btn, noVerify) {
  if (process.platform === 'win32') {
    const acts = btn === 'right'
      ? '[GM]::mouse_event(8,0,0,0,[UIntPtr]::Zero); Start-Sleep -Milliseconds 50; [GM]::mouse_event(16,0,0,0,[UIntPtr]::Zero)'
      : btn === 'double'
      ? '[GM]::mouse_event(2,0,0,0,[UIntPtr]::Zero); [GM]::mouse_event(4,0,0,0,[UIntPtr]::Zero); Start-Sleep -Milliseconds 70; [GM]::mouse_event(2,0,0,0,[UIntPtr]::Zero); [GM]::mouse_event(4,0,0,0,[UIntPtr]::Zero)'
      : '[GM]::mouse_event(2,0,0,0,[UIntPtr]::Zero); Start-Sleep -Milliseconds 50; [GM]::mouse_event(4,0,0,0,[UIntPtr]::Zero)';
    const tmp = path.join(os.tmpdir(), 'glucer-click-' + newId() + '.jpg');
    try {
      await winPS(mouseScript(pos.cx, pos.cy, acts, noVerify ? null : tmp), { GLUCER_SHOT: tmp });
      let verify = null;
      try { const b = fs.readFileSync(tmp); if (b.length) verify = { mime: 'image/jpeg', data: b.toString('base64') }; } catch (e) {}
      return { verify };
    } finally { try { fs.unlinkSync(tmp); } catch (e) {} }
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
    else await winPS(asmProlog('gm', 'GM', GM_CSHARP).concat(['[void][GM]::SetProcessDPIAware()', 'Start-Sleep -Milliseconds 50', scroll]).join('\n'));
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
    const script = asmProlog('gt', 'GT', GT_CSHARP).concat([
      "$text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + b64 + "'))",
      '[void][GT]::TypeText($text)']).join('\n');
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

/* ---------- Window awareness (see and focus apps without pixel guessing) ---------- */
const LW_CSHARP = [
  'using System;',
  'using System.Text;',
  'using System.Collections.Generic;',
  'using System.Runtime.InteropServices;',
  'public class LW {',
  '  public delegate bool P(IntPtr h, IntPtr l);',
  '  public delegate bool MCB(IntPtr hm, IntPtr dc, ref RECT rc, IntPtr d);',
  '  [DllImport("user32.dll")] public static extern bool EnumWindows(P cb, IntPtr l);',
  '  [DllImport("user32.dll")] public static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr clip, MCB cb, IntPtr d);',
  '  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);',
  '  [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder sb, int n);',
  '  [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);',
  '  [DllImport("user32.dll")] public static extern IntPtr MonitorFromWindow(IntPtr h, uint f);',
  '  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();',
  '  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L; public int T; public int R; public int B; }',
  '  static List<IntPtr> hmons = new List<IntPtr>();',
  '  static bool MonCb(IntPtr hm, IntPtr dc, ref RECT rc, IntPtr d) { hmons.Add(hm); return true; }',
  '  public static List<string> Get() {',
  '    SetProcessDPIAware();',
  '    hmons.Clear();',
  '    EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, MonCb, IntPtr.Zero);',
  '    var outp = new List<string>();',
  '    EnumWindows(delegate(IntPtr h, IntPtr l) {',
  '      if (!IsWindowVisible(h)) return true;',
  '      var sb = new StringBuilder(512);',
  '      if (GetWindowText(h, sb, 512) < 1) return true;',
  '      string t = sb.ToString();',
  '      if (t == "Program Manager" || t == "Windows Input Experience" || t == "Microsoft Text Input Application") return true;',
  '      int mon = 1;',
  '      IntPtr hm = MonitorFromWindow(h, 2);',
  '      if (hm != IntPtr.Zero) { int ix = hmons.IndexOf(hm); if (ix >= 0) mon = ix + 1; }',
  '      outp.Add("[disp " + mon + "] " + (IsIconic(h) ? "[minimized] " : "") + t);',
  '      return true;',
  '    }, IntPtr.Zero);',
  '    return outp;',
  '  }',
  '}'
].join('\n');
const FW_CSHARP = [
  'using System;',
  'using System.Text;',
  'using System.Runtime.InteropServices;',
  'public class FW {',
  '  public delegate bool P(IntPtr h, IntPtr l);',
  '  [DllImport("user32.dll")] public static extern bool EnumWindows(P cb, IntPtr l);',
  '  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);',
  '  [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder sb, int n);',
  '  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);',
  '  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);',
  '  [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);',
  '  [DllImport("user32.dll")] public static extern void keybd_event(byte k, byte s, uint f, UIntPtr e);',
  '  public static string Focus(string q) {',
  '    IntPtr found = IntPtr.Zero; string title = "";',
  '    string ql = q.ToLower();',
  '    EnumWindows(delegate(IntPtr h, IntPtr l) {',
  '      if (!IsWindowVisible(h)) return true;',
  '      var sb = new StringBuilder(512);',
  '      if (GetWindowText(h, sb, 512) < 1) return true;',
  '      string t = sb.ToString();',
  '      if (t.ToLower().Contains(ql)) { found = h; title = t; return false; }',
  '      return true;',
  '    }, IntPtr.Zero);',
  '    if (found == IntPtr.Zero) return "NOTFOUND";',
  '    if (IsIconic(found)) ShowWindow(found, 9);',
  '    keybd_event(0x12, 0, 0, UIntPtr.Zero);',
  '    SetForegroundWindow(found);',
  '    keybd_event(0x12, 0, 2, UIntPtr.Zero);',
  '    return "OK: " + title;',
  '  }',
  '}'
].join('\n');
async function listWindows() {
  if (process.platform === 'win32') {
    const script = asmProlog('lw', 'LW', LW_CSHARP).concat(['[LW]::Get()']).join('\n');
    const out = await winPS(script);
    return out.split(/\r?\n/).map((s) => s.trim()).filter(Boolean).slice(0, 60);
  }
  if (process.platform === 'darwin') {
    const lines = [
      'tell application "System Events"',
      'set outp to ""',
      'repeat with p in (every application process whose visible is true)',
      'repeat with w in (every window of p)',
      'set outp to outp & (name of p) & ": " & (name of w) & linefeed',
      'end repeat',
      'end repeat',
      'return outp',
      'end tell'
    ];
    const out = await runCmd('osascript', lines.flatMap((l) => ['-e', l]));
    return out.split(/\r?\n/).map((s) => s.trim()).filter(Boolean).slice(0, 60);
  }
  try {
    const out = await runCmd('wmctrl', ['-l']);
    return out.split(/\r?\n/).map((l) => l.split(/\s+/).slice(3).join(' ').trim()).filter(Boolean).slice(0, 60);
  } catch (e) {
    try {
      const out = await runCmd('xdotool', ['search', '--onlyvisible', '--name', '', 'getwindowname', '%@']);
      return out.split(/\r?\n/).map((s) => s.trim()).filter(Boolean).slice(0, 60);
    } catch (e2) { throw new Error('Could not list windows. On Linux, Glucer needs the wmctrl or xdotool package installed.'); }
  }
}
async function focusWindow(q) {
  if (process.platform === 'win32') {
    const script = asmProlog('fw', 'FW', FW_CSHARP).concat(['[FW]::Focus($env:GLUCER_Q)']).join('\n');
    const out = (await winPS(script, { GLUCER_Q: q })).trim();
    if (out.startsWith('NOTFOUND')) throw new Error('No window with "' + q + '" in its title. Call list_windows to see the exact titles.');
    return out.replace(/^OK: /, '');
  }
  if (process.platform === 'darwin') {
    const lines = [
      'on run argv',
      'set q to (item 1 of argv)',
      'tell application "System Events"',
      'repeat with p in (every application process whose visible is true)',
      'repeat with w in (every window of p)',
      'if ((name of w) as string) contains q then',
      'set frontmost of p to true',
      'return ("OK: " & (name of w))',
      'end if',
      'end repeat',
      'end repeat',
      'set frontmost of (first application process whose name contains q) to true',
      'return ("OK: " & q)',
      'end tell',
      'end run'
    ];
    const out = (await runCmd('osascript', lines.flatMap((l) => ['-e', l]).concat([q]))).trim();
    return out.replace(/^OK: /, '');
  }
  try { await runCmd('wmctrl', ['-a', q]); return q; }
  catch (e) {
    try { await runCmd('xdotool', ['search', '--name', q, 'windowactivate', '--sync']); return q; }
    catch (e2) { throw new Error('Could not focus that window. On Linux, Glucer needs the wmctrl or xdotool package installed.'); }
  }
}

/* ---------- Click by NAME v3 (UI Automation — exact, fast, self-correcting) ---------- */
/* Asks the app itself where its control is instead of aiming pixels at a
   screenshot. v3 upgrades over v2: matching now understands THE WORDS THE USER
   SEES. Query and every control are normalized (case/punctuation/spacing
   ignored) and scored exact > prefix > contains > all-words > some-words, so
   "Send a message" hits a box whose accessible name differs slightly, and
   placeholder text like "Type here" or "Search" matches even when the Name
   property is empty (HelpText and the field's current Value are scored too,
   plus AutomationId). kind words are aliases now (link->hyperlink,
   text box/input/search box->edit, dropdown->combobox, tab->tabitem, ...) and
   if a kind filter would reject every match, the kind is dropped instead of
   failing the call. Still searches EVERY open window (no focus_window
   needed), presses the control with its own automation pattern
   (Invoke/Toggle/Expand/Select work even off-screen), scrolls it into view
   first, and — when the name is not found — returns the REAL control names
   around it so the very next call succeeds without any screenshot.
   type_text focuses the control and types into it in the same call
   (click + type in one step). */
const UIA_CSHARP = [
  'using System;',
  'using System.Collections.Generic;',
  'using System.Reflection;',
  'using System.Runtime.InteropServices;',
  'using System.Text;',
  'using System.Threading;',
  'using System.Windows.Automation;',
  GT_BODY,
  'public class UIA {',
  '  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();',
  '  [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);',
  '  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, int d, UIntPtr e);',
  '  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);',
  '  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);',
  '  [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hWnd);',
  '  [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);',
  '  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();',
  '  static string Name(AutomationElement e) { try { return e.Current.Name; } catch (Exception) { return null; } }',
  '  static string Kind(AutomationElement e) { try { return e.Current.ControlType.ProgrammaticName.Replace("ControlType.", ""); } catch (Exception) { return ""; } }',
  '  static bool OnScreen(AutomationElement e) { try { return !e.Current.IsOffscreen; } catch (Exception) { return true; } }',
  '  static bool Usable(AutomationElement e) { try { return e.Current.IsEnabled; } catch (Exception) { return true; } }',
  '  static void ScrollIn(AutomationElement e) {',
  '    try { var s = e.GetCurrentPattern(ScrollItemPattern.Pattern) as ScrollItemPattern; if (s != null) s.ScrollIntoView(); } catch (Exception) {}',
  '  }',
  '  static AutomationElement Root() {',
  '    SetProcessDPIAware();',
  '    IntPtr h = GetForegroundWindow();',
  '    if (h != IntPtr.Zero) { try { return AutomationElement.FromHandle(h); } catch (Exception) {} }',
  // FocusedElement is the REAL property name - "FocusedWindow" does not exist
  // in System.Windows.Automation and its compile error used to kill the whole
  // UIA class, silently disabling precise clicking for everyone.
  '    try { return AutomationElement.FocusedElement; } catch (Exception) {}',
  '    return AutomationElement.RootElement;',
  '  }',
  '  static IntPtr WinHandle(AutomationElement e) {',
  '    // The top-level real window that owns this control (needed to raise it before a physical click or typing - clicking physical pixels while another window sits on top would hit THAT window instead).',
  '    try {',
  '      AutomationElement w = e;',
  '      for (int i = 0; i < 30; i++) {',
  '        if (w.Current.NativeWindowHandle != 0) return (IntPtr)w.Current.NativeWindowHandle;',
  '        AutomationElement p = TreeWalker.ControlViewWalker.GetParent(w);',
  '        if (p == null || p == AutomationElement.RootElement) break;',
  '        w = p;',
  '      }',
  '    } catch (Exception) {}',
  '    return IntPtr.Zero;',
  '  }',
  '  static void ToFront(IntPtr h) {',
  '    // Bring the owning window forward before a physical click or typing. The quick ALT tap is the standard trick that lets SetForegroundWindow work when another app holds focus; it is skipped entirely when the window is already foreground.',
  '    if (h == IntPtr.Zero) return;',
  '    try {',
  '      if (GetForegroundWindow() == h) return;',
  '      if (IsIconic(h)) ShowWindow(h, 9); // SW_RESTORE, in case it was minimized',
  '      keybd_event(0x12, 0, 0, UIntPtr.Zero);',
  '      SetForegroundWindow(h);',
  '      keybd_event(0x12, 0, 2, UIntPtr.Zero); // KEYEVENTF_KEYUP',
  '      Thread.Sleep(180);',
  '    } catch (Exception) {}',
  '  }',
  '  static bool Strong(List<Cand> l) { foreach (var c in l) { if (c.score >= 78) return true; } return false; }',
  '  public class Cand { public AutomationElement el; public string name; public string kind; public int score; public bool kok; }',
  '  static string Norm(string s) {',
  '    if (s == null) return "";',
  '    var sb = new StringBuilder();',
  '    foreach (char ch in s.ToLower()) { if (char.IsLetterOrDigit(ch)) sb.Append(ch); else sb.Append(\' \'); }',
  '    var parts = sb.ToString().Split(new char[] { \' \' }, StringSplitOptions.RemoveEmptyEntries);',
  '    return string.Join(" ", parts);',
  '  }',
  '  static string[] MeaningfulWords(string s) {',
  '    var stop = new string[] { "the", "an", "to", "of", "in", "on", "at", "for", "and", "or", "please", "my", "me", "this", "that", "it", "is", "be" };',
  '    var w = Norm(s).Split(new char[] { \' \' }, StringSplitOptions.RemoveEmptyEntries);',
  '    var keep = new List<string>();',
  '    foreach (var x in w) { if (x.Length > 1 && Array.IndexOf(stop, x) < 0) keep.Add(x); }',
  '    return keep.ToArray();',
  '  }',
  '  static int ScoreText(string text, string ql, string[] qw) {',
  '    if (string.IsNullOrEmpty(text)) return -1;',
  '    string t = Norm(text);',
  '    if (t.Length == 0) return -1;',
  '    if (t == ql) return 100;',
  '    if (t.StartsWith(ql)) return 88;',
  '    if (t.IndexOf(ql, StringComparison.Ordinal) >= 0) return 78;',
  '    string[] tw = t.Split(new char[] { \' \' }, StringSplitOptions.RemoveEmptyEntries);',
  '    if (qw.Length > 0 && tw.Length > 0) {',
  '      int hit = 0;',
  '      foreach (var w in qw) { if (Array.IndexOf(tw, w) >= 0) hit++; }',
  '      if (hit == qw.Length && qw.Length > 1) return 74;',
  '      if (hit > 0) { int sc = 20 + (int)(50.0 * hit / qw.Length); if (sc > 60) sc = 60; return sc; }',
  '    }',
  '    return -1;',
  '  }',
  '  static string Help(AutomationElement e) { try { return e.Current.HelpText; } catch (Exception) { return null; } }',
  '  static string Val(AutomationElement e) { try { var vp = e.GetCurrentPattern(ValuePattern.Pattern) as ValuePattern; return vp == null ? null : vp.Current.Value; } catch (Exception) { return null; } }',
  '  static string KindFilter(string kind) {',
  '    string k = Norm(kind).Replace(" ", "");',
  '    if (k == "") return "";',
  '    if (k == "link" || k == "hyperlink" || k == "url") return "hyperlink";',
  '    if (k == "text" || k == "textbox" || k == "textarea" || k == "input" || k == "field" || k == "textfield" || k == "entry" || k == "searchbox" || k == "searchbar" || k == "searchfield" || k == "editor" || k == "messagebox" || k == "chatbox" || k == "chatinput") return "edit";',
  '    if (k == "dropdown" || k == "select" || k == "combo" || k == "combobox") return "combobox";',
  '    if (k == "tab" || k == "tabitem" || k == "tabpage") return "tabitem";',
  '    if (k == "radio" || k == "radiobutton") return "radiobutton";',
  '    if (k == "check" || k == "checkbox" || k == "tickbox") return "checkbox";',
  '    if (k == "list" || k == "listbox" || k == "listitem" || k == "row") return "listitem";',
  '    if (k == "image" || k == "icon" || k == "picture") return "image";',
  '    return k;',
  '  }',
  '  static bool KindOk(string kd, string kf) {',
  '    if (kf == "") return true;',
  '    if (kd == "") return false;',
  '    if (kd == kf) return true;',
  '    return kd.IndexOf(kf, StringComparison.Ordinal) >= 0 || kf.IndexOf(kd, StringComparison.Ordinal) >= 0;',
  '  }',
  '  static void Search(AutomationElement win, string ql, string[] qw, string kf, string intent, List<Cand> found) {',
  '    AutomationElementCollection kids;',
  '    var cond = new PropertyCondition(AutomationElement.IsControlElementProperty, true);',
  '    try { kids = win.FindAll(TreeScope.Descendants, cond); } catch (Exception) { return; }',
  '    int seen = 0;',
  '    var any = new List<Cand>();',
  '    foreach (AutomationElement k in kids) {',
  '      if (++seen > 6000) break; // big web pages have thousands of nodes - 3000 used to cut off before reaching the target',
  '      string n = Name(k);',
  '      int s = ScoreText(n, ql, qw);',
  '      string help = null, val = null, aid = null;',
  '      if (s < 78) { help = Help(k); int s2 = ScoreText(help, ql, qw); if (s2 - 6 > s) s = s2 - 6; }',
  '      if (s < 78) { val = Val(k); int s2 = ScoreText(val, ql, qw); if (s2 - 8 > s) s = s2 - 8; }',
  '      if (s < 78) { try { aid = k.Current.AutomationId; } catch (Exception) {} int s2 = ScoreText(aid, ql, qw); if (s2 - 12 > s) s = s2 - 12; }',
  '      if (s <= 0) continue;',
  '      string kd = Kind(k);',
  '      string kdl = kd.ToLower();',
  '      bool kok = KindOk(kdl, kf);',
  '      if (!Usable(k)) s -= 40;',
  '      if (!OnScreen(k)) s -= 20;',
  '      if (s <= 0) continue;',
  '      // Kind-aware tie-break: when TYPING, prefer the text box; when CLICKING, prefer the button-like control. Two elements often share the same words (a label and its button).',
  '      if (intent == "type") { if (kdl == "edit") s += 6; else if (kdl == "combobox") s += 4; }',
  '      else { if (kdl == "button") s += 5; else if (kdl == "hyperlink") s += 4; else if (kdl == "menuitem") s += 3; else if (kdl == "tabitem") s += 2; }',
  '      any.Add(new Cand { el = k, name = (n ?? help ?? val ?? aid ?? ""), kind = kd, score = s, kok = kok });',
  '    }',
  '    foreach (var c in any) { if (c.kok) found.Add(c); }',
  '    if (found.Count == 0) { foreach (var c in any) { found.Add(new Cand { el = c.el, name = c.name, kind = c.kind, score = c.score - 5 }); } }',
  '  }',
  '  static string WindowTitle(AutomationElement e) {',
  '    try {',
  '      AutomationElement w = e;',
  '      for (int i = 0; i < 30; i++) {',
  '        AutomationElement p = TreeWalker.ControlViewWalker.GetParent(w);',
  '        if (p == null || p == AutomationElement.RootElement) break;',
  '        w = p;',
  '      }',
  '      return Name(w) ?? "";',
  '    } catch (Exception) { return ""; }',
  '  }',
  '  static void CollectNames(AutomationElement p, int depth, List<string> outp) {',
  '    if (p == null || depth > 8 || outp.Count >= 14) return;',
  '    AutomationElementCollection kids;',
  '    try { kids = p.FindAll(TreeScope.Children, Condition.TrueCondition); } catch (Exception) { return; }',
  '    foreach (AutomationElement k in kids) {',
  '      string n = Name(k);',
  '      string kd = Kind(k).ToLower();',
  '      bool clickable = kd.Contains("button") || kd.Contains("menu") || kd.Contains("item") || kd.Contains("hyperlink") || kd.Contains("check") || kd.Contains("radio") || kd.Contains("combo") || kd.Contains("tab") || kd.Contains("edit");',
  '      if (!string.IsNullOrEmpty(n) && clickable && kd != "tooltip") {',
  '        string one = Kind(k) + " \'" + n + "\'";',
  '        if (!outp.Contains(one)) outp.Add(one);',
  '      }',
  '      if (outp.Count >= 14) return;',
  '      CollectNames(k, depth + 1, outp);',
  '    }',
  '  }',
  '  static string Act(AutomationElement el) {',
  '    object p;',
  '    try { p = el.GetCurrentPattern(InvokePattern.Pattern); if (p is InvokePattern) { ((InvokePattern)p).Invoke(); return "invoked"; } } catch (Exception) {}',
  '    try { p = el.GetCurrentPattern(TogglePattern.Pattern); if (p is TogglePattern) { ((TogglePattern)p).Toggle(); return "toggled"; } } catch (Exception) {}',
  '    try { p = el.GetCurrentPattern(ExpandCollapsePattern.Pattern); if (p is ExpandCollapsePattern) { ((ExpandCollapsePattern)p).Expand(); return "expanded"; } } catch (Exception) {}',
  '    try { p = el.GetCurrentPattern(SelectionItemPattern.Pattern); if (p is SelectionItemPattern) { ((SelectionItemPattern)p).Select(); return "selected"; } } catch (Exception) {}',
  '    // LegacyIAccessiblePattern is referenced by REFLECTION, never by name: naming it breaks the Add-Type compile on some machines, and one compile error used to disable ALL clicking.',
  '    try { foreach (AutomationPattern apat in el.GetSupportedPatterns()) { if (apat.ProgrammaticName.IndexOf("LegacyIAccessible", StringComparison.OrdinalIgnoreCase) >= 0) { object lp = el.GetCurrentPattern(apat); MethodInfo mi = lp.GetType().GetMethod("DoDefaultAction"); if (mi != null) { mi.Invoke(lp, null); return "pressed"; } } } } catch (Exception) {}',
  '    double x = 0, y = 0; bool got = false;',
  '    try { var pt = el.GetClickablePoint(); x = pt.X; y = pt.Y; got = true; } catch (Exception) {}',
  '    if (!got) { try { var r = el.Current.BoundingRectangle; x = r.X + r.Width / 2; y = r.Y + r.Height / 2; got = r.Width > 0 && r.Height > 0; } catch (Exception) {} }',
  '    if (!got) return null;',
  '    SetCursorPos((int)x, (int)y);',
  '    Thread.Sleep(120);',
  '    mouse_event(2, 0, 0, 0, UIntPtr.Zero); Thread.Sleep(40); mouse_event(4, 0, 0, 0, UIntPtr.Zero);',
  '    return "clicked at (" + (int)x + ", " + (int)y + ")";',
  '  }',
  '  public static string Click(string name, string kind, string typeText) {',
  '    SetProcessDPIAware();',
  '    string ql = Norm(name);',
  '    if (ql.Length == 0) return "ERR: no usable name given (letters or digits needed).";',
  '    string[] qw = MeaningfulWords(name);',
  '    string kf = KindFilter(kind);',
  '    string intent = string.IsNullOrEmpty(typeText) ? "click" : "type";',
  '    var found = new List<Cand>();',
  '    AutomationElement fg = null;',
  '    try { IntPtr h = GetForegroundWindow(); if (h != IntPtr.Zero) fg = AutomationElement.FromHandle(h); } catch (Exception) {}',
  '    if (fg == null) { try { fg = AutomationElement.FocusedElement; } catch (Exception) {} }',
  '    if (fg != null) Search(fg, ql, qw, kf, intent, found);',
  '    if (!Strong(found)) {',
  '      // Keep scanning OTHER open windows until a strong (near-exact) match turns up - stopping at the first weak match of the wrong window used to click the wrong app.',
  '      try {',
  '        int fh = 0;',
  '        try { if (fg != null) fh = fg.Current.NativeWindowHandle; } catch (Exception) {}',
  '        var tops = AutomationElement.RootElement.FindAll(TreeScope.Children, Condition.TrueCondition);',
  '        int scanned = 0;',
  '        foreach (AutomationElement w in tops) {',
  '          if (++scanned > 30) break;',
  '          try { if (fh != 0 && w.Current.NativeWindowHandle == fh) continue; } catch (Exception) {}',
  '          string wn = Name(w) ?? "";',
  '          if (wn == "" || wn == "Program Manager") continue;',
  '          Search(w, ql, qw, kf, intent, found);',
  '          if (Strong(found)) break;',
  '        }',
  '      } catch (Exception) {}',
  '    }',
  '    if (found.Count == 0) {',
  '      var names = new List<string>();',
  '      CollectNames(fg, 0, names);',
  '      string hint = names.Count > 0 ? " The real controls in the active window are: " + string.Join("; ", names) + "." : "";',
  '      return "ERR: no control" + (string.IsNullOrEmpty(kf) ? "" : " of kind " + kf) + " matching \'" + name + "\' in any open window." + hint + " Retry click_element with one of those exact names (kind is optional - plain words like link or text box are understood) - no screenshot needed.";',
  '    }',
  '    found.Sort((a, b) => b.score.CompareTo(a.score));',
  '    Cand best = found[0];',
  '    ScrollIn(best.el);',
  '    IntPtr wh = WinHandle(best.el);',
  '    if (!string.IsNullOrEmpty(typeText)) {',
  '      ToFront(wh);',
  '      try { best.el.SetFocus(); } catch (Exception) {}',
  '      Thread.Sleep(250);',
  '      string typed = GT.TypeText(typeText);',
  '      return "OK focused " + best.kind + " \'" + best.name + "\' in window \'" + WindowTitle(best.el) + "\' and " + typed;',
  '    }',
  '    ToFront(wh);',
  '    string how = Act(best.el);',
  '    if (how == null) return "ERR: found " + best.kind + " \'" + best.name + "\' but it has no clickable position. Take a screenshot and use mouse_click instead.";',
  '    return "OK " + how + " " + best.kind + " \'" + best.name + "\' in window \'" + WindowTitle(best.el) + "\'";',
  '  }',
  '  static void Collect(AutomationElement p, int depth, List<string> outp, int cap) {',
  '    if (p == null || depth > 7 || outp.Count >= cap) return;',
  '    AutomationElementCollection kids;',
  '    try { kids = p.FindAll(TreeScope.Children, Condition.TrueCondition); } catch (Exception) { return; }',
  '    foreach (AutomationElement k in kids) {',
  '      string n = Name(k);',
  '      string c = "";',
  '      try { c = k.Current.ControlType.ProgrammaticName.Replace("ControlType.", ""); } catch (Exception) {}',
  '      if (string.IsNullOrEmpty(n)) { string hp = Help(k); if (!string.IsNullOrEmpty(hp) && (c == "Edit" || c == "Document")) n = hp; }',
  '      if (!string.IsNullOrEmpty(n) && c != "ToolTip") outp.Add(c + ": " + n);',
  '      if (outp.Count >= cap) return;',
  '      Collect(k, depth + 1, outp, cap);',
  '    }',
  '  }',
  '  public static List<string> List() {',
  '    // Every open window, each block labeled with its title, so the model can pick an exact name from ANY app - not just the active one.',
  '    var outp = new List<string>();',
  '    AutomationElement fg = null;',
  '    try { IntPtr h = GetForegroundWindow(); if (h != IntPtr.Zero) fg = AutomationElement.FromHandle(h); } catch (Exception) {}',
  '    int fh = 0;',
  '    try { if (fg != null) fh = fg.Current.NativeWindowHandle; } catch (Exception) {}',
  '    if (fg != null) Collect(fg, 0, outp, 60);',
  '    try {',
  '      var tops = AutomationElement.RootElement.FindAll(TreeScope.Children, Condition.TrueCondition);',
  '      int scanned = 0;',
  '      foreach (AutomationElement w in tops) {',
  '        if (++scanned > 30 || outp.Count >= 140) break;',
  '        try { if (fh != 0 && w.Current.NativeWindowHandle == fh) continue; } catch (Exception) {}',
  '        string wn = Name(w) ?? "";',
  '        if (wn == "" || wn == "Program Manager") continue;',
  '        int before = outp.Count;',
  '        outp.Add("[window] " + wn);',
  '        Collect(w, 0, outp, Math.Min(before + 21, 140));',
  '        if (outp.Count == before + 1) outp.RemoveAt(before); // window had no named controls',
  '      }',
  '    } catch (Exception) {}',
  '    return outp;',
  '  }',
  '}'
].join('\n');
/* GT_BODY ships inside UIA_CSHARP so the Click method can call GT.TypeText
   directly when click_element is used with type_text. */
const UIA_PS_PROLOG = asmProlog('uia', 'UIA', UIA_CSHARP, 'UIAutomationClient,UIAutomationTypes,WindowsBase');
async function listElements() {
  if (process.platform === 'win32') {
    const out = await winPS(UIA_PS_PROLOG.concat(['[UIA]::List()']).join('\n'));
    return out.split(/\r?\n/).map((s) => s.trim()).filter(Boolean).slice(0, 150);
  }
  if (process.platform === 'darwin') {
    const lines = [
      'tell application "System Events"',
      'set ps to first application process whose frontmost is true',
      'set outp to ""',
      'repeat with e in (every UI element of window 1 of ps)',
      'try',
      'set outp to outp & (role of e) & ": " & (name of e) & linefeed',
      'end try',
      'end repeat',
      'return outp',
      'end tell'
    ];
    const out = await runCmd('osascript', lines.flatMap((l) => ['-e', l]));
    return out.split(/\r?\n/).map((s) => s.trim()).filter(Boolean).slice(0, 80);
  }
  throw new Error('Listing window elements is not supported on this version of Linux yet. Take a screenshot and use mouse_click instead.');
}
async function clickElement(name, kind, typeText) {
  if (process.platform === 'win32') {
    const out = (await winPS(UIA_PS_PROLOG.concat(['[UIA]::Click($env:GLUCER_NAME, $env:GLUCER_KIND, $env:GLUCER_TYPE)']).join('\n'), { GLUCER_NAME: name, GLUCER_KIND: kind || '', GLUCER_TYPE: typeText || '' })).trim();
    if (out.startsWith('ERR')) throw new Error(out.replace(/^ERR:\s*/, ''));
    return out.replace(/^OK\s*/, '');
  }
  if (process.platform === 'darwin') {
    const lines = [
      'on run argv',
      'set q to (item 1 of argv)',
      'set ttext to ""',
      'if (count of argv) > 1 then set ttext to (item 2 of argv)',
      'tell application "System Events"',
      'set ps to first application process whose frontmost is true',
      'repeat with e in (every UI element of window 1 of ps)',
      'try',
      'if ((name of e) as string) contains q then',
      'click e',
      'if ttext is not "" then',
      'delay 0.2',
      'keystroke ttext',
      'return ("OK focused " & (name of e) & " and typed")',
      'end if',
      'return ("OK clicked " & (name of e))',
      'end if',
      'end try',
      'end repeat',
      'return "ERR: no element with that name in the front window. The front window has these: " & (name of every UI element of window 1 of ps whose name is not missing value)',
      'end tell',
      'end run'
    ];
    const out = (await runCmd('osascript', lines.flatMap((l) => ['-e', l]).concat([typeText ? [name, typeText] : [name]]).flat())).trim();
    if (out.startsWith('ERR')) throw new Error(out.replace(/^ERR:\s*/, ''));
    return out.replace(/^OK\s*/, '');
  }
  throw new Error('Clicking by name is not supported on this version of Linux yet. Take a screenshot and use mouse_click instead.');
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
const READ_OK_TOOLS = new Set(['system_info', 'list_folder', 'find_files', 'search_in_files', 'read_text_file', 'read_document', 'reveal_item', 'screenshot', 'screenshot_region', 'clipboard_read', 'list_windows', 'list_elements', '__activity']);

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
      const disp = a.display == null || a.display === '' ? null : (Number(a.display) >= 1 ? Math.round(Number(a.display)) : null);
      return { d, disp, clean: !!a.clean, risk: 'high', lines: ['Take a screenshot' + (disp ? ' of monitor ' + disp : ' of the monitor with the active window') + (d ? ' in ' + d + ' seconds (switch to the window you want Glucer to see)' : ''), 'The picture is sent to the AI service to answer you. Close anything private first.'] };
    },
    run: async (a, p) => {
      if (p.d) await sleep(p.d * 1000);
      const image = await takeScreenshot(p.disp, p.clean);
      if (image.imgW) { lastShot = image; pendingAim = null; }
      const monTxt = image.monCount > 1 ? ' — monitor ' + (image.mon || 1) + ' of ' + image.monCount : '';
      return ok({ note: 'The screenshot is attached to this message as an image, with a red coordinate grid and yellow number labels drawn on it — read the x,y for mouse tools straight off those labels. Mouse tool coordinates are plain pixels (NOT a 0-1000 scale, NOT percentages) in THIS picture (' + image.imgW + 'x' + image.imgH + ')' + monTxt + ', and clicking works on every monitor. If what you want to click shows words on screen (a button label, or placeholder text inside a box like "Send a message" or "Type here"), use click_element with those exact words — it is far more accurate than clicking pixels.', monitor: image.mon || 1, monitors: image.monCount || 1 }, 'Looked at your screen' + monTxt, { image });
    }
  },

  screenshot_region: {
    plan: (a) => {
      if (process.platform !== 'win32') throw new Error('Zooming into a region is only supported on Windows for now. Use the regular screenshot instead.');
      if (!lastShot || !lastShot.imgW) throw new Error('Take a full screenshot first, then zoom into it.');
      const x = Number(a.x), y = Number(a.y);
      if (!Number.isFinite(x) || !Number.isFinite(y)) throw new Error('Give the center of the area to zoom into as x,y — pixels in the last picture.');
      const w = Math.max(160, Math.min(1400, Math.round(Number(a.width) || 500)));
      const h = Math.max(120, Math.min(1000, Math.round(Number(a.height) || 350)));
      return { x, y, w, h, risk: 'high', lines: ['Zoom into the screen around (' + Math.round(x) + ', ' + Math.round(y) + ') to see it at full resolution', 'The picture is sent to the AI service to answer you. Close anything private first.'] };
    },
    run: async (a, p) => {
      const src = lastShot;
      const sx = Number(src.screenW) / Math.max(1, Number(src.imgW));
      const sy = Number(src.screenH) / Math.max(1, Number(src.imgH));
      const pcx = (Number(src.originX) || 0) + Math.round(p.x * sx);
      const pcy = (Number(src.originY) || 0) + Math.round(p.y * sy);
      const pw = Math.max(120, Math.round(p.w * sx)), ph = Math.max(90, Math.round(p.h * sy));
      const mL = Number(src.originX) || 0, mT = Number(src.originY) || 0;
      const mW = Math.max(120, Number(src.screenW) || 0), mH = Math.max(90, Number(src.screenH) || 0);
      const L = Math.max(mL, Math.min(mL + mW - pw, pcx - Math.round(pw / 2)));
      const T = Math.max(mT, Math.min(mT + mH - ph, pcy - Math.round(ph / 2)));
      const img = await winCaptureRect(L, T, pw, ph, src);
      lastShot = img; pendingAim = null;
      return ok({ note: 'A sharp close-up is attached with its own coordinate grid. Its yellow labels count from the close-up\'s OWN top-left corner, and mouse tool coordinates are pixels in THIS picture — click using these labels for pinpoint accuracy.', zoomed: true }, 'Zoomed in around (' + Math.round(p.x) + ', ' + Math.round(p.y) + ')', { image: img });
    }
  },

  list_windows: {
    plan: () => ({ lines: ['List the titles of the windows open on your screen'] }),
    run: async () => {
      const titles = await listWindows();
      if (!titles.length) throw new Error('No open windows with titles were found.');
      return ok({ windows: titles, count: titles.length }, 'Found ' + titles.length + ' open window' + (titles.length === 1 ? '' : 's'));
    }
  },

  focus_window: {
    plan: (a) => {
      const q = String(a.title || '').trim();
      if (!q) throw new Error('Say which window to focus (part of its title, like "Notepad").');
      return { q, lines: ['Bring this window to the front: "' + q + '"'] };
    },
    run: async (a, p) => {
      const t = await focusWindow(p.q);
      return ok({ focused: t }, 'Focused "' + t + '" — the keyboard now types there');
    }
  },

  list_elements: {
    plan: () => ({ lines: ['List the clickable things (buttons, menus, links, text boxes) in every open window, by name'] }),
    run: async () => {
      const items = await listElements();
      if (!items.length) throw new Error('No named elements found in any open window (they may not support this). Take a screenshot and use mouse_click instead.');
      return ok({ elements: items, count: items.length }, 'Found ' + items.length + ' named things across your open windows (blocks starting [window] show which app each belongs to)');
    }
  },

  click_element: {
    plan: (a) => {
      const name = String(a.name || '').trim();
      if (!name) throw new Error('Say what to click (its name, like "File" or "Save").');
      const rawKind = String(a.kind || '').trim().toLowerCase();
      const kind = /^[a-z][a-z0-9 _-]{0,30}$/.test(rawKind) ? rawKind : ''; // any plain kind word passes - the C# side normalizes aliases and falls back if a kind rejects every match
      let typeText = null;
      if (a.type_text != null && String(a.type_text) !== '') {
        typeText = String(a.type_text);
        if (typeText.length > 500) throw new Error('That text is too long to type. For long text, use clipboard_write, then key_press with ctrl+v.');
      }
      return { name, kind, typeText, lines: ['Click "' + name + '"' + (kind ? ' (' + kind + ')' : '') + (typeText ? ' and type into it' : '') + ' — by name, in whatever window has it'] };
    },
    run: async (a, p) => {
      const detail = await clickElement(p.name, p.kind, p.typeText);
      return ok({ clicked: p.name, detail }, p.typeText ? 'Clicked "' + p.name + '" and typed' : 'Clicked "' + p.name + '" by name');
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
      // Web links must reach the real browser. In the desktop app that is
      // Electron's shell.openExternal; standalone mode uses the OS launcher
      // (rundll32 on Windows - NOT explorer.exe, which can open a File
      // Explorer window instead of the browser).
      if (p.kind === 'url') {
        if (shellOpen) { await shellOpen(p.target); return ok({ opened: p.target, via: 'browser' }, 'Opened in your browser'); }
        let cmd, args;
        if (process.platform === 'win32') { cmd = 'rundll32'; args = ['url.dll,FileProtocolHandler', p.target]; }
        else { cmd = process.platform === 'darwin' ? 'open' : 'xdg-open'; args = [p.target]; }
        spawn(cmd, args, { detached: true, stdio: 'ignore' }).on('error', () => {}).unref();
        return ok({ opened: p.target, via: 'browser' }, 'Opened in your browser');
      }
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
      const btn = ['left', 'right', 'double'].includes(a.button) ? a.button : 'left';
      const p = (lastShot && lastShot.imgW) ? toScreen(a.x, a.y) : null;
      const preview = !!p && aimState(a.x, a.y).needPreview;
      return { btn, ax: a.x, ay: a.y, p, lines: [preview
        ? 'Aim the mouse at screen position (' + p.cx + ', ' + p.cy + ') and show a close-up first (nothing is clicked yet)'
        : (btn === 'double' ? 'DOUBLE-click' : 'Click the ' + btn.toUpperCase() + ' mouse button') + (p ? ' at screen position (' + p.cx + ', ' + p.cy + ')' : ' on the screen')] };
    },
    run: async (a, p) => {
      const reAimed = await ensureShot();
      const pos = toScreen(p.ax, p.ay);
      if (aimState(p.ax, p.ay).needPreview) {
        let img = null;
        try { img = await aimPreview(pos); } catch (e) {}
        if (img) {
          pendingAim = { x: Number(p.ax), y: Number(p.ay), at: Date.now(), n: (pendingAim ? pendingAim.n : 0) + 1 };
          return ok(
            { clicked: false, aimed_at: { x: Number(p.ax), y: Number(p.ay) }, note: 'NOTHING WAS CLICKED YET. The attached close-up is sharp, enlarged 2x, and the red cross is exactly where the click would land. Its yellow grid numbers are in the SAME coordinates as your screenshot. If the cross is on the thing you want, call mouse_click again with the SAME x and y to fire. If it is off, call mouse_click with corrected x,y read off the yellow grid numbers.' },
            'Aimed at (' + pos.cx + ', ' + pos.cy + ') - close-up shown, nothing clicked yet',
            { image: img }
          );
        }
      }
      pendingAim = null;
      const res = await mouseClick(pos, p.btn);
      const v = res && res.verify;
      return ok(
        { x: pos.cx, y: pos.cy, button: p.btn, check: v ? 'A close-up is attached. The red cross marks EXACTLY where the click landed, and its yellow grid numbers are in the same coordinates as your screenshot. If the cross is not on the thing you meant to click, call mouse_click again with corrected x,y read off those numbers - the screen is re-checked automatically.' : 'No verification picture this time - take a screenshot to check the result.' },
        'Clicked ' + p.btn + ' at (' + pos.cx + ', ' + pos.cy + ')' + (reAimed ? ' (screen was re-checked just before, so the aim is current)' : ''),
        v ? { image: v } : undefined
      );
    }
  },

  /* Computer Use: runs ONE action chosen by Gemini's computer-use model. Its x,y are on a
     0-999 grid over the clean screenshot, so they convert with a single multiply. The
     aim-preview is skipped on purpose - this model is trained to aim. */
  cu_act: {
    plan: (a) => {
      if (!a || !a.name) throw new Error('No action given.');
      return { n: String(a.name), g: a.args || {}, lines: ['Computer Use: ' + a.name + (a.args && a.args.intent ? ' - ' + String(a.args.intent).slice(0, 120) : '')] };
    },
    run: async (a, p) => {
      const g = p.g, n = p.n;
      if (!lastShot || !lastShot.imgW) lastShot = await takeScreenshot(undefined, true);
      const pos = (x, y) => toScreen(Number(x) / 1000 * lastShot.imgW, Number(y) / 1000 * lastShot.imgH);
      if (n === 'click') await mouseClick(pos(g.x, g.y), 'left', true);
      else if (n === 'double_click' || n === 'triple_click') await mouseClick(pos(g.x, g.y), 'double', true);
      else if (n === 'right_click') await mouseClick(pos(g.x, g.y), 'right', true);
      else if (n === 'move') { const q = pos(g.x, g.y); await winPS(mouseScript(q.cx, q.cy, 'Start-Sleep -Milliseconds 10')); }
      else if (n === 'type') { await keyboardType(String(g.text || '')); if (g.press_enter) await keyPress(parseCombo('enter')); }
      else if (n === 'press_key') await keyPress(parseCombo(g.key));
      else if (n === 'hotkey') await keyPress(parseCombo((g.keys || []).join('+')));
      else if (n === 'scroll') {
        if (g.direction !== 'up' && g.direction !== 'down') throw new Error('Only up/down scrolling is supported.');
        await mouseScroll(pos(g.x, g.y), g.direction, Math.max(1, Math.min(10, Math.round((Number(g.magnitude_in_pixels) || 300) / 100))));
      }
      else if (n === 'wait') await sleep(Math.min(10, Number(g.seconds) || 1) * 1000);
      else if (n !== 'take_screenshot') throw new Error('Action not supported yet: ' + n);
      await sleep(600);
      const img = await takeScreenshot(lastShot.monCount > 1 ? lastShot.mon : undefined, true);
      lastShot = img; pendingAim = null;
      return ok({ done: n }, 'Did ' + n, { image: img });
    }
  },

  mouse_scroll: {
    plan: (a) => {
      const dir = a.direction === 'up' ? 'up' : 'down';
      const n = Math.max(1, Math.min(10, Math.round(Number(a.clicks) || 3)));
      const pos = (a.x != null && a.y != null && lastShot && lastShot.imgW) ? toScreen(a.x, a.y) : null;
      return { dir, n, ax: a.x, ay: a.y, pos, lines: ['Scroll ' + dir + ' ' + n + ' notches' + (pos ? ' at (' + pos.cx + ', ' + pos.cy + ')' : ' where the mouse pointer is')] };
    },
    run: async (a, p) => {
      let pos = p.pos;
      if (p.ax != null && p.ay != null) { await ensureShot(); pos = toScreen(p.ax, p.ay); }
      await mouseScroll(pos, p.dir, p.n);
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
