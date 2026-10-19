/* Glucer Agent: lets Glucer work with files, apps and commands on this computer.
   Website version:  node glucer-agent.js     (add --strict to approve in this window instead of in Glucer)
   Desktop app:      loaded by the app itself (no server, nothing to run).                              */
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

/* ---------- Undo history ---------- */
const HIST_FILE = path.join(DATA_DIR, 'history.json');
function loadHist() { try { return JSON.parse(fs.readFileSync(HIST_FILE, 'utf8')); } catch (e) { return []; } }
function saveHist(h) { try { fs.mkdirSync(DATA_DIR, { recursive: true }); fs.writeFileSync(HIST_FILE, JSON.stringify(h.slice(-200))); } catch (e) {} }
function logOp(op) { op.id = op.id || newId(); op.time = Date.now(); const h = loadHist(); h.push(op); saveHist(h); return op.id; }

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

/* ---------- Tools ---------- */
const SKIP = new Set(['node_modules', '.git', 'AppData', 'Library', '$Recycle.Bin', 'System Volume Information', 'Windows', 'Program Files', 'Program Files (x86)', '.cache', '.npm']);
const BINARY_EXT = /^(png|jpe?g|gif|webp|ico|bmp|pdf|zip|rar|7z|gz|tar|exe|dll|msi|iso|dmg|mp3|mp4|mov|avi|mkv|wav|flac|ttf|otf|woff2?|bin|dat|db|sqlite|class|jar|so|dylib|docx|xlsx|pptx)$/i;
const RISKY_OPEN = /\.(exe|bat|cmd|ps1|sh|msi|app|command|scr|vbs|jar|lnk)$/i;
const BLOCKED = [
  /\brm\s+-[a-z]*r[a-z]*\s+(\/|~|\$HOME|\*)(\s|$)/i, /\bmkfs/i, /\bdd\s+.*of=\/dev\//i, /\bformat\s+[a-z]:/i,
  /\b(rd|rmdir)\s+\/s.*\b[a-z]:\\?(\s|$)/i, /\bdel\s+.*\b[a-z]:\\\*?(\s|$)/i, /\bdiskpart\b/i, /\bshutdown\b/i, /:\(\)\s*\{/
];

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
      let text = buf.toString('utf8');
      const truncated = text.length > 20000 || st.size > len;
      return ok({ path: p.full, text: text.slice(0, 20000), truncated }, 'Read ' + path.basename(p.full));
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
async function handleCall(name, args, approved) {
  try {
    if (name === '__undo') return await undoOp(args && args.id);
    if (!Object.prototype.hasOwnProperty.call(TOOLS, name)) throw new Error('Unknown tool: ' + String(name).slice(0, 40));
    args = args && typeof args === 'object' ? args : {};
    const tool = TOOLS[name];
    const plan = tool.plan(args);
    if (plan.lines) {
      if (STRICT) { if (!(await termAsk(plan.lines))) throw new Denied(); }
      else if (approved !== true) return { ok: false, needsApproval: true, lines: plan.lines.slice(0, 40), risk: plan.risk || 'normal', summary: 'Waiting for your OK' };
    }
    return await tool.run(args, plan);
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
        const r = await handleCall(String(msg.name || ''), msg.args, msg.approved === true);
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
