(() => {
  const $ = (id) => document.getElementById(id);

  const gate = $("gate");
  const app = $("app");
  const joinForm = $("join-form");
  const nameInput = $("name-input");
  const thread = $("thread");
  const composer = $("composer");
  const textInput = $("text-input");
  const fileInput = $("file-input");
  const typingEl = $("typing");
  const onlineLabel = $("online-label");
  const people = $("people");
  const peopleList = $("people-list");
  const installBtn = $("install-btn");
  const preview = $("preview");
  const previewVideo = $("preview-video");
  const previewImage = $("preview-image");
  const previewClose = $("preview-close");
  const previewSend = $("preview-send");
  const caption = $("caption");
  const toastEl = $("toast");
  const offlineBar = $("offline-bar");
  const adminPanel = $("admin");
  const adminAuth = $("admin-auth");
  const adminTools = $("admin-tools");
  const adminList = $("admin-list");
  const adminCode = $("admin-code");
  const adminLogList = $("admin-log-list");
  const alertStack = $("alert-stack");
  const alertBadge = $("alert-badge");
  let unreadAlerts = 0;
  let lastUsers = [];
  let lastLogs = [];
  let myFlags = { muted: false, blocked: false, banned: false, admin: false };

  let socket = null;
  let me = JSON.parse(localStorage.getItem("chat_user") || "null");
  let authToken = localStorage.getItem("ft_jwt") || "";
  let sessionKey = null;
  let sessionWait = Promise.resolve();
  let sessionWaitRes = null;
  let lastServerPub = "";
  let sessionJti = "";
  let refreshToken = localStorage.getItem("ft_refresh") || "";
  let accessExp = Number(localStorage.getItem("ft_jwt_exp") || 0);
  let refreshTimer = null;
  let pendingFile = null;
  let lastDay = "";
  let typingTimer = null;
  let deferredPrompt = null;
  let reconnectTimer = null;
  let heartbeatTimer = null;
  let reconnectAttempt = 0;
  let flushing = false;
  let manualStatus = (me && me.status) || "available";
  let healthTimer = null;
  const rendered = new Set();
  const typingMap = new Map();
  const PALETTE = [
    "#0084FF", "#00A400", "#FF5CA8", "#F5A623",
    "#7B61FF", "#13C2C2", "#EB2F96", "#2F54EB",
    "#FA541C", "#52C41A",
  ];

  const idb = {
    db: null,
    async open() {
      if (this.db) return this.db;
      this.db = await new Promise((resolve, reject) => {
        const req = indexedDB.open("chat-aberto", 2);
        req.onupgradeneeded = () => {
          const db = req.result;
          if (!db.objectStoreNames.contains("messages")) {
            db.createObjectStore("messages", { keyPath: "id" });
          }
          if (!db.objectStoreNames.contains("outbox")) {
            db.createObjectStore("outbox", { keyPath: "id" });
          }
          if (!db.objectStoreNames.contains("files")) {
            db.createObjectStore("files", { keyPath: "id" });
          }
          if (!db.objectStoreNames.contains("crypto")) {
            db.createObjectStore("crypto", { keyPath: "id" });
          }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
      return this.db;
    },
    async tx(store, mode, fn) {
      const db = await this.open();
      return new Promise((resolve, reject) => {
        const t = db.transaction(store, mode);
        const s = t.objectStore(store);
        const result = fn(s);
        t.oncomplete = () => resolve(result?.result ?? result);
        t.onerror = () => reject(t.error);
      });
    },
    put(store, value) {
      return this.tx(store, "readwrite", (s) => s.put(value));
    },
    get(store, key) {
      return this.tx(store, "readonly", (s) => s.get(key));
    },
    del(store, key) {
      return this.tx(store, "readwrite", (s) => s.delete(key));
    },
    all(store) {
      return this.tx(store, "readonly", (s) => s.getAll());
    },
  };

  let currentGroupId = "aberto";
  let groups = [];
  let pubkeys = {};
  const EMOJIS = ["😀","😁","😂","🤣","😊","😍","😘","😜","🤔","😎","😭","😡","👍","👎","❤️","🔥","🎉","🙏","👏","✅","❌","😅","😇","🥰","😋","😴","🤝","💯","🙌","👀","💪","🫂","🌸","⭐","😊","😉","🤗","😴","🤤","😷","🤒","🥳","😏","😬","🙄","😶","😮","😢","😤","👋","✌️","🤞","👌","🤙","👊","💖","💙","💚","💜","🖤","🤍","🤎","💛","🧡"];

  const b64 = {
    enc(buf) {
      const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
      let s = "";
      bytes.forEach((n) => { s += String.fromCharCode(n); });
      return btoa(s);
    },
    dec(text) {
      const raw = atob(text);
      const out = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
      return out;
    },
  };

  const e2e = {
    pair: null,
    pub: null,
    groupKeys: {},
    async boot() {
      if (this.pair) return this.pair;
      const saved = await idb.get("crypto", "identity").catch(() => null);
      if (saved?.priv) {
        this.pair = {
          privateKey: await crypto.subtle.importKey("jwk", saved.priv, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]),
          publicKey: await crypto.subtle.importKey("jwk", saved.pub, { name: "ECDH", namedCurve: "P-256" }, true, []),
        };
      } else {
        this.pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
        const priv = await crypto.subtle.exportKey("jwk", this.pair.privateKey);
        const pub = await crypto.subtle.exportKey("jwk", this.pair.publicKey);
        await idb.put("crypto", { id: "identity", priv, pub });
      }
      const raw = await crypto.subtle.exportKey("raw", this.pair.publicKey);
      this.pub = b64.enc(raw);
      return this.pair;
    },
    async importPub(rawB64) {
      return crypto.subtle.importKey("raw", b64.dec(rawB64), { name: "ECDH", namedCurve: "P-256" }, true, []);
    },
    async sharedAes(theirB64) {
      const their = await this.importPub(theirB64);
      const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: their }, this.pair.privateKey, 256);
      return crypto.subtle.importKey("raw", bits, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    },
    async newGroupKey() {
      const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
      return key;
    },
    async exportGroupKey(key) {
      return b64.enc(await crypto.subtle.exportKey("raw", key));
    },
    async importGroupKey(rawB64) {
      return crypto.subtle.importKey("raw", b64.dec(rawB64), { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
    },
    async wrapFor(theirB64, groupKey) {
      const aes = await this.sharedAes(theirB64);
      const raw = await crypto.subtle.exportKey("raw", groupKey);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aes, raw);
      return { iv: b64.enc(iv), ct: b64.enc(ct) };
    },
    async unwrapFrom(theirB64, blob) {
      const aes = await this.sharedAes(theirB64);
      const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64.dec(blob.iv) }, aes, b64.dec(blob.ct));
      return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
    },
    async encryptText(gid, text) {
      const key = this.groupKeys[gid];
      if (!key) return null;
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(text || ""));
      return { e2e: true, iv: b64.enc(iv), ct: b64.enc(ct) };
    },
    async decryptText(gid, iv, ct) {
      const key = this.groupKeys[gid];
      if (!key || !iv || !ct) return null;
      try {
        const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64.dec(iv) }, key, b64.dec(ct));
        return new TextDecoder().decode(pt);
      } catch {
        return null;
      }
    },
    async adoptWraps(gid, wraps, keys) {
      await this.boot();
      const mine = (me?.name || "").toLowerCase();
      const mineWrap = wraps && (wraps[mine] || wraps[me?.name]);
      if (mineWrap && keys[mineWrap.from]) {
        try {
          this.groupKeys[gid] = await this.unwrapFrom(keys[mineWrap.from], mineWrap);
          await idb.put("crypto", { id: `g:${gid}`, raw: await this.exportGroupKey(this.groupKeys[gid]) });
          return true;
        } catch {
          /* fall through */
        }
      }
      const saved = await idb.get("crypto", `g:${gid}`).catch(() => null);
      if (saved?.raw) {
        this.groupKeys[gid] = await this.importGroupKey(saved.raw);
        return true;
      }
      if (!this.groupKeys[gid]) {
        this.groupKeys[gid] = await this.newGroupKey();
        await idb.put("crypto", { id: `g:${gid}`, raw: await this.exportGroupKey(this.groupKeys[gid]) });
      }
      return true;
    },
    async shareWraps(gid) {
      const key = this.groupKeys[gid];
      if (!key) return;
      const wraps = {};
      for (const [name, raw] of Object.entries(pubkeys || {})) {
        if (!raw || name.toLowerCase() === (me?.name || "").toLowerCase()) continue;
        try {
          wraps[name.toLowerCase()] = await this.wrapFor(raw, key);
        } catch {
          /* skip bad key */
        }
      }
      if (Object.keys(wraps).length) emit({ op: "key_wraps", groupId: gid, wraps });
    },
    async fingerprint(rawB64) {
      if (!rawB64) return "";
      const digest = await crypto.subtle.digest("SHA-256", b64.dec(rawB64));
      const hex = [...new Uint8Array(digest)].map((n) => n.toString(16).padStart(2, "0")).join("");
      return hex.toUpperCase().replace(/(.{4})/g, "$1 ").trim();
    },
    async pairNumber(theirB64) {
      await this.boot();
      const a = this.pub || "";
      const b = theirB64 || "";
      const ordered = [a, b].sort().join("|");
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(ordered));
      const hex = [...new Uint8Array(digest)].map((n) => n.toString(16).padStart(2, "0")).join("");
      return hex.toUpperCase().replace(/(.{4})/g, "$1 ").trim();
    },
  };

  const identity = {
    peers: {},
    myFp: "",
    async load() {
      const rows = await idb.all("crypto").catch(() => []);
      (rows || []).forEach((row) => {
        if (row?.id && String(row.id).startsWith("peer:")) {
          this.peers[row.id.slice(5)] = row;
        }
      });
    },
    async rememberMe() {
      await e2e.boot();
      this.myFp = await e2e.fingerprint(e2e.pub);
      const rec = (await idb.get("crypto", "identity").catch(() => null)) || { id: "identity" };
      rec.pubRaw = e2e.pub;
      rec.fp = this.myFp;
      rec.storedAt = Date.now();
      await idb.put("crypto", rec);
      const el = $("my-fp");
      if (el) el.textContent = this.myFp || "indisponível";
    },
    async inspect(map) {
      pubkeys = map || pubkeys;
      await this.load();
      await this.rememberMe();
      const changes = [];
      for (const [name, key] of Object.entries(pubkeys || {})) {
        if (!name || !key) continue;
        const k = name.toLowerCase();
        if (me && k === me.name.toLowerCase()) continue;
        const fp = await e2e.fingerprint(key);
        const prev = this.peers[k];
        const rec = {
          id: `peer:${k}`,
          name,
          key,
          fp,
          verified: prev?.verified && prev.key === key,
          changed: Boolean(prev && prev.key && prev.key !== key),
          previousFp: prev && prev.key !== key ? prev.fp : prev?.previousFp,
          seenAt: Date.now(),
        };
        if (rec.changed) {
          rec.verified = false;
          changes.push(rec);
        }
        this.peers[k] = rec;
        await idb.put("crypto", rec);
      }
      this.render();
      return changes;
    },
    async setVerified(name, verified) {
      const k = name.toLowerCase();
      const rec = this.peers[k];
      if (!rec) return;
      rec.verified = verified;
      rec.changed = verified ? false : rec.changed;
      rec.verifiedAt = verified ? Date.now() : null;
      await idb.put("crypto", rec);
      this.render();
      renderUsers(lastUsers);
    },
    statusOf(name) {
      const rec = this.peers[(name || "").toLowerCase()];
      if (!rec) return null;
      if (rec.changed) return "changed";
      if (rec.verified) return "verified";
      return "seen";
    },
    render() {
      const list = $("id-list");
      if (!list) return;
      list.innerHTML = "";
      const rows = Object.values(this.peers).sort((a, b) => String(a.name).localeCompare(String(b.name)));
      if (!rows.length) {
        const empty = document.createElement("li");
        empty.textContent = "Nenhuma chave de contato ainda.";
        list.appendChild(empty);
        return;
      }
      rows.forEach((rec) => {
        const li = document.createElement("li");
        const title = document.createElement("strong");
        title.textContent = rec.name;
        if (rec.verified) {
          const tag = document.createElement("em");
          tag.className = "badge verified";
          tag.textContent = "verificado";
          title.appendChild(tag);
        } else if (rec.changed) {
          const tag = document.createElement("em");
          tag.className = "badge changed";
          tag.textContent = "chave mudou";
          title.appendChild(tag);
        }
        const fp = document.createElement("div");
        fp.className = "fp-mini";
        fp.textContent = rec.fp || "";
        const actions = document.createElement("div");
        actions.className = "id-actions";
        const pairBtn = document.createElement("button");
        pairBtn.type = "button";
        pairBtn.textContent = "Código do par";
        pairBtn.addEventListener("click", async () => {
          const num = await e2e.pairNumber(rec.key);
          toast("Código do par copiado");
          navigator.clipboard?.writeText(`${rec.name}\n${num}`).catch(() => {});
          fp.textContent = num;
        });
        const vBtn = document.createElement("button");
        vBtn.type = "button";
        vBtn.className = rec.verified ? "warn" : "ok";
        vBtn.textContent = rec.verified ? "Remover verificação" : "Marcar verificado";
        vBtn.addEventListener("click", () => this.setVerified(rec.name, !rec.verified));
        actions.appendChild(pairBtn);
        actions.appendChild(vBtn);
        li.appendChild(title);
        li.appendChild(fp);
        li.appendChild(actions);
        list.appendChild(li);
      });
    },
  };

  if (me?.name) nameInput.value = me.name;

  function uid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    return `c-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }

  function colorFromName(name) {
    let hash = 0;
    for (let i = 0; i < name.length; i++) hash = name.charCodeAt(i) + ((hash << 5) - hash);
    return PALETTE[Math.abs(hash) % PALETTE.length];
  }

  function isOnline() {
    return navigator.onLine !== false;
  }

  function socketOpen() {
    return socket && socket.readyState === WebSocket.OPEN;
  }

  function bumpAlertBadge() {
    if (!alertBadge) return;
    const open = adminPanel && !adminPanel.classList.contains("hidden");
    if (open) {
      unreadAlerts = 0;
      alertBadge.classList.add("hidden");
      return;
    }
    unreadAlerts += 1;
    alertBadge.textContent = unreadAlerts > 9 ? "9+" : String(unreadAlerts);
    alertBadge.classList.remove("hidden");
  }

  function beep(level) {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.value = level === "danger" ? 220 : level === "warning" ? 360 : 520;
      gain.gain.value = 0.04;
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      setTimeout(() => {
        osc.stop();
        ctx.close();
      }, 160);
    } catch {
      /* ignore */
    }
  }

  function desktopNotify(title, text) {
    if (!("Notification" in window) || Notification.permission !== "granted") return;
    if (!document.hidden) return;
    try {
      new Notification(title, { body: text, icon: "/icons/icon-192.png" });
    } catch {
      /* ignore */
    }
  }

  function showModAlert(data) {
    if (!alertStack) {
      toast(data.text || data.title || "Alerta");
      return;
    }
    const card = document.createElement("div");
    card.className = `alert-card ${data.level || "info"}`;
    const body = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = data.title || "Moderação";
    const text = document.createElement("span");
    text.textContent = data.text || "";
    body.appendChild(title);
    body.appendChild(text);
    const close = document.createElement("button");
    close.type = "button";
    close.textContent = "✕";
    close.addEventListener("click", () => card.remove());
    card.appendChild(body);
    card.appendChild(close);
    alertStack.prepend(card);
    while (alertStack.children.length > 4) alertStack.lastChild.remove();
    setTimeout(() => card.remove(), data.level === "danger" ? 10000 : 6500);
    beep(data.level);
    bumpAlertBadge();
    desktopNotify(data.title || "Moderação", data.text || "");
    if (me && data.target === me.name && data.action) {
      if (data.action === "mute") toast("Você foi silenciado.");
      if (data.action === "block") toast("Você foi bloqueado.");
      if (data.action === "ban") toast("Você foi banido.");
    }
  }

  function toast(text) {
    toastEl.textContent = text;
    toastEl.classList.remove("hidden");
    setTimeout(() => toastEl.classList.add("hidden"), 2400);
  }

  function setOfflineUI() {
    const netDown = !isOnline();
    const wsDown = !socketOpen();
    offlineBar.classList.toggle("hidden", !netDown);
    if (netDown) {
      onlineLabel.textContent = "sem internet";
      onlineLabel.style.color = "#ffd56a";
    } else if (wsDown) {
      onlineLabel.textContent = "conectando…";
      onlineLabel.style.color = "#53bdeb";
    } else {
      onlineLabel.style.color = "#00a884";
    }
  }

  function initials(name) {
    return String(name || "?")
      .trim()
      .split(/\s+/)
      .slice(0, 2)
      .map((p) => p[0]?.toUpperCase() || "")
      .join("") || "?";
  }

  function formatTime(ts) {
    return new Date(ts).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" });
  }

  function formatDay(ts) {
    const d = new Date(ts);
    const today = new Date();
    const yesterday = new Date();
    yesterday.setDate(today.getDate() - 1);
    if (d.toDateString() === today.toDateString()) return "Hoje";
    if (d.toDateString() === yesterday.toDateString()) return "Ontem";
    return d.toLocaleDateString("pt-BR");
  }

  function scrollBottom(force) {
    const near = thread.scrollHeight - thread.scrollTop - thread.clientHeight < 140;
    if (force || near) thread.scrollTop = thread.scrollHeight;
  }

  function addDayIfNeeded(ts) {
    const day = formatDay(ts);
    if (day !== lastDay) {
      lastDay = day;
      const el = document.createElement("div");
      el.className = "day-sep";
      el.textContent = day;
      thread.appendChild(el);
    }
  }

  function renderSystem(msg) {
    if (!msg?.id || rendered.has(msg.id)) return;
    rendered.add(msg.id);
    addDayIfNeeded(msg.createdAt);
    const el = document.createElement("div");
    el.className = "sys";
    el.textContent = msg.text;
    thread.appendChild(el);
    scrollBottom();
  }

  let replyTo = null;
  const msgIndex = new Map();

  function tickStatus(msg) {
    if (msg.pending || msg.status === "pending") return "pending";
    if (msg.status === "read" || (msg.readBy && msg.readBy.length)) return "read";
    if (msg.status === "delivered" || (msg.deliveredTo && msg.deliveredTo.length)) return "delivered";
    return "sent";
  }

  function ticksHtml(status) {
    if (status === "pending") return "🕒";
    if (status === "sent") return "✓";
    if (status === "delivered") return "✓✓";
    if (status === "read") return "✓✓";
    return "✓";
  }

  function applyTicks(row, msg) {
    const st = tickStatus(msg);
    row.classList.toggle("pending", st === "pending");
    row.dataset.status = st;
    const ticks = row.querySelector(".ticks");
    if (ticks) {
      ticks.className = `ticks ${st}`;
      ticks.textContent = ticksHtml(st);
    }
    const time = row.querySelector(".msg-time");
    if (time) time.textContent = formatTime(msg.createdAt);
  }

  function quoteLabel(reply) {
    if (!reply) return "";
    if (reply.type === "video") return reply.text || "Vídeo";
    if (reply.type === "image") return reply.text || "Foto";
    return reply.text || "Mensagem";
  }

  function setReply(msg) {
    if (!msg || msg.deleted) return;
    replyTo = {
      id: msg.id,
      author: msg.author,
      text: quoteLabel(msg),
      type: msg.type || "text",
    };
    $("reply-name").textContent = msg.author || "";
    $("reply-text").textContent = replyTo.text;
    $("reply-bar").classList.remove("hidden");
    textInput.focus();
  }

  function clearReply() {
    replyTo = null;
    $("reply-bar").classList.add("hidden");
  }

  function renderMessage(msg, forceScroll) {
    if (!msg?.id) return;
    msgIndex.set(msg.id, { ...(msgIndex.get(msg.id) || {}), ...msg });
    if (msg.clientId) msgIndex.set(msg.clientId, msgIndex.get(msg.id));

    const existing = document.querySelector(`[data-mid="${CSS.escape(msg.id)}"]`)
      || (msg.clientId && document.querySelector(`[data-cid="${CSS.escape(msg.clientId)}"]`));
    if (existing) {
      if (msg.deleted) {
        existing.classList.add("deleted");
        const bubble = existing.querySelector(".bubble") || existing.querySelector(".media");
        if (bubble) {
          bubble.className = "bubble";
          bubble.textContent = "Mensagem apagada";
        }
      }
      applyTicks(existing, msg);
      rendered.add(msg.id);
      if (msg.clientId) rendered.add(msg.clientId);
      return;
    }
    if (rendered.has(msg.id) || (msg.clientId && rendered.has(msg.clientId))) return;
    rendered.add(msg.id);
    if (msg.clientId) rendered.add(msg.clientId);
    addDayIfNeeded(msg.createdAt);

    const mine = me && msg.author === me.name;
    const row = document.createElement("div");
    row.className = `row ${mine ? "me" : "them"}${msg.pending ? " pending" : ""}${msg.deleted ? " deleted" : ""}`;
    row.dataset.mid = msg.id;
    if (msg.clientId) row.dataset.cid = msg.clientId;

    const av = document.createElement("div");
    av.className = "avatar";
    av.style.background = msg.color || "#00a884";
    av.textContent = initials(msg.author);

    const col = document.createElement("div");
    col.className = "col";

    if (!mine) {
      const who = document.createElement("div");
      who.className = "author";
      who.textContent = msg.author;
      col.appendChild(who);
    }

    const bubble = document.createElement("div");
    bubble.className = msg.deleted ? "bubble" : (msg.type === "video" || msg.type === "image" ? "media" : "bubble");

    if (msg.replyTo) {
      const q = document.createElement("div");
      q.className = "quote";
      q.innerHTML = "<strong></strong><span></span>";
      q.querySelector("strong").textContent = msg.replyTo.author || "";
      q.querySelector("span").textContent = quoteLabel(msg.replyTo);
      bubble.appendChild(q);
    }

    if (msg.deleted) {
      const t = document.createElement("div");
      t.textContent = "Mensagem apagada";
      bubble.appendChild(t);
    } else if (msg.type === "video") {
      const v = document.createElement("video");
      v.controls = true;
      v.playsInline = true;
      v.preload = "metadata";
      if (msg.thumb) v.poster = msg.thumb;
      v.src = msg.mediaUrl;
      bubble.appendChild(v);
      if (msg.text) {
        const cap = document.createElement("div");
        cap.className = "cap";
        cap.textContent = msg.text;
        bubble.appendChild(cap);
      }
    } else if (msg.type === "radio") {
      const wrap = document.createElement("div");
      const tag = document.createElement("div");
      tag.textContent = "📡 Rádio";
      const audio = document.createElement("audio");
      audio.controls = true;
      audio.preload = "metadata";
      audio.src = msg.mediaUrl;
      wrap.appendChild(tag);
      wrap.appendChild(audio);
      bubble.appendChild(wrap);
      if (!mine && !document.hidden) {
        audio.play().catch(() => {});
      }
    } else if (msg.type === "image") {
      const img = document.createElement("img");
      img.src = msg.mediaUrl;
      img.alt = msg.text || "imagem";
      bubble.appendChild(img);
      if (msg.text) {
        const cap = document.createElement("div");
        cap.className = "cap";
        cap.textContent = msg.text;
        bubble.appendChild(cap);
      }
    } else {
      const t = document.createElement("div");
      t.textContent = msg.text;
      bubble.appendChild(t);
      if (msg.edited) {
        const ed = document.createElement("small");
        ed.style.opacity = ".7";
        ed.textContent = " editada";
        t.appendChild(ed);
      }
    }

    const meta = document.createElement("div");
    meta.className = "meta-line";
    const time = document.createElement("span");
    time.className = "msg-time";
    time.textContent = formatTime(msg.createdAt);
    meta.appendChild(time);
    if (mine) {
      const ticks = document.createElement("span");
      ticks.className = "ticks";
      meta.appendChild(ticks);
    }
    bubble.appendChild(meta);
    col.appendChild(bubble);

    row.appendChild(av);
    row.appendChild(col);
    row.addEventListener("click", () => setReply(msgIndex.get(msg.id) || msg));
    row.addEventListener("contextmenu", (ev) => {
      ev.preventDefault();
      messageActions(msg, mine);
    });
    row.addEventListener("dblclick", () => {
      if (mine) messageActions(msg, true);
    });
    thread.appendChild(row);
    applyTicks(row, msg);
    scrollBottom(forceScroll);
  }

  function ackVisible(kind) {
    if (!me?.name || !socketOpen()) return;
    const ids = [...msgIndex.values()]
      .filter((m) => m && m.author && m.author !== me.name && !m.deleted)
      .map((m) => m.id)
      .filter(Boolean);
    if (!ids.length) return;
    emit({ op: "receipts", kind, ids: [...new Set(ids)].slice(-80) });
  }

  async function revealMessage(msg) {
    if (!msg || msg.deleted) return msg;
    if (msg.e2e && msg.iv && msg.ct) {
      const gid = msg.groupId || currentGroupId;
      const plain = await e2e.decryptText(gid, msg.iv, msg.ct);
      msg.text = plain || "🔒 Mensagem criptografada";
    }
    return msg;
  }

  function currentGroup() {
    return groups.find((g) => g.id === currentGroupId) || { id: "aberto", name: "FT Chat", kind: "public" };
  }

  function renderGroups() {
    const list = $("groups-list");
    if (!list) return;
    list.innerHTML = "";
    const title = $("room-title");
    const g = currentGroup();
    if (title) title.textContent = `${g.name} 🔒`;
    (groups.length ? groups : [{ id: "aberto", name: "FT Chat", kind: "public" }]).forEach((row) => {
      const li = document.createElement("li");
      if (row.id === currentGroupId) li.className = "on";
      const label = row.kind === "dm" && me
        ? (row.members || []).find((n) => n.toLowerCase() !== me.name.toLowerCase()) || row.name
        : row.name;
      li.textContent = label;
      const lock = document.createElement("span");
      lock.className = "lock-dot";
      lock.textContent = row.kind === "public" ? "público · E2E" : `${(row.members || []).length} membros · E2E`;
      li.appendChild(lock);
      li.addEventListener("click", () => switchGroup(row.id));
      list.appendChild(li);
    });
  }

  function goHome() {
    currentGroupId = "aberto";
    renderGroups();
    emit({ op: "join_group", groupId: "aberto" });
    $("roster")?.classList.remove("open");
    toast("Chat aberto");
  }

  function messageActions(msg, mine) {
    if (!msg || msg.deleted) return;
    if (mine) {
      const choice = prompt("1 = editar\n2 = apagar para todos\nCancelar = nada", "2");
      if (choice === "1") {
        const next = prompt("Nova mensagem", msg.text || "");
        if (next && next.trim()) emit({ op: "edit", id: msg.id, text: next.trim() });
      } else if (choice === "2") {
        if (confirm("Apagar para todos?")) emit({ op: "delete", id: msg.id });
      }
      return;
    }
    setReply(msg);
  }

  function switchGroup(gid) {
    if (!gid || gid === currentGroupId) return;
    currentGroupId = gid;
    renderGroups();
    emit({ op: "join_group", groupId: gid });
    $("groups").classList.add("hidden");
  }

  function enterApp() {
    gate.classList.add("hidden");
    app.classList.remove("hidden");
    textInput.focus();
    setOfflineUI();
  }

  function jwtJti(tok) {
    try {
      let mid = String(tok || "").split(".")[1] || "";
      mid = mid.replace(/-/g, "+").replace(/_/g, "/");
      while (mid.length % 4) mid += "=";
      return JSON.parse(atob(mid)).jti || "";
    } catch {
      return "";
    }
  }

  function sessionAad() {
    return new TextEncoder().encode(`ft-session:${sessionJti}`);
  }

  async function openSession(serverPub) {
    if (!authToken) throw new Error("JWT ausente para abrir a sessão");
    sessionJti = jwtJti(authToken);
    if (!sessionJti) throw new Error("JWT sem jti");
    const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const raw = await crypto.subtle.exportKey("raw", pair.publicKey);
    const their = await crypto.subtle.importKey("raw", b64.dec(serverPub), { name: "ECDH", namedCurve: "P-256" }, true, []);
    const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: their }, pair.privateKey, 256);
    const base = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
    sessionKey = await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new TextEncoder().encode("ft-chat-session"),
        info: new TextEncoder().encode("ws-aesgcm"),
      },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    if (socketOpen()) {
      socket.send(JSON.stringify({
        op: "session_open",
        publicKey: b64.enc(raw),
        token: authToken,
      }));
    }
  }

  async function sealSession(obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: sessionAad() },
      sessionKey,
      new TextEncoder().encode(JSON.stringify(obj)),
    );
    return { sess: true, iv: b64.enc(iv), ct: b64.enc(ct) };
  }

  async function openSessionBox(blob) {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64.dec(blob.iv), additionalData: sessionAad() },
      sessionKey,
      b64.dec(blob.ct),
    );
    return JSON.parse(new TextDecoder().decode(pt));
  }

  function emit(payload) {
    if (!socketOpen()) return false;
    if (authToken && payload.op !== "ping" && payload.op !== "session_open") {
      payload.token = payload.token || authToken;
    }
    if (sessionKey && payload.op !== "session_open") {
      sealSession(payload).then((env) => {
        if (socketOpen()) socket.send(JSON.stringify(env));
      }).catch(() => {});
      return true;
    }
    socket.send(JSON.stringify(payload));
    return true;
  }

  function saveTokens(data, name) {
    authToken = data.accessToken || data.token || "";
    if (data.refreshToken) refreshToken = data.refreshToken;
    accessExp = Date.now() + Math.max(30, Number(data.expiresIn || 900)) * 1000;
    localStorage.setItem("ft_jwt", authToken);
    localStorage.setItem("ft_refresh", refreshToken || "");
    localStorage.setItem("ft_jwt_name", name);
    localStorage.setItem("ft_jwt_exp", String(accessExp));
    scheduleRefresh(name);
    return authToken;
  }

  function scheduleRefresh(name) {
    clearTimeout(refreshTimer);
    if (!name) return;
    const wait = Math.max(4000, accessExp - Date.now() - 60000);
    refreshTimer = setTimeout(() => {
      refreshAccess(name).catch(() => {});
    }, wait);
  }

  async function refreshAccess(name) {
    if (!refreshToken) return ensureAuth(name, true);
    const res = await fetch("/api/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.status === 401 || res.status === 403) {
      refreshToken = "";
      localStorage.removeItem("ft_refresh");
      return ensureAuth(name, true);
    }
    if (!res.ok) throw new Error(data.error || "Falha ao renovar sessão");
    return saveTokens(data, data.name || name);
  }

  async function ensureAuth(name, forceLogin) {
    if (!forceLogin && refreshToken && localStorage.getItem("ft_jwt_name") === name) {
      if (!authToken || accessExp - Date.now() < 90000) {
        return refreshAccess(name);
      }
      scheduleRefresh(name);
      return authToken;
    }
    const res = await fetch("/api/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || "Falha no login JWT");
    return saveTokens(data, name);
  }

  async function joinNow(name) {
    const status = manualStatus === "busy"
      ? "busy"
      : (document.hidden ? "away" : (manualStatus || "available"));
    await ensureAuth(name);
    if (!sessionKey && lastServerPub) {
      try {
        sessionWait = new Promise((resolve) => { sessionWaitRes = resolve; });
        await openSession(lastServerPub);
      } catch {
        sessionWaitRes && sessionWaitRes();
      }
    }
    await Promise.race([
      sessionWait || Promise.resolve(),
      new Promise((resolve) => setTimeout(resolve, 2500)),
    ]);
    return emit({ op: "join", name, status, publicKey: e2e.pub, token: authToken });
  }

  async function cacheMessage(msg) {
    const copy = { ...msg };
    delete copy.file;
    await idb.put("messages", copy);
  }

  async function loadLocalHistory() {
    try {
      const list = (await idb.all("messages")) || [];
      list.sort((a, b) => a.createdAt - b.createdAt);
      list.forEach((m) => {
        if (m.type === "system") renderSystem(m);
        else renderMessage(m, false);
      });
      const box = (await idb.all("outbox")) || [];
      for (const item of box) {
        if (!item.localPreview) continue;
        if (item.kind === "media") {
          const fileRec = await idb.get("files", item.id);
          if (fileRec?.blob) {
            item.localPreview.mediaUrl = URL.createObjectURL(fileRec.blob);
          }
        }
        renderMessage(item.localPreview, false);
      }
      scrollBottom(true);
    } catch (err) {
      console.warn("histórico local", err);
    }
  }

  async function enqueue(item) {
    await idb.put("outbox", item);
    if (item.localPreview) await cacheMessage(item.localPreview);
    if (navigator.serviceWorker?.ready) {
      navigator.serviceWorker.ready.then((reg) => {
        if (reg.sync) reg.sync.register("chat-flush").catch(() => {});
      });
    }
  }

  async function flushOutbox() {
    if (flushing || !socketOpen() || !me?.name) return;
    flushing = true;
    try {
      const items = ((await idb.all("outbox")) || []).sort((a, b) => a.createdAt - b.createdAt);
      for (const item of items) {
        if (item.kind === "media") {
          const fileRec = await idb.get("files", item.id);
          if (!fileRec?.blob) {
            await idb.del("outbox", item.id);
            continue;
          }
          const file = fileRec.blob instanceof File
            ? fileRec.blob
            : new File([fileRec.blob], fileRec.name || "arquivo", { type: fileRec.type || item.mime });
          const meta = await uploadFile(file);
          const ok = emit({
            op: "message",
            clientId: item.id,
            type: meta.type,
            text: item.text || "",
            mediaUrl: meta.url,
            thumb: meta.thumb,
            duration: meta.duration,
            mime: meta.mime,
            replyTo: item.replyTo || item.localPreview?.replyTo,
          });
          if (!ok) return;
          await idb.del("files", item.id);
          await idb.del("outbox", item.id);
        } else {
          const ok = emit({
            op: "message",
            clientId: item.id,
            type: "text",
            text: item.e2e ? "" : item.text,
            replyTo: item.replyTo || item.localPreview?.replyTo,
            groupId: item.groupId || currentGroupId,
            e2e: item.e2e,
            iv: item.iv,
            ct: item.ct,
          });
          if (!ok) return;
          await idb.del("outbox", item.id);
        }
      }
    } catch (err) {
      console.warn("fila offline", err);
    } finally {
      flushing = false;
    }
  }

  function scheduleReconnect() {
    clearTimeout(reconnectTimer);
    const wait = Math.min(4000, 250 * Math.pow(1.35, reconnectAttempt));
    reconnectAttempt += 1;
    reconnectTimer = setTimeout(connect, wait);
  }

  function startHeartbeat() {
    clearInterval(heartbeatTimer);
    heartbeatTimer = setInterval(() => {
      if (socketOpen()) emit({ op: "ping", t: Date.now() });
    }, 20000);
  }

  function connect() {
    if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
      return;
    }
    const proto = location.protocol === "https:" ? "wss" : "ws";
    try {
      socket = new WebSocket(`${proto}://${location.host}/ws`);
    } catch {
      setOfflineUI();
      scheduleReconnect();
      return;
    }

    socket.addEventListener("open", () => {
      reconnectAttempt = 0;
      sessionKey = null;
      sessionWait = new Promise((resolve) => { sessionWaitRes = resolve; });
      setTimeout(() => sessionWaitRes && sessionWaitRes(), 2500);
      setOfflineUI();
      startHeartbeat();
    });

    socket.addEventListener("close", () => {
      clearInterval(heartbeatTimer);
      setOfflineUI();
      scheduleReconnect();
    });

    socket.addEventListener("error", () => {
      setOfflineUI();
    });

    socket.addEventListener("message", async (ev) => {
      let data;
      try {
        data = JSON.parse(ev.data);
      } catch {
        return;
      }
      if (data.sess && sessionKey) {
        try {
          data = await openSessionBox(data);
        } catch {
          return;
        }
      }
      onEvent(data);
    });
  }

  function onEvent(data) {
    switch (data.op) {
      case "pubkeys":
        identity.inspect(data.pubkeys || pubkeys).then((changes) => {
          changes.forEach((rec) => {
            toast(`A chave E2E de ${rec.name} mudou. Confira a identidade.`);
            showModAlert({
              level: "danger",
              title: "Chave de identidade mudou",
              text: `${rec.name} está com uma chave nova. Compare o código antes de marcar como verificado.`,
              action: "key_changed",
            });
          });
        });
        e2e.shareWraps(currentGroupId);
        break;
      case "key_changed":
        if (data.name && me && data.name !== me.name) {
          identity.inspect(pubkeys);
          toast(`Identidade de ${data.name} foi regenerada neste aparelho.`);
        }
        break;
      case "key_wraps":
        if (data.pubkeys) pubkeys = data.pubkeys;
        e2e.adoptWraps(data.groupId || currentGroupId, data.wraps || {}, pubkeys).then(() => {
          e2e.shareWraps(data.groupId || currentGroupId);
        });
        break;
      case "group_created":
        groups = data.groups || groups;
        if (data.group) switchGroup(data.group.id);
        renderGroups();
        toast("Grupo criado.");
        break;
      case "group_updated":
        groups = groups.map((g) => g.id === data.group.id ? data.group : g);
        if (!groups.find((g) => g.id === data.group.id)) groups.push(data.group);
        renderGroups();
        break;
      case "joined":
        if (data.groups) groups = data.groups;
        if (data.pubkeys) pubkeys = data.pubkeys;
        identity.inspect(pubkeys);
        currentGroupId = data.groupId || "aberto";
        e2e.adoptWraps(currentGroupId, data.wraps || {}, pubkeys).then(() => e2e.shareWraps(currentGroupId));
        renderGroups();
        me = { name: data.name, color: data.color, status: data.status || "available", admin: !!data.admin };
        myFlags = {
          muted: !!data.muted,
          blocked: !!data.blocked,
          banned: !!data.banned,
          admin: !!data.admin,
        };
        localStorage.setItem("chat_user", JSON.stringify(me));
        enterApp();
        setAdminUI();
        applyRestrictionUI();
        enablePush(false);
        flushOutbox();
        break;
      case "admin":
        myFlags.admin = true;
        if (me) me.admin = true;
        localStorage.setItem("chat_user", JSON.stringify(me));
        if (data.logs) lastLogs = data.logs;
        setAdminUI();
        renderModLogs(lastLogs);
        if (Notification && Notification.permission === "default") {
          Notification.requestPermission().catch(() => {});
        }
        toast("Você é administrador.");
        enablePush(false);
        break;
      case "moderation_logs":
        lastLogs = data.logs || [];
        renderModLogs(lastLogs);
        break;
      case "moderation_log":
        if (data.logs) lastLogs = data.logs;
        else if (data.entry) lastLogs = [data.entry, ...lastLogs].slice(0, 80);
        renderModLogs(lastLogs);
        break;
      case "alert":
        showModAlert(data);
        break;
      case "moderation":
        if (data.self) {
          myFlags = { ...myFlags, ...data.self };
          applyRestrictionUI();
        }
        if (data.action === "mute") toast("Você foi silenciado.");
        if (data.action === "block") toast("Você foi bloqueado.");
        if (data.action === "unmute" || data.action === "unblock") toast("Sua restrição foi removida.");
        break;
      case "moderation_state":
        if (data.users) renderUsers(data.users);
        break;
      case "kicked":
        toast(data.reason || "Sessão encerrada pelo admin.");
        break;
      case "security_sessions":
        renderSessions(data.sessions || []);
        break;
      case "location_on":
        $("loc-share")?.classList.add("hidden");
        $("loc-stop")?.classList.remove("hidden");
        toast("Localização ligada por 15 min. Só o admin vê.");
        break;
      case "location_off":
        $("loc-stop")?.classList.add("hidden");
        $("loc-share")?.classList.remove("hidden");
        toast("Localização desligada.");
        break;
      case "banned":
        toast(data.reason || "Você foi banido.");
        myFlags.banned = true;
        applyRestrictionUI();
        gate.classList.remove("hidden");
        app.classList.add("hidden");
        break;
      case "pong":
        break;
      case "receipt": {
        const cur = msgIndex.get(data.id) || msgIndex.get(data.clientId) || {};
        const next = {
          ...cur,
          status: data.status,
          deliveredTo: data.deliveredTo,
          readBy: data.readBy,
          pending: false,
        };
        if (data.id) msgIndex.set(data.id, next);
        if (data.clientId) msgIndex.set(data.clientId, next);
        renderMessage(next, false);
        break;
      }
      case "edited": {
        const msg = data.message;
        if (msg) {
          msgIndex.set(msg.id, msg);
          renderMessage(msg, false);
        }
        break;
      }
      case "dm_open": {
        groups = data.groups || groups;
        if (data.group && !groups.find((g) => g.id === data.group.id)) groups.push(data.group);
        currentGroupId = data.groupId || data.group?.id || currentGroupId;
        renderGroups();
        thread.innerHTML = "";
        lastDay = "";
        rendered.clear();
        (data.messages || []).forEach((m) => renderMessage(m, false));
        toast("Conversa particular");
        break;
      }
      case "group_left":
        groups = data.groups || groups;
        goHome();
        toast("Você saiu do grupo");
        break;
      case "deleted": {
        const cur = msgIndex.get(data.id) || msgIndex.get(data.clientId) || { id: data.id };
        renderMessage({ ...cur, deleted: true }, false);
        break;
      }
      case "history":
        thread.innerHTML = "";
        rendered.clear();
        msgIndex.clear();
        lastDay = "";
        if (data.groupId) currentGroupId = data.groupId;
        if (data.group) {
          groups = groups.map((g) => g.id === data.group.id ? data.group : g);
          renderGroups();
        }
        if (data.pubkeys) pubkeys = data.pubkeys;
        (async () => {
          if (data.wraps) await e2e.adoptWraps(currentGroupId, data.wraps, pubkeys);
          for (const m of data.messages || []) {
            await revealMessage(m);
            if (m.type === "system") renderSystem(m);
            else renderMessage(m, false);
            cacheMessage(m);
          }
          idb.all("outbox").then((box) => {
            (box || []).forEach((item) => {
              if (item.localPreview && (!item.groupId || item.groupId === currentGroupId)) {
                renderMessage(item.localPreview, false);
              }
            });
            scrollBottom(true);
            ackVisible("delivered");
            if (!document.hidden) ackVisible("read");
          });
        })();
        break;
      case "message": {
        const blockedNames = new Set(lastUsers.filter((u) => u.blocked).map((u) => u.name));
        if (!myFlags.admin && data.author !== me?.name && blockedNames.has(data.author)) break;
        if (data.groupId && data.groupId !== currentGroupId) break;
        revealMessage(data).then((m) => {
          renderMessage({ ...m, pending: false }, data.author === me?.name);
          cacheMessage({ ...m, pending: false });
        });
        if (data.author && me && data.author !== me.name) {
          beep("info");
          emit({ op: "receipts", kind: "delivered", ids: [data.id] });
          if (!document.hidden) emit({ op: "receipts", kind: "read", ids: [data.id] });
        }
        break;
      }
      case "system":
        renderSystem(data);
        cacheMessage(data);
        break;
      case "hello":
        lastServerPub = data.serverPub || "";
        if (lastServerPub && authToken) {
          openSession(lastServerPub).catch(() => toast("Falha na sessão JWT."));
        }
        break;
      case "session_ok":
        sessionWaitRes && sessionWaitRes();
        e2e.boot().then(() => identity.rememberMe()).then(async () => {
          if (me?.name && !app.classList.contains("hidden")) {
            try { await joinNow(me.name); } catch (err) { toast(err.message || "Login falhou"); }
          }
          flushOutbox();
        });
        break;
      case "need_auth":
        if (me?.name) {
          ensureAuth(me.name).then(() => joinNow(me.name)).catch((err) => toast(err.message || data.text));
        } else {
          toast(data.text || "Entre novamente.");
        }
        break;
      case "shell_out": {
        const box = $("shell-out");
        if (box) box.textContent = (box.textContent + "\n$ " + (data.cmd || "") + "\n" + (data.text || "")).slice(-2500);
        break;
      }
      case "error":
        toast(data.text || "Erro");
        break;
      case "users":
        renderUsers(data.users || []);
        break;
      case "typing":
        if (!data.name || data.name === me?.name) return;
        if (data.typing) typingMap.set(data.name, Date.now());
        else typingMap.delete(data.name);
        refreshTyping();
        break;
      default:
        break;
    }
  }

  function statusLabel(u) {
    if (u.status === "available") return "disponível";
    if (u.status === "away") return "ausente";
    if (u.status === "busy") return "ocupado";
    if (u.lastSeen) {
      const diff = Date.now() - Number(u.lastSeen);
      if (diff < 60000) return "visto agora";
      if (diff < 3600000) return `visto há ${Math.max(1, Math.round(diff / 60000))} min`;
      return `visto ${new Date(Number(u.lastSeen)).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" })}`;
    }
    return "offline";
  }

  function badgeHtml(u) {
    const bits = [];
    if (u.admin) bits.push("admin");
    const idst = identity.statusOf(u.name);
    if (idst === "verified") bits.push("verificado");
    if (idst === "changed") bits.push("chave mudou");
    if (u.muted) bits.push("silenciado");
    if (u.blocked) bits.push("bloqueado");
    if (u.banned) bits.push("banido");
    return bits;
  }

  function renderUsers(list) {
    lastUsers = list || [];
    const live = lastUsers.filter((u) => u.status && u.status !== "offline");
    if (isOnline() && socketOpen()) {
      onlineLabel.textContent = live.length ? `${live.length} disponível(is)` : "conectado";
      onlineLabel.style.color = "#31a24c";
    }
    peopleList.innerHTML = "";
    const roster = $("roster-list");
    if (roster) roster.innerHTML = "";
    lastUsers.forEach((u) => {
      const li = document.createElement("li");
      const dot = document.createElement("span");
      dot.className = `dot ${u.status || "offline"}`;
      dot.style.background = u.color;
      dot.textContent = initials(u.name);
      const meta = document.createElement("span");
      meta.className = "person-meta";
      const title = document.createElement("span");
      title.textContent = u.name;
      badgeHtml(u).forEach((b) => {
        const tag = document.createElement("em");
        tag.className = `badge ${b === "silenciado" ? "muted" : b === "bloqueado" ? "blocked" : b === "banido" ? "banned" : b === "verificado" ? "verified" : b === "chave mudou" ? "changed" : b}`;
        tag.textContent = b;
        title.appendChild(tag);
      });
      const small = document.createElement("small");
      small.textContent = statusLabel(u);
      meta.appendChild(title);
      meta.appendChild(small);
      li.appendChild(dot);
      li.appendChild(meta);
      if (me && u.name !== me.name) {
        li.addEventListener("click", () => emit({ op: "open_dm", target: u.name }));
      }
      peopleList.appendChild(li);
      if (roster && me && u.name !== me.name) {
        const copy = li.cloneNode(true);
        copy.addEventListener("click", () => emit({ op: "open_dm", target: u.name }));
        roster.appendChild(copy);
      }
    });
    renderAdminList();
  }

  function logLabel(action) {
    return {
      mute: "silenciou",
      unmute: "tirou o silêncio de",
      block: "bloqueou",
      unblock: "desbloqueou",
      ban: "baniu",
      unban: "desbaniu",
      admin_grant: "virou administrador",
      admin_auth_fail: "tentou código admin inválido",
      mute_expired: "teve o silêncio expirado",
    }[action] || action;
  }

  function logClass(action) {
    if (["unmute", "unblock", "unban"].includes(action)) return "act-free";
    if (action === "mute" || action === "mute_expired") return "act-mute";
    if (action === "block") return "act-block";
    if (action === "ban" || action === "admin_auth_fail") return "act-ban";
    return "";
  }

  function renderModLogs(logs) {
    if (!adminLogList) return;
    adminLogList.innerHTML = "";
    if (!logs || !logs.length) {
      const empty = document.createElement("li");
      empty.textContent = "Nenhuma ação registrada ainda.";
      adminLogList.appendChild(empty);
      return;
    }
    logs.forEach((row) => {
      const li = document.createElement("li");
      const when = document.createElement("span");
      when.className = "when";
      when.textContent = new Date(row.createdAt).toLocaleString("pt-BR");
      const body = document.createElement("span");
      body.className = logClass(row.action);
      const verb = logLabel(row.action);
      let text = `${row.actor || "sistema"} ${verb}`;
      if (row.target && row.target !== row.actor) text += ` ${row.target}`;
      if (row.minutes) text += ` (${row.minutes} min)`;
      if (row.reason) text += ` — ${row.reason}`;
      body.textContent = text;
      li.appendChild(when);
      li.appendChild(body);
      adminLogList.appendChild(li);
    });
  }

  function setAdminUI() {
    const isAdmin = !!(me && (me.admin || myFlags.admin));
    adminAuth.classList.toggle("hidden", isAdmin);
    adminTools.classList.toggle("hidden", !isAdmin);
    renderAdminList();
    renderModLogs(lastLogs);
    if (isAdmin) emit({ op: "logs" });
  }

  function applyRestrictionUI() {
    const locked = myFlags.muted || myFlags.blocked || myFlags.banned;
    composer.classList.toggle("locked", locked);
    sendBtn = $("send-btn");
    if (sendBtn) sendBtn.disabled = locked;
    if (myFlags.banned) {
      textInput.placeholder = "Você foi banido";
    } else if (myFlags.muted) {
      textInput.placeholder = "Você está silenciado";
    } else if (myFlags.blocked) {
      textInput.placeholder = "Você está bloqueado";
    } else {
      textInput.placeholder = "Mensagem";
    }
  }

  function moderate(target, action, minutes) {
    emit({ op: "moderate", target, action, minutes: minutes || 0 });
  }

  function renderSessions(rows) {
    const list = $("session-list");
    if (!list) return;
    list.innerHTML = "";
    if (!rows.length) {
      const empty = document.createElement("li");
      empty.textContent = "Nenhuma sessão online.";
      list.appendChild(empty);
      return;
    }
    rows.forEach((s) => {
      const li = document.createElement("li");
      const title = document.createElement("strong");
      title.textContent = s.name || "—";
      const meta = document.createElement("div");
      meta.className = "fp-mini";
      const bits = [`IP ${s.ip || "?"}`, (s.ua || "aparelho").slice(0, 48)];
      if (s.sharing && s.location) {
        bits.push(`loc ${s.location.lat}, ${s.location.lng}`);
      }
      meta.textContent = bits.join(" · ");
      const actions = document.createElement("div");
      actions.className = "mod-actions";
      if (s.sharing && s.location) {
        const map = document.createElement("button");
        map.type = "button";
        map.className = "free";
        map.textContent = "Mapa";
        map.addEventListener("click", () => {
          window.open(`https://www.openstreetmap.org/?mlat=${s.location.lat}&mlon=${s.location.lng}#map=16/${s.location.lat}/${s.location.lng}`, "_blank", "noopener");
        });
        actions.appendChild(map);
      }
      if (me && s.name !== me.name) {
        const kick = document.createElement("button");
        kick.type = "button";
        kick.className = "ban";
        kick.textContent = "Encerrar sessão";
        kick.addEventListener("click", () => emit({ op: "kick_session", sid: s.sid, target: s.name }));
        actions.appendChild(kick);
      }
      li.appendChild(title);
      li.appendChild(meta);
      li.appendChild(actions);
      list.appendChild(li);
    });
  }

  function renderAdminList() {
    if (!adminList) return;
    adminList.innerHTML = "";
    lastUsers.forEach((u) => {
      if (me && u.name === me.name) return;
      const li = document.createElement("li");
      const head = document.createElement("div");
      head.textContent = `${u.name} · ${statusLabel(u)}`;
      const actions = document.createElement("div");
      actions.className = "mod-actions";
      const btns = u.banned
        ? [["unban", "Desbanir", "free"]]
        : u.blocked
          ? [["unblock", "Desbloquear", "free"], ["ban", "Banir", "ban"]]
          : u.muted
            ? [["unmute", "Tirar silêncio", "free"], ["block", "Bloquear", "block"], ["ban", "Banir", "ban"]]
            : [
                ["mute", "Silenciar 10 min", "mute", 10],
                ["mute", "Silenciar 1h", "mute", 60],
                ["mute", "Silenciar", "mute", 0],
                ["block", "Bloquear", "block"],
                ["ban", "Banir", "ban"],
              ];
      btns.forEach(([action, label, cls, minutes]) => {
        const b = document.createElement("button");
        b.type = "button";
        b.className = cls;
        b.textContent = label;
        b.addEventListener("click", () => moderate(u.name, action, minutes));
        actions.appendChild(b);
      });
      li.appendChild(head);
      li.appendChild(actions);
      adminList.appendChild(li);
    });
  }

  function refreshTyping() {
    const names = [...typingMap.keys()];
    if (!names.length) {
      typingEl.classList.add("hidden");
      typingEl.textContent = "";
      return;
    }
    typingEl.classList.remove("hidden");
    typingEl.textContent =
      names.length === 1
        ? `${names[0]} está digitando…`
        : `${names.slice(0, 2).join(", ")} estão digitando…`;
  }

  let pendingRadioText = "";

  function netUp() {
    return isOnline() && socketOpen();
  }

  function askRadio(text) {
    pendingRadioText = text || "";
    const sheet = $("radio-sheet");
    if ($("radio-preview")) $("radio-preview").textContent = pendingRadioText.slice(0, 140);
    sheet?.classList.remove("hidden");
  }

  async function sendViaLora(text) {
    const body = {
      name: me?.name || "anon",
      text: String(text || "").slice(0, 200),
      groupId: currentGroupId,
      via: "lora",
      createdAt: Date.now(),
    };
    try {
      const res = await fetch("/api/radio/lora", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: authToken ? `Bearer ${authToken}` : "" },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Gateway LoRa indisponível");
      toast(data.forwarded ? "LoRa enviado ao gateway." : "LoRa na fila local. Liga o gateway.");
      renderSystem({
        id: uid(),
        type: "system",
        text: `📡 LoRa: ${body.text}`,
        createdAt: Date.now(),
      });
    } catch (err) {
      toast(err.message || "Falha LoRa");
    }
  }

  async function sendText(text) {
    if (!me?.name) {
      toast("Entre com um nome antes de enviar.");
      return;
    }
    if (!netUp()) {
      askRadio(text);
      return;
    }
    if (myFlags.muted || myFlags.blocked || myFlags.banned) {
      toast("Você não pode enviar mensagens agora.");
      return;
    }
    const clientId = uid();
    const local = {
      id: clientId,
      clientId,
      type: "text",
      text,
      author: me.name,
      color: me.color || colorFromName(me.name),
      createdAt: Date.now(),
      pending: !socketOpen(),
      status: socketOpen() ? "sent" : "pending",
      replyTo: replyTo,
    };
    const quoted = replyTo;
    renderMessage(local, true);
    await cacheMessage(local);
    const packet = { op: "message", clientId, type: "text", text, replyTo: quoted, groupId: currentGroupId };
    await e2e.boot();
    if (!e2e.groupKeys[currentGroupId]) await e2e.adoptWraps(currentGroupId, {}, pubkeys);
    const enc = await e2e.encryptText(currentGroupId, text);
    if (enc) {
      packet.e2e = true;
      packet.iv = enc.iv;
      packet.ct = enc.ct;
      packet.text = "";
    }
    const sent = emit(packet);
    clearReply();
    if (!sent) {
      await enqueue({
        id: clientId,
        kind: "text",
        text,
        createdAt: local.createdAt,
        replyTo: quoted,
        groupId: currentGroupId,
        e2e: packet.e2e,
        iv: packet.iv,
        ct: packet.ct,
        localPreview: local,
      });
      toast("Sem internet. Mensagem guardada na fila.");
      setOfflineUI();
    }
  }

  async function sendMedia(file, text) {
    if (!me?.name) {
      toast("Entre com um nome antes de enviar.");
      return;
    }
    if (myFlags.muted || myFlags.blocked || myFlags.banned) {
      toast("Você não pode enviar mídia agora.");
      return;
    }
    const clientId = uid();
    const localUrl = URL.createObjectURL(file);
    const local = {
      id: clientId,
      clientId,
      type: file.type.startsWith("video/") ? "video" : "image",
      text,
      mediaUrl: localUrl,
      author: me.name,
      color: me.color || colorFromName(me.name),
      createdAt: Date.now(),
      pending: true,
      status: "pending",
      mime: file.type,
      replyTo: replyTo,
    };
    const quoted = replyTo;
    renderMessage(local, true);
    await cacheMessage(local);

    if (socketOpen() && isOnline()) {
      try {
        const meta = await uploadFile(file);
        const sent = emit({
          op: "message",
          clientId,
          type: meta.type,
          text,
          mediaUrl: meta.url,
          thumb: meta.thumb,
          duration: meta.duration,
          mime: meta.mime,
          replyTo: quoted,
          groupId: currentGroupId,
        });
        clearReply();
        if (sent) return;
      } catch (err) {
        toast(err.message || "Falha no envio. Vai na fila.");
      }
    }

    await idb.put("files", {
      id: clientId,
      blob: file,
      name: file.name,
      type: file.type,
    });
    await enqueue({
      id: clientId,
      kind: "media",
      text,
      mime: file.type,
      createdAt: local.createdAt,
      replyTo: quoted,
      localPreview: local,
    });
    toast("Sem internet. Vídeo/foto guardado para enviar depois.");
    setOfflineUI();
  }

  async function enterWithGoogle(resp) {
    const res = await fetch("/api/auth/google", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: resp.credential }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || "Google recusado");
    saveTokens(data, data.name);
    me = { name: data.name, color: colorFromName(data.name), picture: data.picture };
    localStorage.setItem("chat_user", JSON.stringify(me));
    try { await e2e.boot(); } catch { /* ignore */ }
    enterApp();
    await joinNow(data.name);
  }

  (function resumeGoogleHash() {
    const hash = new URLSearchParams((location.hash || "").replace(/^#/, ""));
    const gtok = hash.get("gtok");
    const gname = hash.get("gname");
    if (!gtok || !gname) return;
    saveTokens({ accessToken: gtok, refreshToken: hash.get("gref") || "", expiresIn: 900 }, gname);
    me = { name: gname, color: colorFromName(gname) };
    localStorage.setItem("chat_user", JSON.stringify(me));
    history.replaceState({}, "", location.pathname);
    e2e.boot().catch(() => {}).then(() => {
      enterApp();
      joinNow(gname).catch((err) => toast(err.message || "Falha ao entrar"));
    });
  })();

  fetch("/api/config").then((r) => r.json()).then((cfg) => {
    if (cfg?.googleOAuth) $("google-oauth-link")?.classList.remove("hidden");
    if (!cfg?.googleClientId || !$("google-btn")) return;
    const s = document.createElement("script");
    s.src = "https://accounts.google.com/gsi/client";
    s.async = true;
    s.onload = () => {
      if (!window.google?.accounts?.id) return;
      window.google.accounts.id.initialize({
        client_id: cfg.googleClientId,
        callback: (g) => enterWithGoogle(g).catch((err) => toast(err.message || "Google falhou")),
      });
      window.google.accounts.id.renderButton($("google-btn"), {
        theme: "filled_black",
        size: "large",
        width: 280,
      });
    };
    document.head.appendChild(s);
  }).catch(() => {});

  joinForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = nameInput.value.trim();
    if (!name) return;
    me = { name, color: colorFromName(name) };
    localStorage.setItem("chat_user", JSON.stringify(me));
    try { await e2e.boot(); } catch { /* WebCrypto indisponível */ }
    enterApp();
    try {
      if (!await joinNow(name)) {
        toast("Você entrou offline. As mensagens sobem quando voltar a rede.");
      }
    } catch (err) {
      toast(err.message || "Conectado sem sessão cifrada.");
    }
  });

  function applyStatus(status, fromUser) {
    if (!["available", "away", "busy"].includes(status)) status = "available";
    if (fromUser) manualStatus = status;
    if (me) {
      me.status = status;
      localStorage.setItem("chat_user", JSON.stringify(me));
    }
    document.querySelectorAll("#status-pick button").forEach((btn) => {
      btn.classList.toggle("on", btn.dataset.status === (manualStatus || status));
    });
    emit({ op: "status", status });
  }

  $("status-pick").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-status]");
    if (!btn) return;
    applyStatus(btn.dataset.status, true);
  });

  function closeMore() {
    $("more-menu")?.classList.add("hidden");
  }
  $("more-btn")?.addEventListener("click", (e) => {
    e.stopPropagation();
    $("more-menu").classList.toggle("hidden");
  });
  $("menu-close")?.addEventListener("click", (e) => {
    e.stopPropagation();
    closeMore();
  });
  document.addEventListener("click", (e) => {
    const menu = $("more-menu");
    if (!menu || menu.classList.contains("hidden")) return;
    if (e.target.closest("#more-menu") || e.target.closest("#more-btn")) return;
    menu.classList.add("hidden");
  });
  $("people-btn").addEventListener("click", () => {
    closeMore();
    people.classList.toggle("hidden");
    $("roster")?.classList.toggle("open");
  });
  $("home-btn")?.addEventListener("click", goHome);
  $("back-btn")?.addEventListener("click", goHome);
  $("leave-group")?.addEventListener("click", () => {
    if (currentGroupId === "aberto") {
      toast("Você já está no chat aberto.");
      return;
    }
    if (confirm("Sair deste grupo/conversa?")) emit({ op: "leave_group", groupId: currentGroupId });
  });
  $("id-btn").addEventListener("click", async () => {
    closeMore();
    $("identity").classList.toggle("hidden");
    await identity.rememberMe();
    await identity.inspect(pubkeys);
  });
  $("id-close").addEventListener("click", () => $("identity").classList.add("hidden"));
  $("copy-fp").addEventListener("click", async () => {
    await identity.rememberMe();
    try {
      await navigator.clipboard.writeText(identity.myFp);
      toast("Impressão digital copiada.");
    } catch {
      toast(identity.myFp);
    }
  });
  const pageRoutes = {
    conversas: "page-chats",
    perfil: "page-profile",
    config: "page-settings",
  };
  function fillPage(id) {
    if (id === "page-chats") {
      const box = $("chats-list");
      const src = $("roster-list");
      if (box && src) box.innerHTML = src.innerHTML;
    }
    if (id === "page-profile") {
      if ($("profile-name")) $("profile-name").textContent = me?.name || "—";
      if ($("profile-bio")) $("profile-bio").value = localStorage.getItem("ft_bio") || "";
      const photo = $("profile-photo");
      if (photo) photo.src = localStorage.getItem("ft_avatar") || "/icons/icon-192.png";
    }
  }
  function openPage(id, push = true) {
    closeMore();
    ["page-chats", "page-profile", "page-settings"].forEach((k) => $(k)?.classList.add("hidden"));
    $(id)?.classList.remove("hidden");
    $("app")?.classList.add("page-open");
    $("emoji-panel")?.classList.add("hidden");
    fillPage(id);
    if (push) {
      const hash = { "page-chats": "#/conversas", "page-profile": "#/perfil", "page-settings": "#/config" }[id] || "#/";
      if (location.hash !== hash) location.hash = hash;
    }
  }
  function closePages() {
    $("app")?.classList.remove("page-open");
    ["page-chats", "page-profile", "page-settings"].forEach((k) => $(k)?.classList.add("hidden"));
    if (location.hash && location.hash !== "#/" && location.hash !== "#") {
      location.hash = "#/";
    }
  }
  function routeFromHash() {
    const key = (location.hash || "").replace(/^#\/?/, "");
    const id = pageRoutes[key];
    if (id) openPage(id, false);
    else closePages();
  }
  window.addEventListener("hashchange", routeFromHash);
  $("chats-btn")?.addEventListener("click", () => openPage("page-chats"));
  $("chats-close")?.addEventListener("click", closePages);
  $("chats-home")?.addEventListener("click", () => { closePages(); goHome(); });
  let profileAvatar = localStorage.getItem("ft_avatar") || "";
  $("profile-btn")?.addEventListener("click", () => openPage("page-profile"));
  $("profile-close")?.addEventListener("click", closePages);
  $("profile-file")?.addEventListener("change", async () => {
    const file = $("profile-file").files?.[0];
    $("profile-file").value = "";
    if (!file) return;
    try {
      const meta = await uploadFile(file);
      profileAvatar = meta.url;
      localStorage.setItem("ft_avatar", profileAvatar);
      if ($("profile-photo")) $("profile-photo").src = profileAvatar;
      toast("Foto pronta. Toque em Atualizar perfil.");
    } catch (err) {
      toast(err.message || "Falha na foto");
    }
  });
  $("profile-save")?.addEventListener("click", () => {
    const bio = ($("profile-bio")?.value || "").slice(0, 80);
    localStorage.setItem("ft_bio", bio);
    emit({ op: "profile", bio, avatar: profileAvatar });
    toast("Perfil atualizado.");
    closePages();
  });
  $("settings-btn")?.addEventListener("click", () => openPage("page-settings"));
  $("settings-close")?.addEventListener("click", closePages);
  routeFromHash();
  $("set-notify")?.addEventListener("click", () => $("notify-btn")?.click());
  $("set-available")?.addEventListener("click", () => applyStatus("available", true));
  $("set-away")?.addEventListener("click", () => applyStatus("away", true));
  $("shell-btn")?.addEventListener("click", () => {
    closeMore();
    $("sys-shell")?.classList.toggle("hidden");
    $("shell-in")?.focus();
  });
  $("shell-close")?.addEventListener("click", () => $("sys-shell")?.classList.add("hidden"));
  $("shell-form")?.addEventListener("submit", (e) => {
    e.preventDefault();
    const input = $("shell-in");
    const cmd = (input?.value || "").trim();
    if (!cmd) return;
    input.value = "";
    if (cmd === "/home" || cmd === "home") {
      goHome();
      const box = $("shell-out");
      if (box) box.textContent += "\n$ home\nvoltou ao chat aberto";
      return;
    }
    emit({ op: "shell", cmd });
  });
  $("groups-btn").addEventListener("click", () => {
    closeMore();
    $("groups").classList.toggle("hidden");
    renderGroups();
  });
  $("groups-close").addEventListener("click", () => $("groups").classList.add("hidden"));
  $("group-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const name = $("group-name").value.trim();
    if (!name) return;
    emit({ op: "create_group", name, kind: "private" });
    $("group-name").value = "";
  });
  $("member-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const target = $("member-name").value.trim();
    if (!target) return;
    emit({ op: "add_member", groupId: currentGroupId, target });
    $("member-name").value = "";
  });
  const emojiPanel = $("emoji-panel");
  EMOJIS.forEach((emo) => {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = emo;
    b.addEventListener("click", () => {
      const start = textInput.selectionStart || textInput.value.length;
      const end = textInput.selectionEnd || start;
      textInput.value = textInput.value.slice(0, start) + emo + textInput.value.slice(end);
      textInput.focus();
      textInput.selectionStart = textInput.selectionEnd = start + emo.length;
    });
    emojiPanel.appendChild(b);
  });
  $("emoji-btn").addEventListener("click", () => emojiPanel.classList.toggle("hidden"));
  $("people-close").addEventListener("click", () => people.classList.add("hidden"));
  $("admin-btn").addEventListener("click", () => {
    closeMore();
    adminPanel.classList.toggle("hidden");
    if (!adminPanel.classList.contains("hidden")) {
      unreadAlerts = 0;
      if (alertBadge) alertBadge.classList.add("hidden");
      if (Notification && Notification.permission === "default") {
        Notification.requestPermission().catch(() => {});
      }
      if (myFlags.admin) emit({ op: "security_sessions" });
    }
    setAdminUI();
  });
  $("admin-close").addEventListener("click", () => adminPanel.classList.add("hidden"));
  $("logs-refresh").addEventListener("click", () => emit({ op: "logs" }));
  $("sessions-refresh")?.addEventListener("click", () => emit({ op: "security_sessions" }));
  $("loc-share")?.addEventListener("click", () => {
    if (!navigator.geolocation) {
      toast("Este aparelho não informa localização.");
      return;
    }
    toast("O navegador vai pedir permissão de localização.");
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        emit({
          op: "share_location",
          lat: pos.coords.latitude,
          lng: pos.coords.longitude,
          accuracy: pos.coords.accuracy,
          minutes: 15,
        });
      },
      () => toast("Permissão de localização negada."),
      { enableHighAccuracy: false, timeout: 12000, maximumAge: 30000 },
    );
  });
  $("loc-stop")?.addEventListener("click", () => emit({ op: "stop_location" }));
  $("push-btn").addEventListener("click", () => enablePush(true));
  $("notify-btn").addEventListener("click", () => enablePush(true));
  $("reply-cancel").addEventListener("click", clearReply);

  function urlBase64ToUint8Array(base64String) {
    const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
    const raw = atob((base64String + padding).replace(/-/g, "+").replace(/_/g, "/"));
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  function markPushOn() {
    const adminBtn = $("push-btn");
    const chatBtn = $("notify-btn");
    if (adminBtn) adminBtn.textContent = "Push ativo";
    if (chatBtn) chatBtn.textContent = "Avisos on";
  }

  async function enablePush(interactive) {
    const adminBtn = $("push-btn");
    const chatBtn = $("notify-btn");
    if (!me?.name) return;
    if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
      if (interactive) toast("Este navegador não suporta push.");
      return;
    }
    if (!interactive && localStorage.getItem("chat_push") !== "1" && Notification.permission !== "granted") {
      return;
    }
    try {
      const perm = interactive || Notification.permission === "default"
        ? await Notification.requestPermission()
        : Notification.permission;
      if (perm !== "granted") {
        if (interactive) toast("Permita as notificações no celular/navegador.");
        if (adminBtn) adminBtn.textContent = "Notificações bloqueadas";
        return;
      }
      const info = await fetch("/api/push/public-key").then((r) => r.json());
      if (!info.publicKey) throw new Error("sem chave pública");
      const reg = await navigator.serviceWorker.ready;
      let sub = await reg.pushManager.getSubscription();
      if (!sub) {
        sub = await reg.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: urlBase64ToUint8Array(info.publicKey),
        });
      }
      if (!authToken) await ensureAuth(me.name);
      const res = await fetch("/api/push/subscribe", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({ name: me.name, token: authToken, subscription: sub.toJSON() }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || "falha ao registrar");
      }
      localStorage.setItem("chat_push", "1");
      markPushOn();
      if (interactive) toast("Pronto. As mensagens chegam neste celular.");
    } catch (err) {
      if (interactive) toast(err.message || "Não foi possível ativar o push.");
    }
  }
  adminAuth.addEventListener("submit", (e) => {
    e.preventDefault();
    const code = adminCode.value.trim();
    if (!code) return;
    emit({ op: "admin_auth", code });
    adminCode.value = "";
  });

  textInput.addEventListener("input", () => {
    textInput.style.height = "auto";
    textInput.style.height = Math.min(textInput.scrollHeight, 120) + "px";
    emit({ op: "typing", typing: true });
    clearTimeout(typingTimer);
    typingTimer = setTimeout(() => emit({ op: "typing", typing: false }), 900);
  });

  textInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      composer.requestSubmit();
    }
  });

  let radioRec = null;
  let radioChunks = [];
  async function startRadio() {
    if (!navigator.mediaDevices?.getUserMedia) {
      toast("Este aparelho não tem microfone.");
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      radioChunks = [];
      radioRec = new MediaRecorder(stream);
      radioRec.ondataavailable = (ev) => { if (ev.data.size) radioChunks.push(ev.data); };
      radioRec.onstop = async () => {
        stream.getTracks().forEach((t) => t.stop());
        const blob = new Blob(radioChunks, { type: radioRec.mimeType || "audio/webm" });
        radioRec = null;
        if (blob.size < 400) {
          toast("Rádio muito curto.");
          return;
        }
        const file = new File([blob], `radio-${Date.now()}.webm`, { type: blob.type });
        toast("Enviando rádio…");
        await sendFile(file, "");
      };
      radioRec.start();
      $("radio-btn")?.classList.add("on");
      toast("Rádio no ar — solte para enviar");
    } catch {
      toast("Permissão de microfone negada.");
    }
  }
  function stopRadio() {
    $("radio-btn")?.classList.remove("on");
    if (radioRec && radioRec.state !== "inactive") radioRec.stop();
  }
  $("radio-btn")?.addEventListener("pointerdown", (e) => { e.preventDefault(); startRadio(); });
  $("radio-btn")?.addEventListener("pointerup", stopRadio);
  $("radio-btn")?.addEventListener("pointerleave", stopRadio);
  $("radio-close")?.addEventListener("click", () => $("radio-sheet").classList.add("hidden"));
  $("radio-wait")?.addEventListener("click", async () => {
    $("radio-sheet").classList.add("hidden");
    if (pendingRadioText) {
      await enqueue({
        id: uid(),
        kind: "text",
        text: pendingRadioText,
        createdAt: Date.now(),
        groupId: currentGroupId,
      });
      toast("Guardado. Sobe quando a internet voltar.");
    }
  });
  $("radio-ptt")?.addEventListener("click", () => {
    $("radio-sheet").classList.add("hidden");
    startRadio();
  });
  $("radio-lora")?.addEventListener("click", () => {
    $("radio-sheet").classList.add("hidden");
    sendViaLora(pendingRadioText);
  });

  composer.addEventListener("submit", (e) => {
    e.preventDefault();
    const text = textInput.value.trim();
    if (!text) return;
    textInput.value = "";
    textInput.style.height = "auto";
    emit({ op: "typing", typing: false });
    sendText(text);
  });

  fileInput.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    fileInput.value = "";
    if (!file) return;
    if (file.size > 80 * 1024 * 1024) {
      toast("Arquivo muito grande (máx. 80 MB).");
      return;
    }
    pendingFile = file;
    caption.value = "";
    previewVideo.classList.remove("show");
    previewImage.classList.remove("show");
    const url = URL.createObjectURL(file);
    if (file.type.startsWith("video/")) {
      previewVideo.src = url;
      previewVideo.classList.add("show");
    } else {
      previewImage.src = url;
      previewImage.classList.add("show");
    }
    preview.classList.remove("hidden");
  });

  function closePreview() {
    preview.classList.add("hidden");
    previewVideo.pause();
    pendingFile = null;
  }

  previewClose.addEventListener("click", closePreview);

  previewSend.addEventListener("click", async () => {
    if (!pendingFile) return;
    const file = pendingFile;
    const text = caption.value.trim();
    closePreview();
    await sendMedia(file, text);
  });

  function uploadFile(file) {
    return new Promise((resolve, reject) => {
      const data = new FormData();
      data.append("file", file);
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/upload");
      if (authToken) xhr.setRequestHeader("Authorization", `Bearer ${authToken}`);
      xhr.onload = () => {
        try {
          const json = JSON.parse(xhr.responseText);
          if (xhr.status >= 200 && xhr.status < 300) resolve(json);
          else reject(new Error(json.error || "Upload falhou"));
        } catch {
          reject(new Error("Upload falhou"));
        }
      };
      xhr.onerror = () => reject(new Error("Sem conexão no upload"));
      xhr.send(data);
    });
  }

  window.addEventListener("online", () => {
    reconnectAttempt = 0;
    setOfflineUI();
    connect();
    flushOutbox();
    toast("Internet voltou. Enviando fila…");
  });
  window.addEventListener("offline", () => {
    setOfflineUI();
    toast("Você está offline. Pode continuar enviando.");
  });
  document.addEventListener("visibilitychange", () => {
    if (manualStatus === "busy") {
      if (!document.hidden) {
        connect();
        flushOutbox();
      }
      return;
    }
    const status = document.hidden ? "away" : "available";
    applyStatus(status, false);
    if (!document.hidden) {
      connect();
      flushOutbox();
      ackVisible("read");
    }
  });

  function pollHealth() {
    fetch("/api/health", { cache: "no-store" })
      .then((r) => r.json())
      .then((info) => {
        if (info?.ok && !socketOpen()) connect();
      })
      .catch(() => {
        if (!isOnline()) setOfflineUI();
        else if (!socketOpen()) connect();
      });
  }
  healthTimer = setInterval(pollHealth, 20000);

  function openMobileSheet() {
    const sheet = $("mobile-sheet");
    if (!sheet) return;
    $("sheet-url").textContent = location.href;
    sheet.classList.remove("hidden");
  }
  $("open-mobile")?.addEventListener("click", openMobileSheet);
  $("sheet-close")?.addEventListener("click", () => $("mobile-sheet").classList.add("hidden"));
  $("sheet-copy")?.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(location.href);
      toast("Link copiado. Cole no celular.");
    } catch {
      toast(location.href);
    }
  });
  $("sheet-install")?.addEventListener("click", async () => {
    if (deferredPrompt) {
      deferredPrompt.prompt();
      await deferredPrompt.userChoice;
      deferredPrompt = null;
      $("install-btn").classList.add("hidden");
    } else {
      openMobileSheet();
      toast("No celular: menu do navegador → Adicionar à tela inicial.");
    }
  });

  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    deferredPrompt = e;
    installBtn.classList.remove("hidden");
  });

  installBtn.addEventListener("click", async () => {
    if (!deferredPrompt) return;
    deferredPrompt.prompt();
    await deferredPrompt.userChoice;
    deferredPrompt = null;
    installBtn.classList.add("hidden");
  });

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").then((reg) => {
      if (reg.sync) reg.sync.register("chat-flush").catch(() => {});
    }).catch(() => {});
    navigator.serviceWorker.addEventListener("message", (ev) => {
      if (ev.data && ev.data.op === "flush") flushOutbox();
    });
  }

  loadLocalHistory();
  connect();
  setOfflineUI();
  applyStatus(manualStatus, true);
})();
