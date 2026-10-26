"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const store = {
    get(storage, key) { try { return storage.getItem(key); } catch { return null; } },
    set(storage, key, value) { try { storage.setItem(key, value); } catch { /* ignore */ } },
    del(storage, key) { try { storage.removeItem(key); } catch { /* ignore */ } },
  };

  // Geräte-ID: zufällig, pro Browser einmalig. Dient der Geräte-Bindung der Lizenz.
  function deviceId() {
    let id = store.get(localStorage, "pdfdrm.device");
    if (!id) {
      id = (crypto.randomUUID && crypto.randomUUID()) ||
        Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");
      store.set(localStorage, "pdfdrm.device", id);
    }
    return id;
  }

  const state = {
    accessToken: store.get(sessionStorage, "pdfdrm.access"),
    user: null,
    viewToken: null,
    refreshTimer: null,
    doc: null,
    page: 1,
    scale: 1.5,
    objectUrl: null,
  };

  async function api(path, { method = "GET", body, token = state.accessToken, raw = false } = {}) {
    const headers = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetch(path, {
      method, headers, body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store", credentials: "omit",
    });
    if (!res.ok) {
      let msg = `${res.status}`;
      try { msg = (await res.json()).message || msg; } catch { /* ignore */ }
      const err = new Error(msg);
      err.status = res.status;
      throw err;
    }
    return raw ? res : res.json();
  }

  function show(view) {
    for (const v of ["login-view", "library-view", "reader-view"]) $(v).hidden = v !== view;
    $("logout").hidden = view === "login-view";
    $("who").textContent = state.user ? state.user.email : "";
  }

  // --- Anmeldung ------------------------------------------------------------

  $("login-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const form = new FormData(ev.target);
    $("login-error").textContent = "";
    try {
      const res = await api("/api/auth/login", {
        method: "POST", token: null,
        body: { email: form.get("email"), password: form.get("password") },
      });
      state.accessToken = res.access_token;
      state.user = res.user;
      store.set(sessionStorage, "pdfdrm.access", res.access_token);
      ev.target.reset();
      await loadLibrary();
    } catch (err) {
      $("login-error").textContent = err.message;
    }
  });

  $("logout").addEventListener("click", () => {
    closeReader();
    state.accessToken = null;
    state.user = null;
    store.del(sessionStorage, "pdfdrm.access");
    show("login-view");
  });

  // --- Bibliothek -----------------------------------------------------------

  function fmtDate(ts) {
    return ts ? new Date(ts * 1000).toLocaleString() : "unbegrenzt";
  }

  async function loadLibrary() {
    $("library-error").textContent = "";
    try {
      if (!state.user) state.user = await api("/api/me");
      const items = await api("/api/library");
      const list = $("library");
      list.replaceChildren();
      if (!items.length) {
        const li = document.createElement("li");
        li.textContent = "Keine lizenzierten Dokumente vorhanden.";
        list.append(li);
      }
      for (const item of items) {
        const li = document.createElement("li");
        const text = document.createElement("div");
        const title = document.createElement("div");
        title.textContent = item.title;
        const meta = document.createElement("div");
        meta.className = "meta";
        const opens = item.max_opens ? ` · Öffnungen ${item.open_count}/${item.max_opens}` : "";
        meta.textContent = `${item.page_count} Seiten · gültig bis ${fmtDate(item.valid_until)}${opens}`;
        text.append(title, meta);
        const btn = document.createElement("button");
        btn.textContent = "Öffnen";
        btn.addEventListener("click", () => openDocument(item.document_id));
        li.append(text, btn);
        list.append(li);
      }
      show("library-view");
    } catch (err) {
      if (err.status === 401) { $("logout").click(); return; }
      $("library-error").textContent = err.message;
      show("library-view");
    }
  }

  // --- Reader ---------------------------------------------------------------

  async function openDocument(docId) {
    $("library-error").textContent = "";
    try {
      const res = await api(`/api/documents/${encodeURIComponent(docId)}/open`, {
        method: "POST", body: { device_id: deviceId() },
      });
      state.viewToken = res.view_token;
      state.doc = res.document;
      state.page = 1;
      $("doc-title").textContent = res.document.title;
      $("page-count").textContent = res.document.page_count;
      $("page-input").max = res.document.page_count;
      $("print").hidden = !res.permissions.print;
      $("download").hidden = !res.permissions.download;
      document.body.classList.toggle("print-allowed", !!res.permissions.print);
      scheduleRefresh(res.expires_in);
      show("reader-view");
      await renderPage();
    } catch (err) {
      $("library-error").textContent = err.message;
    }
  }

  function scheduleRefresh(expiresIn) {
    clearTimeout(state.refreshTimer);
    const ms = Math.max(10, expiresIn - 60) * 1000;
    state.refreshTimer = setTimeout(async () => {
      try {
        const res = await api("/api/view/refresh", { method: "POST", token: state.viewToken });
        state.viewToken = res.view_token;
        scheduleRefresh(res.expires_in);
      } catch (err) {
        readerError(err);
      }
    }, ms);
  }

  function readerError(err) {
    $("reader-error").textContent = err.message;
    if (err.status === 401 || err.status === 403) {
      // Lizenz widerrufen/abgelaufen: Inhalt sofort entfernen.
      setImage(null);
    }
  }

  function setImage(blob) {
    if (state.objectUrl) URL.revokeObjectURL(state.objectUrl);
    state.objectUrl = blob ? URL.createObjectURL(blob) : null;
    if (state.objectUrl) $("page").src = state.objectUrl;
    else $("page").removeAttribute("src");
  }

  async function renderPage() {
    if (!state.doc) return;
    $("reader-error").textContent = "";
    $("page-input").value = state.page;
    try {
      const res = await api(`/api/view/pages/${state.page}?scale=${state.scale}`, {
        token: state.viewToken, raw: true,
      });
      setImage(await res.blob());
    } catch (err) {
      readerError(err);
    }
  }

  function closeReader() {
    clearTimeout(state.refreshTimer);
    state.viewToken = null;
    state.doc = null;
    setImage(null);
  }

  function go(page) {
    if (!state.doc) return;
    const p = Math.min(Math.max(1, page), state.doc.page_count);
    if (p !== state.page) { state.page = p; renderPage(); }
  }

  $("back").addEventListener("click", () => { closeReader(); loadLibrary(); });
  $("prev").addEventListener("click", () => go(state.page - 1));
  $("next").addEventListener("click", () => go(state.page + 1));
  $("page-input").addEventListener("change", (ev) => go(parseInt(ev.target.value, 10) || 1));
  $("zoom-in").addEventListener("click", () => { state.scale = Math.min(3, state.scale + 0.25); renderPage(); });
  $("zoom-out").addEventListener("click", () => { state.scale = Math.max(0.5, state.scale - 0.25); renderPage(); });
  $("print").addEventListener("click", () => window.print());
  $("download").addEventListener("click", async () => {
    try {
      const res = await api("/api/view/download", { method: "POST", token: state.viewToken, raw: true });
      const blob = await res.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `${state.doc.title || "dokument"}.pdf`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 10000);
    } catch (err) {
      readerError(err);
    }
  });

  document.addEventListener("keydown", (ev) => {
    if (!state.doc) return;
    const key = ev.key.toLowerCase();
    // Strg+S / Strg+P abfangen (rein kosmetische Hürde).
    if ((ev.ctrlKey || ev.metaKey) && (key === "s" || (key === "p" && !document.body.classList.contains("print-allowed")))) {
      ev.preventDefault();
      return;
    }
    if (ev.target.tagName === "INPUT") return;
    if (ev.key === "ArrowRight" || ev.key === "PageDown") go(state.page + 1);
    if (ev.key === "ArrowLeft" || ev.key === "PageUp") go(state.page - 1);
  });
  document.addEventListener("contextmenu", (ev) => { if (state.doc) ev.preventDefault(); });
  document.addEventListener("visibilitychange", () => {
    document.body.classList.toggle("blurred", document.hidden && !!state.doc);
  });

  if (state.accessToken) loadLibrary(); else show("login-view");
})();
