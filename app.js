(() => {
  "use strict";

  const DB_NAME = "tracker-secure-db";
  const DB_VERSION = 1;
  const STORE_NAME = "secure";
  const STORE_KEY = "encrypted-state";
  const SCHEMA_VERSION = 1;
  const FORMAT_VERSION = 1;
  const PBKDF2_ITERATIONS = 310000;
  const AUTO_LOCK_MS = 30000;

  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();
  const categoryCollator = new Intl.Collator(undefined, { sensitivity: "base", numeric: true });

  let state = null;
  let sessionKey = null;
  let sessionSalt = null;
  let currentEnvelope = null;
  let activeView = "today";
  let historyDate = localDateKey(new Date());
  let pendingImport = null;
  let confirmAction = null;
  let deferredInstallPrompt = null;
  let toastTimer = null;
  let autoLockTimer = null;
  let saveChain = Promise.resolve();

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

  document.addEventListener("DOMContentLoaded", init);

  async function init() {
    bindEvents();
    $("#history-date").value = historyDate;
    $("#header-date").textContent = longDate(new Date());

    if (!window.crypto?.subtle) {
      showGateForm("setup");
      $("#setup-error").textContent = "Encryption requires a secure browser connection.";
      $("#setup-form button[type='submit']").disabled = true;
      return;
    }

    try {
      currentEnvelope = await dbGet();
      showGateForm(currentEnvelope ? "unlock" : "setup");
    } catch (error) {
      showGateForm("setup");
      $("#setup-error").textContent = "Local storage could not be opened in this browser.";
      console.error(error);
    }

    if ("serviceWorker" in navigator) {
      navigator.serviceWorker.register("./sw.js").catch(() => {});
    }
  }

  function bindEvents() {
    $("#setup-form").addEventListener("submit", createTracker);
    $("#unlock-form").addEventListener("submit", unlockTracker);
    $("#restore-form").addEventListener("submit", restoreAtGate);
    $("#restore-start").addEventListener("click", () => showGateForm("restore"));
    $("#restore-cancel").addEventListener("click", () => showGateForm(currentEnvelope ? "unlock" : "setup"));
    $("#restore-file").addEventListener("change", updateRestoreFileName);

    $$("[data-view]").forEach(button => button.addEventListener("click", () => showView(button.dataset.view)));
    $$("[data-view-link]").forEach(link => link.addEventListener("click", event => {
      event.preventDefault();
      showView(link.dataset.viewLink);
    }));
    $("#lock-button").addEventListener("click", lockTracker);
    $("#mobile-lock-button").addEventListener("click", lockTracker);
    $("#header-action").addEventListener("click", handleHeaderAction);

    $("#date-prev").addEventListener("click", () => shiftHistoryDate(-1));
    $("#date-next").addEventListener("click", () => shiftHistoryDate(1));
    $("#history-date").addEventListener("change", event => {
      historyDate = event.target.value || localDateKey(new Date());
      renderHistory();
    });

    $("#category-type").addEventListener("change", () => updateCategoryFields(true));
    $("#category-form").addEventListener("submit", saveCategory);
    $("#entry-category").addEventListener("change", () => updateEntryInput());
    $("#entry-scale").addEventListener("input", () => {
      $("#scale-value").textContent = formatNumeric($("#entry-scale").value);
    });
    $("#entry-form").addEventListener("submit", saveEntry);
    $("#password-form").addEventListener("submit", changePassword);
    $("#import-form").addEventListener("submit", importData);

    $("#today-content").addEventListener("click", handleContentClick);
    $("#history-content").addEventListener("click", handleContentClick);
    $("#categories-content").addEventListener("click", handleContentClick);

    $("#change-password-button").addEventListener("click", openPasswordDialog);
    $("#export-encrypted").addEventListener("click", exportEncrypted);
    $("#copy-today").addEventListener("click", event => copyForAI("today", [localDateKey(new Date())], event.currentTarget));
    $("#copy-specific-dates").addEventListener("click", openCopyDatesDialog);
    $("#copy-all").addEventListener("click", event => copyForAI("all", null, event.currentTarget));
    $("#copy-dates-form").addEventListener("submit", copySelectedDates);
    $("#copy-date-list").addEventListener("change", updateCopyDatesSelection);
    $("#import-file").addEventListener("change", prepareImport);
    $("#reset-button").addEventListener("click", confirmReset);
    $("#install-button").addEventListener("click", installApp);

    $$("[data-close-dialog]").forEach(button => button.addEventListener("click", () => button.closest("dialog").close()));
    $$("dialog").forEach(dialog => dialog.addEventListener("click", event => {
      if (event.target === dialog) dialog.close();
    }));
    $("#confirm-dialog").addEventListener("close", handleConfirmClose);

    window.addEventListener("beforeinstallprompt", event => {
      event.preventDefault();
      deferredInstallPrompt = event;
      $("#install-card").hidden = false;
    });
    window.addEventListener("appinstalled", () => {
      deferredInstallPrompt = null;
      $("#install-card").hidden = true;
      showToast("Tracker installed");
    });

    ["pointerdown", "pointermove", "keydown", "touchstart", "scroll", "wheel"].forEach(type => {
      window.addEventListener(type, resetAutoLockTimer, { passive: true });
    });
    document.addEventListener("visibilitychange", () => {
      if (document.hidden && state) lockTracker();
    });
    window.addEventListener("pagehide", () => {
      if (state) lockTracker();
    });
    document.addEventListener("freeze", () => {
      if (state) lockTracker();
    });
  }

  function showGateForm(name) {
    $("#gate").hidden = false;
    $("#app").hidden = true;
    ["setup", "unlock", "restore"].forEach(item => {
      $("#" + item + "-form").hidden = item !== name;
    });
    requestAnimationFrame(() => {
      const input = $("#" + name + "-form input:not([type='file'])");
      input?.focus();
    });
  }

  async function createTracker(event) {
    event.preventDefault();
    const password = $("#setup-password").value;
    const confirmation = $("#setup-confirm").value;
    const error = $("#setup-error");
    error.textContent = "";

    if (password.length < 8) {
      error.textContent = "Use at least 8 characters.";
      return;
    }
    if (password !== confirmation) {
      error.textContent = "Passwords do not match.";
      return;
    }

    setBusy(event.submitter, true, "Creating…");
    try {
      const now = new Date().toISOString();
      state = { schemaVersion: SCHEMA_VERSION, createdAt: now, updatedAt: now, categories: [], entries: [] };
      sessionSalt = crypto.getRandomValues(new Uint8Array(16));
      sessionKey = await deriveKey(password, sessionSalt);
      await persistNow();
      $("#setup-form").reset();
      enterApp();
    } catch (err) {
      error.textContent = "Tracker could not be created. Please try again.";
      console.error(err);
    } finally {
      setBusy(event.submitter, false);
    }
  }

  async function unlockTracker(event) {
    event.preventDefault();
    const password = $("#unlock-password").value;
    const error = $("#unlock-error");
    error.textContent = "";
    setBusy(event.submitter, true, "Unlocking…");

    try {
      const result = await decryptEnvelope(currentEnvelope, password);
      state = result.data;
      sessionKey = result.key;
      sessionSalt = result.salt;
      validateState(state);
      $("#unlock-form").reset();
      enterApp();
    } catch (err) {
      error.textContent = "Incorrect password or unreadable local data.";
    } finally {
      setBusy(event.submitter, false);
    }
  }

  async function restoreAtGate(event) {
    event.preventDefault();
    const file = $("#restore-file").files[0];
    const password = $("#restore-password").value;
    const error = $("#restore-error");
    error.textContent = "";

    if (!file) {
      error.textContent = "Choose an encrypted backup first.";
      return;
    }

    setBusy(event.submitter, true, "Restoring…");
    try {
      const envelope = JSON.parse(await file.text());
      if (!isEncryptedEnvelope(envelope)) throw new Error("Not an encrypted backup");
      const result = await decryptEnvelope(envelope, password);
      validateState(result.data);
      await dbSet(envelope);
      currentEnvelope = envelope;
      state = result.data;
      sessionKey = result.key;
      sessionSalt = result.salt;
      $("#restore-form").reset();
      enterApp();
      showToast("Backup restored");
    } catch (err) {
      error.textContent = "The backup or password is not valid.";
    } finally {
      setBusy(event.submitter, false);
    }
  }

  function updateRestoreFileName() {
    const file = $("#restore-file").files[0];
    $("#restore-file-name").textContent = file ? file.name : "Choose an encrypted Tracker backup.";
  }

  function enterApp() {
    $("#gate").hidden = true;
    $("#app").hidden = false;
    activeView = "today";
    historyDate = localDateKey(new Date());
    $("#history-date").value = historyDate;
    showView("today");
    resetAutoLockTimer();
  }

  function lockTracker() {
    clearTimeout(autoLockTimer);
    autoLockTimer = null;
    state = null;
    sessionKey = null;
    sessionSalt = null;
    pendingImport = null;
    confirmAction = null;
    activeView = "today";
    closeAllDialogs();
    clearRenderedData();
    showGateForm("unlock");
  }

  function resetAutoLockTimer() {
    if (!state) return;
    clearTimeout(autoLockTimer);
    autoLockTimer = setTimeout(lockTracker, AUTO_LOCK_MS);
  }

  function clearRenderedData() {
    ["#today-content", "#history-content", "#categories-content", "#copy-date-list"].forEach(selector => {
      $(selector).replaceChildren();
    });
    ["#today-summary", "#history-summary", "#categories-summary", "#data-counts"].forEach(selector => {
      $(selector).textContent = "";
    });
    ["#category-form", "#entry-form", "#password-form", "#copy-dates-form", "#import-form", "#unlock-form"].forEach(selector => {
      $(selector).reset();
    });
    $("#confirm-message").textContent = "";
  }

  function showView(view) {
    if (!state) return;
    activeView = view;
    $$(".view").forEach(section => section.classList.toggle("active", section.id === "view-" + view));
    $$("[data-view]").forEach(button => button.classList.toggle("active", button.dataset.view === view));

    const labels = { today: "Today", history: "History", categories: "Categories", settings: "Settings" };
    $("#view-kicker").textContent = labels[view];
    $("#header-action").hidden = view === "settings";
    $("#header-action").textContent = view === "categories" ? "New category" : "Add entry";
    $("#header-action").disabled = view !== "categories" && state.categories.length === 0;

    renderAll();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function handleHeaderAction() {
    if (activeView === "categories") openCategoryDialog();
    else openEntryDialog(null, null, activeView === "history" ? historyDate : null);
  }

  function renderAll() {
    renderToday();
    renderHistory();
    renderCategories();
    renderSettings();
  }

  function renderToday() {
    const today = localDateKey(new Date());
    const todayEntries = state.entries.filter(entry => localDateKey(new Date(entry.occurredAt)) === today);
    $("#today-summary").textContent = todayEntries.length
      ? plural(todayEntries.length, "entry", "entries") + " across " + plural(new Set(todayEntries.map(entry => entry.categoryId)).size, "category", "categories")
      : "Nothing recorded yet today.";

    const root = $("#today-content");
    if (!state.categories.length) {
      root.innerHTML = emptyState("Your tracker is empty", "Create a category to decide what you want to record.", "Create category", "new-category");
      return;
    }

    root.innerHTML = `<div class="category-grid">${sortedCategories().map(category => {
      const entries = todayEntries
        .filter(entry => entry.categoryId === category.id)
        .sort((a, b) => new Date(b.occurredAt) - new Date(a.occurredAt));
      const latest = entries[0];
      return `<article class="category-card">
        <div class="category-card-head">
          <div>
            <h2>${escapeHtml(category.name)}</h2>
            <p class="category-meta">${categoryDescriptor(category)}</p>
          </div>
          <span class="category-count">${plural(entries.length, "entry", "entries")}</span>
        </div>
        <div class="latest-value">
          <strong${category.type === "text" ? " class=\"text-value\"" : ""}>${latest ? escapeHtml(formatValue(latest.value, category)) : "—"}</strong>
          <span>${latest ? "Latest at " + shortTime(latest.occurredAt) : "No entry today"}</span>
        </div>
        <div class="category-actions">
          <button class="button primary" type="button" data-action="add-entry" data-category-id="${category.id}">Add entry</button>
        </div>
      </article>`;
    }).join("")}</div>`;
  }

  function renderHistory() {
    const entries = state.entries
      .filter(entry => localDateKey(new Date(entry.occurredAt)) === historyDate)
      .sort((a, b) => new Date(b.occurredAt) - new Date(a.occurredAt));
    const selected = dateFromLocalKey(historyDate);
    $("#history-title").textContent = isToday(historyDate) ? "Today" : compactDate(selected);
    $("#history-summary").textContent = entries.length ? plural(entries.length, "entry", "entries") : "Nothing recorded on this day.";
    $("#history-date").value = historyDate;
    $("#date-next").disabled = isToday(historyDate);

    const root = $("#history-content");
    if (!entries.length) {
      root.innerHTML = emptyState("No entries", "Choose another day or add an entry for this date.", state.categories.length ? "Add entry" : "Create category", state.categories.length ? "add-entry" : "new-category");
      return;
    }

    root.innerHTML = `<div class="history-list">${entries.map(entry => {
      const category = state.categories.find(item => item.id === entry.categoryId);
      if (!category) return "";
      const isText = category.type === "text";
      const noteMarkup = isText ? "" : `<div class="history-note${entry.note ? "" : " empty"}">${entry.note ? escapeHtml(entry.note) : "No notes"}</div>`;
      return `<article class="history-item${isText ? " text-entry" : ""}">
        <div><span class="history-name">${escapeHtml(category.name)}</span><time class="history-time" datetime="${escapeHtml(entry.occurredAt)}">${shortTime(entry.occurredAt)}${entry.updatedAt ? " · Edited" : ""}</time></div>
        <div class="history-value">${escapeHtml(formatValue(entry.value, category))}</div>
        ${noteMarkup}
        <div class="item-actions">
          <button class="icon-button" type="button" data-action="edit-entry" data-entry-id="${entry.id}" aria-label="Edit entry">
            <svg aria-hidden="true" viewBox="0 0 24 24"><path d="m14 5 5 5M4 20l3.5-.75L19 7.75A2.12 2.12 0 0 0 16 4.75L4.75 16 4 20Z"/></svg>
          </button>
          <button class="icon-button" type="button" data-action="delete-entry" data-entry-id="${entry.id}" aria-label="Delete entry">
            <svg aria-hidden="true" viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3M7 7l.8 13h8.4L17 7M10 11v5M14 11v5"/></svg>
          </button>
        </div>
      </article>`;
    }).join("")}</div>`;
  }

  function renderCategories() {
    $("#categories-summary").textContent = state.categories.length ? plural(state.categories.length, "category", "categories") : "Create the areas you want to track.";
    const root = $("#categories-content");
    if (!state.categories.length) {
      root.innerHTML = emptyState("No categories", "Your tracker begins with the categories you create.", "Create category", "new-category");
      return;
    }

    root.innerHTML = `<div class="category-list">${sortedCategories().map(category => {
      const count = state.entries.filter(entry => entry.categoryId === category.id).length;
      return `<article class="category-row">
        <div><h2>${escapeHtml(category.name)}</h2><p>${plural(count, "entry", "entries")}</p></div>
        <div class="category-range">${categoryDescriptor(category)}</div>
        <div class="item-actions">
          <button class="icon-button" type="button" data-action="edit-category" data-category-id="${category.id}" aria-label="Edit ${escapeHtml(category.name)}">
            <svg aria-hidden="true" viewBox="0 0 24 24"><path d="m14 5 5 5M4 20l3.5-.75L19 7.75A2.12 2.12 0 0 0 16 4.75L4.75 16 4 20Z"/></svg>
          </button>
          <button class="icon-button" type="button" data-action="delete-category" data-category-id="${category.id}" aria-label="Delete ${escapeHtml(category.name)}">
            <svg aria-hidden="true" viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3M7 7l.8 13h8.4L17 7M10 11v5M14 11v5"/></svg>
          </button>
        </div>
      </article>`;
    }).join("")}</div>`;
  }

  function renderSettings() {
    $("#data-counts").textContent = `${plural(state.categories.length, "category", "categories")} · ${plural(state.entries.length, "entry", "entries")} · Stored encrypted on this device`;
    const dates = availableEntryDates();
    $("#copy-today").disabled = !dates.some(item => item.key === localDateKey(new Date()));
    $("#copy-specific-dates").disabled = dates.length === 0;
    $("#copy-all").disabled = state.entries.length === 0;
  }

  function emptyState(title, copy, actionLabel, action) {
    return `<div class="empty-state"><div class="empty-inner"><div class="empty-mark"></div><h2>${escapeHtml(title)}</h2><p>${escapeHtml(copy)}</p><button class="button primary" type="button" data-action="${action}">${escapeHtml(actionLabel)}</button></div></div>`;
  }

  function handleContentClick(event) {
    const button = event.target.closest("[data-action]");
    if (!button) return;
    const action = button.dataset.action;
    if (action === "new-category") openCategoryDialog();
    if (action === "add-entry") openEntryDialog(button.dataset.categoryId || null, null, activeView === "history" ? historyDate : null);
    if (action === "edit-entry") openEntryDialog(null, button.dataset.entryId);
    if (action === "delete-entry") confirmDeleteEntry(button.dataset.entryId);
    if (action === "edit-category") openCategoryDialog(button.dataset.categoryId);
    if (action === "delete-category") confirmDeleteCategory(button.dataset.categoryId);
  }

  function openCategoryDialog(categoryId = null) {
    const form = $("#category-form");
    form.reset();
    $("#category-error").textContent = "";
    $("#category-id").value = categoryId || "";
    $("#category-dialog-title").textContent = categoryId ? "Edit category" : "New category";

    if (categoryId) {
      const category = state.categories.find(item => item.id === categoryId);
      if (!category) return;
      $("#category-name").value = category.name;
      $("#category-type").value = category.type;
      $("#category-min").value = category.min ?? "";
      $("#category-max").value = category.max ?? "";
      $("#category-step").value = category.step ?? "";
      $("#category-unit").value = category.unit || "";
    } else {
      $("#category-type").value = "scale";
      $("#category-step").value = "1";
    }
    updateCategoryFields();
    $("#category-dialog").showModal();
    requestAnimationFrame(() => $("#category-name").focus());
  }

  function updateCategoryFields(useTypeDefault = false) {
    const type = $("#category-type").value;
    const isNumeric = type === "scale" || type === "number";
    const isNumber = type === "number";
    $("#range-fields").hidden = !isNumeric;
    $("#step-unit-fields").hidden = !isNumeric;
    $("#unit-field").hidden = !isNumber;
    [$("#category-min"), $("#category-max"), $("#category-step")].forEach(input => {
      input.disabled = !isNumeric;
      input.required = isNumeric;
    });
    $("#category-unit").disabled = !isNumber;
    if (isNumeric && (useTypeDefault || !$("#category-step").value)) $("#category-step").value = isNumber ? "0.1" : "1";
    if (!isNumber) $("#category-unit").value = "";
  }

  async function saveCategory(event) {
    event.preventDefault();
    const id = $("#category-id").value;
    const name = $("#category-name").value.trim();
    const type = $("#category-type").value;
    const isNumeric = type === "scale" || type === "number";
    const min = isNumeric ? Number($("#category-min").value) : null;
    const max = isNumeric ? Number($("#category-max").value) : null;
    const step = isNumeric ? Number($("#category-step").value) : null;
    const unit = type === "number" ? $("#category-unit").value.trim() : "";
    const error = $("#category-error");
    error.textContent = "";

    if (!name) return void (error.textContent = "Enter a category name.");
    if (!["scale", "number", "yesno", "text"].includes(type)) return void (error.textContent = "Choose a valid input type.");
    if (isNumeric && ![min, max, step].every(Number.isFinite)) return void (error.textContent = "Enter valid minimum, maximum and step values.");
    if (isNumeric && max <= min) return void (error.textContent = "Maximum must be greater than minimum.");
    if (isNumeric && (step <= 0 || step > max - min)) return void (error.textContent = "Step must be greater than zero and fit within the range.");
    const duplicate = state.categories.find(category => category.name.toLowerCase() === name.toLowerCase() && category.id !== id);
    if (duplicate) return void (error.textContent = "A category with this name already exists.");
    const existingCategory = id ? state.categories.find(item => item.id === id) : null;
    const hasEntries = id && state.entries.some(entry => entry.categoryId === id);
    if (existingCategory && existingCategory.type !== type && hasEntries) {
      return void (error.textContent = "Input type cannot be changed after entries have been recorded.");
    }

    const now = new Date().toISOString();
    if (id) {
      Object.assign(existingCategory, { name, type, min, max, step, unit, updatedAt: now });
    } else {
      state.categories.push({ id: makeId("cat"), name, type, min, max, step, unit, createdAt: now, updatedAt: null });
    }

    await persist();
    $("#category-dialog").close();
    renderAll();
    $("#header-action").disabled = false;
    showToast(id ? "Category updated" : "Category created");
  }

  function openEntryDialog(categoryId = null, entryId = null, targetDate = null) {
    if (!state.categories.length) {
      openCategoryDialog();
      return;
    }
    const form = $("#entry-form");
    form.reset();
    $("#entry-error").textContent = "";
    $("#entry-id").value = entryId || "";
    $("#entry-dialog-title").textContent = entryId ? "Edit entry" : "New entry";
    $("#entry-category").innerHTML = sortedCategories().map(category => `<option value="${category.id}">${escapeHtml(category.name)}</option>`).join("");

    if (entryId) {
      const entry = state.entries.find(item => item.id === entryId);
      if (!entry) return;
      $("#entry-category").value = entry.categoryId;
      $("#entry-time").value = toDateTimeLocal(new Date(entry.occurredAt));
      $("#entry-note").value = entry.note || "";
      updateEntryInput(entry.value);
    } else {
      if (categoryId && state.categories.some(category => category.id === categoryId)) $("#entry-category").value = categoryId;
      const date = targetDate && !isToday(targetDate) ? dateFromLocalKey(targetDate, 12, 0) : new Date();
      $("#entry-time").value = toDateTimeLocal(date);
      updateEntryInput();
    }

    $("#entry-dialog").showModal();
  }

  function updateEntryInput(initialValue = null) {
    const category = state.categories.find(item => item.id === $("#entry-category").value);
    if (!category) return;
    const categoryCount = $("#entry-category-count");
    const today = localDateKey(new Date());
    const entriesToday = $("#entry-id").value
      ? 0
      : state.entries.filter(entry => entry.categoryId === category.id && localDateKey(new Date(entry.occurredAt)) === today).length;
    categoryCount.textContent = entriesToday ? `${plural(entriesToday, "entry", "entries")} today` : "";
    categoryCount.hidden = entriesToday === 0;
    const isScale = category.type === "scale";
    const isNumber = category.type === "number";
    const isYesNo = category.type === "yesno";
    const isText = category.type === "text";
    $("#scale-input-wrap").hidden = !isScale;
    $("#number-input-wrap").hidden = !isNumber;
    $("#yesno-input-wrap").hidden = !isYesNo;
    $("#text-input-wrap").hidden = !isText;
    $("#entry-note-field").hidden = isText;
    $("#entry-scale").disabled = !isScale;
    $("#entry-number").disabled = !isNumber;
    $("#entry-number").required = isNumber;
    $("#entry-text").disabled = !isText;
    $("#entry-text").required = isText;
    $("#entry-note").disabled = isText;
    $$("input[name='entry-yesno']").forEach(input => {
      input.disabled = !isYesNo;
      input.required = isYesNo;
      input.checked = isYesNo && initialValue !== null && (input.value === "yes") === initialValue;
    });

    if (isScale) {
      const value = initialValue ?? midpoint(category.min, category.max, category.step);
      const slider = $("#entry-scale");
      slider.min = category.min;
      slider.max = category.max;
      slider.step = category.step;
      slider.value = clamp(Number(value), category.min, category.max);
      $("#scale-value").textContent = formatNumeric(slider.value);
      $("#scale-unit").textContent = "";
      $("#scale-min").textContent = formatNumeric(category.min);
      $("#scale-max").textContent = formatNumeric(category.max);
    } else if (isNumber) {
      const input = $("#entry-number");
      input.min = category.min;
      input.max = category.max;
      input.step = category.step;
      input.value = initialValue ?? "";
      $("#number-unit").textContent = category.unit || "";
    } else if (isText) {
      $("#entry-text").value = initialValue ?? "";
    }
  }

  async function saveEntry(event) {
    event.preventDefault();
    const id = $("#entry-id").value;
    const categoryId = $("#entry-category").value;
    const category = state.categories.find(item => item.id === categoryId);
    const error = $("#entry-error");
    error.textContent = "";
    if (!category) return void (error.textContent = "Choose a valid category.");

    let value;
    if (category.type === "scale" || category.type === "number") {
      value = Number(category.type === "scale" ? $("#entry-scale").value : $("#entry-number").value);
      if (!Number.isFinite(value)) return void (error.textContent = "Enter a valid value.");
      if (value < category.min || value > category.max) return void (error.textContent = `Value must be between ${formatNumeric(category.min)} and ${formatNumeric(category.max)}.`);
    } else if (category.type === "yesno") {
      const selected = $("input[name='entry-yesno']:checked");
      if (!selected) return void (error.textContent = "Choose Yes or No.");
      value = selected.value === "yes";
    } else {
      value = $("#entry-text").value.trim();
      if (!value) return void (error.textContent = "Enter some text.");
    }

    const occurredAt = new Date($("#entry-time").value);
    if (Number.isNaN(occurredAt.getTime())) return void (error.textContent = "Choose a valid date and time.");
    if (occurredAt.getTime() > Date.now() + 60000) return void (error.textContent = "Entry time cannot be in the future.");
    const note = category.type === "text" ? "" : $("#entry-note").value.trim();
    const now = new Date().toISOString();

    if (id) {
      const entry = state.entries.find(item => item.id === id);
      if (!entry) return;
      Object.assign(entry, { categoryId, value, note, occurredAt: occurredAt.toISOString(), updatedAt: now });
    } else {
      state.entries.push({ id: makeId("entry"), categoryId, value, note, occurredAt: occurredAt.toISOString(), createdAt: now, updatedAt: null });
    }

    historyDate = localDateKey(occurredAt);
    await persist();
    $("#entry-dialog").close();
    renderAll();
    showToast(id ? "Entry updated" : "Entry saved");
  }

  function confirmDeleteEntry(entryId) {
    const entry = state.entries.find(item => item.id === entryId);
    if (!entry) return;
    const category = state.categories.find(item => item.id === entry.categoryId);
    openConfirm({
      title: "Delete entry?",
      message: `This will permanently remove the ${category?.name || "selected"} entry from ${shortDateTime(entry.occurredAt)}.`,
      label: "Delete entry",
      action: async () => {
        state.entries = state.entries.filter(item => item.id !== entryId);
        await persist();
        renderAll();
        showToast("Entry deleted");
      }
    });
  }

  function confirmDeleteCategory(categoryId) {
    const category = state.categories.find(item => item.id === categoryId);
    if (!category) return;
    const count = state.entries.filter(entry => entry.categoryId === categoryId).length;
    openConfirm({
      title: `Delete ${category.name}?`,
      message: count ? `This will permanently remove the category and ${plural(count, "related entry", "related entries")}.` : "This category will be permanently removed.",
      label: "Delete category",
      action: async () => {
        state.categories = state.categories.filter(item => item.id !== categoryId);
        state.entries = state.entries.filter(item => item.categoryId !== categoryId);
        await persist();
        renderAll();
        $("#header-action").disabled = activeView !== "categories" && state.categories.length === 0;
        showToast("Category deleted");
      }
    });
  }

  function openPasswordDialog() {
    $("#password-form").reset();
    $("#password-error").textContent = "";
    $("#password-dialog").showModal();
    requestAnimationFrame(() => $("#current-password").focus());
  }

  async function changePassword(event) {
    event.preventDefault();
    const currentPassword = $("#current-password").value;
    const newPassword = $("#new-password").value;
    const confirmation = $("#confirm-new-password").value;
    const error = $("#password-error");
    error.textContent = "";
    if (newPassword.length < 8) return void (error.textContent = "Use at least 8 characters.");
    if (newPassword !== confirmation) return void (error.textContent = "New passwords do not match.");

    setBusy(event.submitter, true, "Updating…");
    try {
      await decryptEnvelope(currentEnvelope, currentPassword);
      sessionSalt = crypto.getRandomValues(new Uint8Array(16));
      sessionKey = await deriveKey(newPassword, sessionSalt);
      await persistNow();
      $("#password-dialog").close();
      showToast("Password updated");
    } catch (err) {
      error.textContent = "Current password is incorrect.";
    } finally {
      setBusy(event.submitter, false);
    }
  }

  async function exportEncrypted() {
    try {
      await persist();
      downloadJson(currentEnvelope, fileName("tracker-backup"));
      showToast("Encrypted backup exported");
    } catch (err) {
      showToast("Backup could not be exported");
    }
  }

  function openCopyDatesDialog() {
    const dates = availableEntryDates();
    if (!dates.length) {
      showToast("There are no entries to copy");
      return;
    }

    $("#copy-dates-error").textContent = "";
    $("#copy-selected-dates").disabled = true;
    $("#copy-date-list").innerHTML = dates.map(item => `<label class="date-choice">
      <input type="checkbox" name="copy-date" value="${escapeHtml(item.key)}">
      <span><strong>${escapeHtml(fullDate(dateFromLocalKey(item.key, 12, 0)))}</strong><small>${plural(item.count, "entry", "entries")}</small></span>
    </label>`).join("");
    $("#copy-dates-dialog").showModal();
  }

  function updateCopyDatesSelection() {
    $("#copy-selected-dates").disabled = $$("input[name='copy-date']:checked", $("#copy-date-list")).length === 0;
    $("#copy-dates-error").textContent = "";
  }

  async function copySelectedDates(event) {
    event.preventDefault();
    const dates = new FormData(event.currentTarget).getAll("copy-date").map(String);
    if (!dates.length) {
      $("#copy-dates-error").textContent = "Choose at least one date.";
      return;
    }
    const copied = await copyForAI("specific_dates", dates, event.submitter);
    if (copied) $("#copy-dates-dialog").close();
  }

  async function copyForAI(mode, dateKeys, button) {
    setBusy(button, true, "Copying…");
    try {
      const exportData = buildReadableExport(mode, dateKeys);
      if (!exportData.entries.length) {
        showToast("There are no entries to copy");
        return false;
      }
      await copyText(JSON.stringify(exportData, null, 2));
      showToast(mode === "today" ? "Today's entries copied for AI" : mode === "all" ? "All entries copied for AI" : "Selected dates copied for AI");
      return true;
    } catch (err) {
      showToast("Data could not be copied");
      return false;
    } finally {
      setBusy(button, false);
    }
  }

  function buildReadableExport(mode = "all", dateKeys = null) {
    const selectedDates = mode === "all"
      ? null
      : [...new Set((dateKeys || []).map(String))].sort();
    const selectedDateSet = selectedDates ? new Set(selectedDates) : null;
    const sourceEntries = state.entries.filter(entry => !selectedDateSet || selectedDateSet.has(localDateKey(new Date(entry.occurredAt))));
    const usedCategoryIds = new Set(sourceEntries.map(entry => entry.categoryId));
    const sourceCategories = mode === "all" ? state.categories : state.categories.filter(category => usedCategoryIds.has(category.id));
    const categories = sortedCategories(sourceCategories).map(category => ({
      id: category.id,
      name: category.name,
      inputType: category.type,
      minimum: category.min,
      maximum: category.max,
      step: category.step,
      unit: category.unit || null,
      createdAt: category.createdAt,
      updatedAt: category.updatedAt
    }));
    const categoryMap = new Map(categories.map(category => [category.id, category]));
    const entries = [...sourceEntries]
      .sort((a, b) => new Date(a.occurredAt) - new Date(b.occurredAt))
      .map(entry => ({
        id: entry.id,
        categoryId: entry.categoryId,
        categoryName: categoryMap.get(entry.categoryId)?.name || null,
        value: entry.value,
        unit: categoryMap.get(entry.categoryId)?.unit || null,
        notes: categoryMap.get(entry.categoryId)?.inputType === "text" ? null : entry.note || "",
        occurredAt: entry.occurredAt,
        localDate: localDateKey(new Date(entry.occurredAt)),
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt
      }));
    return {
      kind: "tracker-readable-export",
      formatVersion: FORMAT_VERSION,
      app: "Tracker",
      exportedAt: new Date().toISOString(),
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "unknown",
      selection: {
        mode,
        dates: selectedDates || availableEntryDates().map(item => item.key).sort()
      },
      summary: { categories: categories.length, entries: entries.length, dates: new Set(entries.map(entry => entry.localDate)).size, firstEntryAt: entries[0]?.occurredAt || null, lastEntryAt: entries.at(-1)?.occurredAt || null },
      categories,
      entries
    };
  }

  function availableEntryDates() {
    const counts = new Map();
    state.entries.forEach(entry => {
      const key = localDateKey(new Date(entry.occurredAt));
      counts.set(key, (counts.get(key) || 0) + 1);
    });
    return [...counts].map(([key, count]) => ({ key, count })).sort((a, b) => b.key.localeCompare(a.key));
  }

  function sortedCategories(categories = state.categories) {
    return [...categories].sort((a, b) => categoryCollator.compare(a.name, b.name));
  }

  async function copyText(value) {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return;
    }

    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    textarea.style.pointerEvents = "none";
    document.body.appendChild(textarea);
    textarea.select();
    const copied = document.execCommand("copy");
    textarea.remove();
    if (!copied) throw new Error("Clipboard unavailable");
  }

  async function prepareImport(event) {
    const file = event.target.files[0];
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text());
      if (!isEncryptedEnvelope(parsed) && parsed?.kind !== "tracker-readable-export") throw new Error("Unsupported file");
      pendingImport = parsed;
      $("#import-form").reset();
      $("#import-error").textContent = "";
      $("#import-password-field").hidden = !isEncryptedEnvelope(parsed);
      $("#import-description").textContent = isEncryptedEnvelope(parsed)
        ? `${file.name} is an encrypted backup. Enter its password, then merge or replace your current data.`
        : `${file.name} is a readable export. Choose whether to merge it with or replace your current data.`;
      $("#import-dialog").showModal();
    } catch (err) {
      showToast("This is not a valid Tracker export");
    } finally {
      event.target.value = "";
    }
  }

  async function importData(event) {
    event.preventDefault();
    if (!pendingImport) return;
    const mode = new FormData(event.currentTarget).get("import-mode") || "merge";
    const error = $("#import-error");
    error.textContent = "";
    setBusy(event.submitter, true, "Importing…");

    try {
      let incoming;
      if (isEncryptedEnvelope(pendingImport)) {
        const password = $("#import-password").value;
        if (!password) throw new Error("Enter the backup password.");
        incoming = (await decryptEnvelope(pendingImport, password)).data;
      } else {
        incoming = readableToState(pendingImport);
      }
      validateState(incoming);
      state = mode === "replace" ? normalizeState(incoming) : mergeStates(state, incoming);
      await persist();
      pendingImport = null;
      $("#import-dialog").close();
      renderAll();
      $("#header-action").disabled = activeView !== "categories" && state.categories.length === 0;
      showToast(mode === "replace" ? "Data replaced" : "Data merged");
    } catch (err) {
      error.textContent = err.message === "Enter the backup password." ? err.message : "The file or backup password is not valid.";
    } finally {
      setBusy(event.submitter, false);
    }
  }

  function readableToState(exported) {
    const now = new Date().toISOString();
    const categories = (exported.categories || []).map(category => {
      const type = category.inputType;
      const isNumeric = type === "scale" || type === "number";
      return {
        id: String(category.id),
        name: String(category.name),
        type,
        min: isNumeric ? Number(category.minimum) : null,
        max: isNumeric ? Number(category.maximum) : null,
        step: isNumeric ? Number(category.step) : null,
        unit: type === "number" && category.unit ? String(category.unit) : "",
        createdAt: category.createdAt || now,
        updatedAt: category.updatedAt || null
      };
    });
    const categoryMap = new Map(categories.map(category => [category.id, category]));
    return {
      schemaVersion: SCHEMA_VERSION,
      createdAt: exported.exportedAt || now,
      updatedAt: now,
      categories,
      entries: (exported.entries || []).map(entry => {
        const categoryId = String(entry.categoryId);
        const category = categoryMap.get(categoryId);
        return {
          id: String(entry.id),
          categoryId,
          value: importedValue(entry.value, category?.type),
          note: category?.type === "text" ? "" : String(entry.notes || ""),
          occurredAt: entry.occurredAt,
          createdAt: entry.createdAt || entry.occurredAt,
          updatedAt: entry.updatedAt || null
        };
      })
    };
  }

  function importedValue(value, type) {
    if (type === "scale" || type === "number") return Number(value);
    if (type === "text") return String(value ?? "");
    if (type === "yesno") {
      if (value === true || value === "yes" || value === "true" || value === 1) return true;
      if (value === false || value === "no" || value === "false" || value === 0) return false;
    }
    return value;
  }

  function mergeStates(existing, incoming) {
    const result = normalizeState(existing);
    const categoryMap = new Map();

    incoming.categories.forEach(category => {
      const sameId = result.categories.find(item => item.id === category.id);
      if (!sameId) {
        result.categories.push({ ...category });
        categoryMap.set(category.id, category.id);
        return;
      }
      if (categorySignature(sameId) === categorySignature(category)) {
        categoryMap.set(category.id, sameId.id);
        return;
      }
      const newId = makeId("cat");
      result.categories.push({ ...category, id: newId, name: uniqueCategoryName(category.name, result.categories) });
      categoryMap.set(category.id, newId);
    });

    const existingEntryIds = new Set(result.entries.map(entry => entry.id));
    incoming.entries.forEach(entry => {
      if (existingEntryIds.has(entry.id)) return;
      const mappedCategoryId = categoryMap.get(entry.categoryId);
      if (!mappedCategoryId) return;
      result.entries.push({ ...entry, categoryId: mappedCategoryId });
      existingEntryIds.add(entry.id);
    });
    result.updatedAt = new Date().toISOString();
    return result;
  }

  function normalizeState(value) {
    return JSON.parse(JSON.stringify({
      schemaVersion: SCHEMA_VERSION,
      createdAt: value.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      categories: value.categories || [],
      entries: value.entries || []
    }));
  }

  function categorySignature(category) {
    return JSON.stringify([category.name, category.type, Number(category.min), Number(category.max), Number(category.step), category.unit || ""]);
  }

  function uniqueCategoryName(name, categories) {
    let candidate = name + " (Imported)";
    let index = 2;
    const names = new Set(categories.map(category => category.name.toLowerCase()));
    while (names.has(candidate.toLowerCase())) candidate = `${name} (Imported ${index++})`;
    return candidate;
  }

  function confirmReset() {
    openConfirm({
      kicker: "Permanent action",
      title: "Reset Tracker?",
      message: "All local categories, entries and the current master password will be permanently removed. Export a backup first if you may need this data.",
      label: "Reset everything",
      action: async () => {
        await dbDelete();
        currentEnvelope = null;
        state = null;
        sessionKey = null;
        sessionSalt = null;
        closeAllDialogs();
        showGateForm("setup");
        showToast("Tracker reset");
      }
    });
  }

  function openConfirm({ kicker = "Confirm", title, message, label, action }) {
    confirmAction = action;
    $("#confirm-dialog").returnValue = "";
    $("#confirm-kicker").textContent = kicker;
    $("#confirm-title").textContent = title;
    $("#confirm-message").textContent = message;
    $("#confirm-accept").textContent = label;
    $("#confirm-dialog").showModal();
  }

  async function handleConfirmClose() {
    if ($("#confirm-dialog").returnValue === "confirm" && confirmAction) {
      const action = confirmAction;
      confirmAction = null;
      try { await action(); } catch (err) { showToast("That change could not be saved"); }
    } else {
      confirmAction = null;
    }
  }

  async function installApp() {
    if (!deferredInstallPrompt) return;
    deferredInstallPrompt.prompt();
    await deferredInstallPrompt.userChoice;
    deferredInstallPrompt = null;
    $("#install-card").hidden = true;
  }

  function shiftHistoryDate(days) {
    const date = dateFromLocalKey(historyDate, 12, 0);
    date.setDate(date.getDate() + days);
    if (date > new Date()) return;
    historyDate = localDateKey(date);
    renderHistory();
  }

  async function persist() {
    saveChain = saveChain.catch(() => {}).then(persistNow);
    return saveChain;
  }

  async function persistNow() {
    if (!state || !sessionKey || !sessionSalt) throw new Error("Tracker is locked");
    state.updatedAt = new Date().toISOString();
    currentEnvelope = await encryptState(state, sessionKey, sessionSalt);
    await dbSet(currentEnvelope);
  }

  async function deriveKey(password, salt) {
    const material = await crypto.subtle.importKey("raw", textEncoder.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptState(data, key, salt) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, textEncoder.encode(JSON.stringify(data)));
    return {
      kind: "tracker-encrypted-backup",
      formatVersion: FORMAT_VERSION,
      app: "Tracker",
      generatedAt: new Date().toISOString(),
      kdf: { name: "PBKDF2", hash: "SHA-256", iterations: PBKDF2_ITERATIONS, salt: bytesToBase64(salt) },
      cipher: { name: "AES-GCM", iv: bytesToBase64(iv) },
      ciphertext: bytesToBase64(new Uint8Array(ciphertext))
    };
  }

  async function decryptEnvelope(envelope, password) {
    if (!isEncryptedEnvelope(envelope)) throw new Error("Invalid encrypted backup");
    const salt = base64ToBytes(envelope.kdf.salt);
    const iv = base64ToBytes(envelope.cipher.iv);
    const key = await deriveKeyWithIterations(password, salt, envelope.kdf.iterations);
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, base64ToBytes(envelope.ciphertext));
    return { data: JSON.parse(textDecoder.decode(plaintext)), key, salt };
  }

  async function deriveKeyWithIterations(password, salt, iterations) {
    const safeIterations = Number(iterations);
    if (!Number.isInteger(safeIterations) || safeIterations < 100000 || safeIterations > 2000000) throw new Error("Unsupported key settings");
    const material = await crypto.subtle.importKey("raw", textEncoder.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: safeIterations, hash: "SHA-256" },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  function isEncryptedEnvelope(value) {
    return value?.kind === "tracker-encrypted-backup"
      && value?.kdf?.name === "PBKDF2"
      && value?.kdf?.hash === "SHA-256"
      && value?.cipher?.name === "AES-GCM"
      && typeof value?.kdf?.salt === "string"
      && typeof value?.cipher?.iv === "string"
      && typeof value?.ciphertext === "string";
  }

  function validateState(value) {
    if (!value || !Array.isArray(value.categories) || !Array.isArray(value.entries)) throw new Error("Invalid data structure");
    const categoryIds = new Set();
    const categoriesById = new Map();
    value.categories.forEach(category => {
      if (!category || typeof category.id !== "string" || !category.id || typeof category.name !== "string" || !category.name.trim()) throw new Error("Invalid category");
      if (!["scale", "number", "yesno", "text"].includes(category.type)) throw new Error("Invalid category type");
      if ((category.type === "scale" || category.type === "number") && (![category.min, category.max, category.step].every(Number.isFinite) || category.max <= category.min || category.step <= 0)) throw new Error("Invalid category range");
      if (categoryIds.has(category.id)) throw new Error("Duplicate category");
      categoryIds.add(category.id);
      categoriesById.set(category.id, category);
    });
    const entryIds = new Set();
    value.entries.forEach(entry => {
      if (!entry || typeof entry.id !== "string" || !entry.id || !categoryIds.has(entry.categoryId) || Number.isNaN(new Date(entry.occurredAt).getTime())) throw new Error("Invalid entry");
      const category = categoriesById.get(entry.categoryId);
      if ((category.type === "scale" || category.type === "number") && !Number.isFinite(entry.value)) throw new Error("Invalid numeric entry");
      if (category.type === "yesno" && typeof entry.value !== "boolean") throw new Error("Invalid Yes or No entry");
      if (category.type === "text" && (typeof entry.value !== "string" || !entry.value.trim())) throw new Error("Invalid text entry");
      if (typeof entry.note !== "string") throw new Error("Invalid entry notes");
      if (entryIds.has(entry.id)) throw new Error("Duplicate entry");
      entryIds.add(entry.id);
    });
    return true;
  }

  function openDb() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(STORE_NAME)) request.result.createObjectStore(STORE_NAME);
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async function dbGet() {
    const db = await openDb();
    try {
      return await transactionPromise(db, "readonly", store => store.get(STORE_KEY));
    } finally { db.close(); }
  }

  async function dbSet(value) {
    const db = await openDb();
    try {
      await transactionPromise(db, "readwrite", store => store.put(value, STORE_KEY));
    } finally { db.close(); }
  }

  async function dbDelete() {
    const db = await openDb();
    try {
      await transactionPromise(db, "readwrite", store => store.delete(STORE_KEY));
    } finally { db.close(); }
  }

  function transactionPromise(db, mode, operation) {
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, mode);
      const request = operation(transaction.objectStore(STORE_NAME));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
      transaction.onerror = () => reject(transaction.error);
    });
  }

  function downloadJson(value, name) {
    const blob = new Blob([JSON.stringify(value, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = name;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function bytesToBase64(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
  }

  function base64ToBytes(value) {
    const binary = atob(value);
    return Uint8Array.from(binary, char => char.charCodeAt(0));
  }

  function categoryDescriptor(category) {
    if (category.type === "yesno") return "Yes or no";
    if (category.type === "text") return "Free text";
    const range = `${formatNumeric(category.min)}–${formatNumeric(category.max)}`;
    return category.type === "scale" ? `Scale · ${range}` : `${range}${category.unit ? " " + escapeHtml(category.unit) : ""}`;
  }

  function formatValue(value, category) {
    if (category.type === "yesno") return value ? "Yes" : "No";
    if (category.type === "text") return String(value);
    return `${formatNumeric(value)}${category.unit ? " " + category.unit : ""}`;
  }

  function formatNumeric(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return "—";
    return new Intl.NumberFormat(undefined, { maximumFractionDigits: 6 }).format(number);
  }

  function midpoint(min, max, step) {
    const steps = Math.round(((min + max) / 2 - min) / step);
    return Number((min + steps * step).toFixed(8));
  }

  function clamp(value, min, max) { return Math.min(Math.max(value, min), max); }

  function localDateKey(date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const day = String(date.getDate()).padStart(2, "0");
    return `${year}-${month}-${day}`;
  }

  function dateFromLocalKey(key, hour = 0, minute = 0) {
    const [year, month, day] = key.split("-").map(Number);
    return new Date(year, month - 1, day, hour, minute);
  }

  function toDateTimeLocal(date) {
    const pad = value => String(value).padStart(2, "0");
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }

  function isToday(key) { return key === localDateKey(new Date()); }
  function longDate(date) { return new Intl.DateTimeFormat(undefined, { weekday: "long", day: "numeric", month: "long" }).format(date); }
  function fullDate(date) { return new Intl.DateTimeFormat(undefined, { weekday: "long", day: "numeric", month: "long", year: "numeric" }).format(date); }
  function compactDate(date) { return new Intl.DateTimeFormat(undefined, { weekday: "short", day: "numeric", month: "short" }).format(date); }
  function shortTime(value) { return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" }).format(new Date(value)); }
  function shortDateTime(value) { return new Intl.DateTimeFormat(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }).format(new Date(value)); }

  function plural(count, singular, pluralForm) { return `${count} ${count === 1 ? singular : pluralForm}`; }
  function makeId(prefix) { return `${prefix}_${crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).slice(2)}`; }
  function fileName(prefix) { return `${prefix}-${localDateKey(new Date())}.json`; }

  function escapeHtml(value) {
    return String(value).replace(/[&<>'"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);
  }

  function setBusy(button, busy, label = "Working…") {
    if (!button) return;
    if (busy) {
      button.dataset.originalText = button.textContent;
      button.textContent = label;
      button.disabled = true;
    } else {
      button.textContent = button.dataset.originalText || button.textContent;
      button.disabled = false;
    }
  }

  function showToast(message) {
    const toast = $("#toast");
    clearTimeout(toastTimer);
    toast.textContent = message;
    toast.classList.add("show");
    toastTimer = setTimeout(() => toast.classList.remove("show"), 2600);
  }

  function closeAllDialogs() {
    $$("dialog[open]").forEach(dialog => dialog.close());
  }
})();
