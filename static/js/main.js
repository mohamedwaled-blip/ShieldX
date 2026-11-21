
(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const app = $("#app");
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ------------------------------------------------------------------ state */
  const state = {
    lang: "ar",
    maxMb: 16,
    busy: false,
    live: null,            // { kind: "url"|"file", input, data } | { loading } | { error }
    file: null,            // الملف المختار في قسم فحص الملفات
    preview: { phase: "empty" },  // empty | ready | scanning | done | error
    history: [],           // فحوصات الجلسة دي بس (في الذاكرة)
  };
  try { if (localStorage.getItem("lc-lang") === "en") state.lang = "en"; } catch (_) { /* ignore */ }

  /* ------------------------------------------------------------------ i18n */
  const ATTR = {
    brand: ["فاحص اللينكات", "Link Checker"], nav: ["التنقل الرئيسي", "Main navigation"],
    lang: ["اللغة", "Language"], menu: ["القائمة", "Menu"], seg: ["نوع الفحص", "Scan type"],
    gauge: ["نسبة الخطر", "Risk level"], types: ["الأنواع المدعومة", "Supported file types"],
  };
  const PH = { ph: ["أدخل الرابط الذي تريد فحصه...", "Enter the link you want to scan..."] };

  const SIGNALS = {
    no_host: ["الرابط لا يحتوي على دومين صالح", "The link has no valid domain"],
    shortener: ["رابط مختصر يخفي الوجهة الحقيقية", "Shortened link that hides the real destination"],
    at_sign: ["علامة @ داخل الرابط تخفي الدومين الحقيقي", "An @ sign in the link hides the real domain"],
    no_https: ["بدون HTTPS", "No HTTPS"],
    ip_host: ["الرابط يستخدم عنوان IP بدلاً من اسم دومين", "The link uses an IP address instead of a domain name"],
    punycode: ["دومين بحروف مموّهة (Punycode/Unicode)", "Domain with disguised characters (Punycode/Unicode)"],
    long_url: ["رابط طويل بشكل مريب", "Suspiciously long link"],
    many_subdomains: ["عدد كبير من الدومينات الفرعية", "Many subdomains"],
    suspicious_tld: ["امتداد دومين شائع في الاحتيال ({tld})", "Domain extension common in scams ({tld})"],
    many_digits: ["أرقام كثيرة في اسم الدومين", "Many digits in the domain name"],
    many_hyphens: ["شرطات كثيرة في الدومين", "Too many hyphens in the domain"],
    odd_port: ["منفذ غير معتاد ({port})", "Unusual port ({port})"],
    bad_port: ["منفذ غير صالح", "Invalid port"],
    redirect_param: ["رابط تحويل (redirect) داخل الرابط", "A redirect link inside the link"],
    exec_download: ["الرابط يحمّل ملفاً تنفيذياً", "The link downloads an executable file"],
    scam_keywords: ["كلمات شائعة في الاحتيال", "Common scam words", "words"],
    brand_in_domain: ["اسم «{brand}» ظاهر في الدومين، لكن الدومين الأساسي ليس الرسمي",
      "“{brand}” appears in the domain, but the base domain isn't the official one", "domain"],
    brand_lookalike: ["الدومين يقلّد اسم «{brand}» بأرقام أو حروف مشابهة",
      "The domain imitates “{brand}” with look-alike digits or letters"],
    brand_typosquat: ["الدومين قريب جداً من «{brand}» بحرف زائد أو ناقص (Typosquatting)",
      "The domain is very close to “{brand}” with an extra or missing letter (typosquatting)"],
    brand_in_path: ["اسم «{brand}» موجود في المسار لكن الدومين ليس الرسمي",
      "“{brand}” appears in the path but the domain isn't official"],
    db_exact: ["الرابط مسجَّل في قاعدة التهديدات ({source})", "The link is listed in the threat database ({source})"],
    db_domain: ["ظهر هذا الدومين في {count} رابط خبيث (المصدر: {sources})",
      "This domain appeared in {count} malicious links (source: {sources})"],
    invalid_url: ["شكل الرابط غير صالح", "The link format is invalid"],
    // ملفات
    known_hash: ["الهاش معروف في قاعدة الملفات الخبيثة/الاختبار: {name}", "The hash is known in the malicious/test file database: {name}"],
    executable: ["الملف تنفيذي (Executable)", "The file is an executable"],
    ext_hides_exe: ["الامتداد {ext} يخفي أن الملف تنفيذي", "The {ext} extension hides that this is an executable"],
    ext_mismatch: ["الامتداد {ext} لا يطابق نوع المحتوى الحقيقي ({kind})", "The {ext} extension doesn't match the real content type ({kind})"],
    ext_content_mismatch: ["الامتداد {ext} لكن المحتوى ليس بالشكل المتوقع لهذا النوع", "The extension is {ext} but the content isn't what that type should look like"],
    double_ext: ["امتداد مزدوج مخادع (مثل invoice.pdf.exe)", "Deceptive double extension (like invoice.pdf.exe)"],
    dangerous_ext: ["امتداد خطير ({ext})", "Dangerous extension ({ext})"],
    macro_file: ["ملف أوفيس يحتوي على ماكرو (Macro)", "Office file containing a macro"],
    archive: ["ملف مضغوط (محتواه لا يُفحص هنا)", "Archive file (its contents are not scanned here)"],
    trailing_data: ["بيانات زائدة بعد نهاية الصورة (قد تكون مخفية)", "Extra data after the end of the image (may be hidden)"],
    script_in_image: ["كود مشبوه داخل الصورة", "Suspicious code inside the image", "hits"],
    pdf_active: ["ملف PDF يحتوي على JavaScript أو ملفات مضمَّنة", "PDF contains JavaScript or embedded files"],
  };
  const SIGNAL_ICON = {
    no_host: "link", shortener: "link", at_sign: "user", no_https: "lock", ip_host: "globe", punycode: "globe",
    long_url: "lines", many_subdomains: "lines", suspicious_tld: "globe", many_digits: "lines", many_hyphens: "lines",
    odd_port: "globe", bad_port: "globe", redirect_param: "link", exec_download: "file", scam_keywords: "key",
    brand_in_domain: "user", brand_lookalike: "user", brand_typosquat: "user", brand_in_path: "user",
    db_exact: "db", db_domain: "db", invalid_url: "link", known_hash: "hash", executable: "file",
    ext_hides_exe: "file", ext_mismatch: "file", ext_content_mismatch: "file", double_ext: "file",
    dangerous_ext: "warn", macro_file: "code", archive: "file", trailing_data: "image", script_in_image: "code",
    pdf_active: "code",
  };
  const ERRORS = {
    empty_url: ["أدخل رابطاً أولاً.", "Enter a link first."],
    url_too_long: ["الرابط طويل جداً.", "That link is too long."],
    empty_file: ["الملف فارغ.", "The file is empty."],
    no_file: ["اختر ملفاً أولاً.", "Choose a file first."],
    too_large: ["حجم الملف أكبر من الحد المسموح ({max} MB).", "The file is larger than the allowed {max} MB."],
    network: ["تعذّر الاتصال بالخادم، حاول مرة أخرى.", "Couldn't reach the server, please try again."],
    generic: ["حدث خطأ غير متوقع.", "Something went wrong."],
  };
  const TYPE_LABEL = {
    pdf: ["مستند PDF", "PDF document"], doc: ["مستند Word", "Word document"], docx: ["مستند Word", "Word document"],
    xls: ["جدول Excel", "Excel sheet"], xlsx: ["جدول Excel", "Excel sheet"], ppt: ["عرض تقديمي", "Presentation"],
    pptx: ["عرض تقديمي", "Presentation"], zip: ["ملف مضغوط", "Archive"], rar: ["ملف مضغوط", "Archive"],
    "7z": ["ملف مضغوط", "Archive"], gz: ["ملف مضغوط", "Archive"], exe: ["ملف تنفيذي", "Executable"],
    msi: ["حزمة تثبيت", "Installer package"], apk: ["تطبيق أندرويد", "Android app"], txt: ["ملف نصي", "Text file"],
    png: ["صورة", "Image"], jpg: ["صورة", "Image"], jpeg: ["صورة", "Image"], gif: ["صورة", "Image"],
    webp: ["صورة", "Image"], bmp: ["صورة", "Image"],
  };
  const L = {
    risk: ["نسبة الخطر", "Risk"], indicators: ["المؤشرات المرصودة", "Detected indicators"],
    total: ["مجموع النقاط", "Total points"], none: ["لم تُرصد أي مؤشرات خطر", "No risk indicators were found"],
    scanning: ["جارٍ الفحص", "Scanning"], waiting: ["في الانتظار", "Waiting"], ready: ["جاهز للفحص", "Ready to scan"],
    failed: ["تعذّر الفحص", "Scan failed"], safe: ["آمن", "Safe"], low: ["منخفض الخطورة", "Low risk"],
    danger: ["خطير", "Dangerous"], suspicious: ["مشبوه", "Suspicious"], preview: ["معاينة الملف المرفوع", "Uploaded file preview"],
    noFile: ["لم يتم اختيار ملف بعد", "No file selected yet"], pickFile: ["اختر ملفاً أو صورة للفحص...", "Choose a file or image to scan..."],
    fname: ["اسم الملف", "File name"], size: ["الحجم", "Size"], type: ["النوع", "Type"], file: ["ملف", "File"],
    status: ["حالة الفحص", "Scan status"], unknown: ["غير معروف", "Unknown"], sha: ["SHA-256", "SHA-256"],
    lowOnly: ["توجد علامات بسيطة فقط، ولا يوجد دليل قوي على خطورته.", "Only minor signs; no strong evidence that it is dangerous."],
    lowNone: ["لا توجد مؤشرات خطر واضحة، لكن هذا لا يضمن أنه آمن 100%.", "No clear risk indicators, but this doesn't guarantee it's 100% safe."],
  };
  const t = (pair) => pair[state.lang === "en" ? 1 : 0];

  /* ------------------------------------------------------------------ dom helpers */
  const NS = "http://www.w3.org/2000/svg";
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === false || v == null) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else el.setAttribute(k, v === true ? "" : v);
    }
    append(el, kids);
    return el;
  }
  function append(el, kids) {
    for (const k of kids.flat(Infinity)) {
      if (k == null || k === false) continue;
      el.append(typeof k === "string" ? document.createTextNode(k) : k);
    }
  }
  /** "نص {param} نص" -> fragment؛ القيم بتتحط جوه span.en (اتجاه LTR معزول) */
  function rich(template, params = {}) {
    const frag = document.createDocumentFragment();
    template.split(/(\{\w+\})/).forEach((part) => {
      const m = part.match(/^\{(\w+)\}$/);
      if (m && m[1] in params) frag.append(h("span", { class: "en", text: String(params[m[1]]) }));
      else if (part) frag.append(document.createTextNode(part));
    });
    return frag;
  }
  const ICONS = {
    lock: '<rect x="5" y="11" width="14" height="9" rx="2"></rect><path d="M8 11V8a4 4 0 0 1 7.5-2"></path>',
    globe: '<circle cx="12" cy="12" r="9"></circle><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"></path>',
    lines: '<path d="M4 7h16M4 12h10M4 17h16"></path>',
    key: '<circle cx="8" cy="15" r="3.5"></circle><path d="M10.5 12.5L19 4M16 7l2 2M13.5 9.5l2 2"></path>',
    user: '<circle cx="12" cy="8" r="4"></circle><path d="M4 20c0-4 3.5-6 8-6s8 2 8 6"></path>',
    link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"></path><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"></path>',
    file: '<path d="M7 3h7l5 5v13H7z"></path><path d="M14 3v5h5"></path>',
    fileLines: '<path d="M7 3h7l5 5v13H7z"></path><path d="M14 3v5h5M10 13h6M10 17h6"></path>',
    warn: '<path d="M12 4l9 16H3L12 4z"></path><path d="M12 10v4M12 17.5v.01"></path>',
    db: '<ellipse cx="12" cy="6" rx="7" ry="3"></ellipse><path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"></path>',
    hash: '<path d="M5 9h14M5 15h14M10 4L8 20M16 4l-2 16"></path>',
    code: '<path d="M8 8l-4 4 4 4M16 8l4 4-4 4M14 5l-4 14"></path>',
    image: '<rect x="3" y="4" width="18" height="16" rx="3"></rect><circle cx="9" cy="10" r="2"></circle><path d="M21 16l-5-5-8 8"></path>',
    check: '<path d="M5 12.5l4.5 4.5L19 7.5"></path>',
    shieldOk: '<path d="M12 3l7 3v5c0 5-3 8.5-7 10-4-1.5-7-5-7-10V6l7-3z"></path><path d="M8.5 12.5l2.5 2.5 4.5-5"></path>',
    shieldWarn: '<path d="M12 3l7 3v5c0 5-3 8.5-7 10-4-1.5-7-5-7-10V6l7-3z"></path><path d="M12 8.5v4M12 15.5v.01"></path>',
    shieldX: '<path d="M12 3l7 3v5c0 5-3 8.5-7 10-4-1.5-7-5-7-10V6l7-3z"></path><path d="M9.5 9.5l5 5M14.5 9.5l-5 5"></path>',
  };
  function icon(name, size = "") {
    const svg = document.createElementNS(NS, "svg");
    svg.setAttribute("class", "ic" + (size ? " ic-" + size : ""));
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    svg.innerHTML = ICONS[name] || ICONS.warn; // ثوابت مكتوبة هنا بس، مش بيانات خارجية
    return svg;
  }
  const bi = (ar, en) => [h("span", { class: "t-ar", text: ar }), h("span", { class: "t-en", text: en })];
  const spinner = () => h("span", { class: "spinner" });

  /* ------------------------------------------------------------------ formatting / verdicts */
  function fmtSize(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`;
    return `${(n / 1024 / 1024).toFixed(1)} MB`;
  }
  const extOf = (name) => (name.includes(".") ? name.split(".").pop().toLowerCase() : "");
  const badgeOf = (name) => (extOf(name) || "FILE").slice(0, 4).toUpperCase();
  const typeOf = (name) => t(TYPE_LABEL[extOf(name)] || L.file);

  function verdictKey(data) {
    if (data.verdict === "خطير") return "danger";
    if (data.verdict === "مشبوه") return "suspicious";
    if (data.verdict === "منخفض الخطورة") return "low";
    return data.score >= 70 ? "danger" : data.score >= 35 ? "suspicious" : "low";
  }
  const isRed = (k) => k !== "low";
  const pillLabel = (k, data) => (k === "low" ? (data.signals && data.signals.length ? L.low : L.safe) : L[k]);
  const pillIcon = (k) => (k === "danger" ? "shieldX" : k === "suspicious" ? "shieldWarn" : "shieldOk");

  const arCount = (n, one, two, few, many) =>
    n === 1 ? one : n === 2 ? two : n <= 10 ? `${n} ${few}` : `${n} ${many}`;

  function summary(k, n, subject) {
    const file = subject === "file";
    if (state.lang === "ar") {
      if (k === "danger") {
        const c = arCount(n, "مؤشر خطر واحد", "مؤشرا خطر", "مؤشرات خطر", "مؤشر خطر");
        return `${n >= 3 && n <= 10 ? "اكتُشفت" : "اكتُشف"} ${c}، ${file ? "لا تقم بتشغيل هذا الملف" : "لا تفتح هذا الرابط"}.`;
      }
      if (k === "suspicious") {
        const c = arCount(n, "مؤشر مشبوه واحد", "مؤشران مشبوهان", "مؤشرات مشبوهة", "مؤشراً مشبوهاً");
        return `يوجد ${c}، تعامل معه بحذر.`;
      }
      return n ? t(L.lowOnly) : t(L.lowNone);
    }
    if (k === "danger") return `${n} risk indicator${n === 1 ? " was" : "s were"} detected. ${file ? "Do not run this file." : "Do not open this link."}`;
    if (k === "suspicious") return `${n} suspicious indicator${n === 1 ? "" : "s"} found. Handle it with care.`;
    return n ? t(L.lowOnly) : t(L.lowNone);
  }

  /* ------------------------------------------------------------------ result pieces */
  function signalRow(sig, red) {
    const entry = SIGNALS[sig.code];
    const params = sig.params || {};
    const text = h("span", { class: "txt" });
    if (entry) {
      text.append(rich(t(entry), params));
      if (entry[2] && params[entry[2]]) text.append(h("small", { class: "en", text: params[entry[2]] }));
    } else {
      text.append(document.createTextNode(sig.label || sig.code || ""));
    }
    return h("li", {},
      h("span", { class: "ico" }, icon(SIGNAL_ICON[sig.code] || "warn")),
      text,
      h("span", { class: "pts", text: `+${sig.points}` }));
  }

  function indicators(data) {
    const sigs = data.signals || [];
    const red = isRed(verdictKey(data));
    const list = h("ul", { class: "ind-list" });
    if (sigs.length) sigs.forEach((s) => list.append(signalRow(s, red)));
    else list.append(h("li", {},
      h("span", { class: "ico ok" }, icon("check")),
      h("span", { class: "txt" }, ...bi(L.none[0], L.none[1]))));
    return [
      h("div", { class: "ind-title" },
        h("span", {}, ...bi(L.indicators[0], L.indicators[1])),
        h("span", { class: `pill ${red ? "red" : "green"} en`, text: String(sigs.length) })),
      list,
      h("div", { class: "total" },
        h("span", {}, ...bi(L.total[0], L.total[1])),
        h("b", { text: `${data.score} / 100` })),
    ];
  }

  function fileMeta(f) {
    const kind = f.kind ? f.kind.toUpperCase() : t(L.unknown);
    return [
      h("div", { class: "meta" },
        h("div", {}, h("small", {}, ...bi(L.fname[0], L.fname[1])), h("b", { class: "mono", text: f.name })),
        h("div", {}, h("small", {}, ...bi(L.size[0], L.size[1])), h("b", { class: "mono", text: fmtSize(f.size) })),
        h("div", {}, h("small", {}, ...bi(L.type[0], L.type[1])), h("b", { class: "mono", text: kind }))),
      h("div", { class: "hash mono" }, h("small", { text: "SHA-256" }), f.sha256),
    ];
  }

  function ring(score, red) {
    const C = 477.5;
    const arc = document.createElementNS(NS, "circle");
    for (const [k, v] of Object.entries({ class: "arc", cx: 88, cy: 88, r: 76, fill: "none", "stroke-width": 12,
      "stroke-linecap": "round", "stroke-dasharray": `${C} ${C}`, "stroke-dashoffset": C })) arc.setAttribute(k, v);
    const track = document.createElementNS(NS, "circle");
    for (const [k, v] of Object.entries({ class: "track", cx: 88, cy: 88, r: 76, fill: "none", "stroke-width": 12 })) track.setAttribute(k, v);
    const svg = document.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", "0 0 176 176");
    svg.setAttribute("aria-hidden", "true");
    svg.append(track, arc);
    requestAnimationFrame(() => requestAnimationFrame(() => arc.setAttribute("stroke-dashoffset", String(C * (1 - score / 100)))));
    return h("div", { class: "ring", role: "img", "aria-label": `${t(ATTR.gauge)} ${score}%` }, svg,
      h("div", { class: "n" }, h("b", { text: `${score}%` }), h("span", {}, ...bi(L.risk[0], L.risk[1]))));
  }

  function meter(score) {
    const i = h("i");
    i.style.width = "0%";
    requestAnimationFrame(() => requestAnimationFrame(() => { i.style.width = `${score}%`; }));
    return h("div", { class: "meter", "aria-hidden": "true" }, i);
  }

  function titleNode(k, score) {
    const v = (cls) => h("span", { class: cls, text: `${score}%` });
    return state.lang === "ar"
      ? h("h3", { class: "rc-title" }, `${t(L[k])} — نسبة الخطر `, v("v en"))
      : h("h3", { class: "rc-title" }, `${t(L[k])} — risk `, v("v"));
  }

  /** البطاقة الكبيرة (نتيجة رابط أو ملف مفحوص من أعلى الصفحة) */
  function resultCard(live) {
    const { data, kind, input } = live;
    const k = verdictKey(data);
    const red = isRed(k);
    const n = (data.signals || []).length;
    const subject = kind === "file" ? "file" : "url";
    const left = h("div", { class: "rc-score" },
      ring(data.score, red), titleNode(k, data.score), meter(data.score),
      h("p", { class: "rc-sum", text: summary(k, n, subject) }));
    const right = h("div", {}, ...indicators(data), kind === "file" && data.file ? fileMeta(data.file) : null);
    return h("article", { class: `rc ${red ? "red" : "green"} wide`, "aria-label": t(L[k]) },
      h("header", { class: "rc-head" },
        h("span", { class: `pill ${red ? "red" : "green"}` }, icon(pillIcon(k), "sm"), t(pillLabel(k, data))),
        h("span", { class: "url mono", text: kind === "file" && data.file ? data.file.name : input })),
      h("div", { class: "rc-grid" }, left, right));
  }

  function errorCard(code, params, fallback) {
    const entry = ERRORS[code] || ERRORS.generic;
    return h("article", { class: "rc red wide", role: "alert" },
      h("header", { class: "rc-head" }, h("span", { class: "pill red" }, icon("shieldWarn", "sm"), t(L.failed))),
      h("p", { class: "rc-sum" }, rich(t(entry), params || {}), (!ERRORS[code] && fallback) ? " " + fallback : ""));
  }

  function loadingCard(label) {
    return h("article", { class: "rc wide", "aria-busy": "true" },
      h("header", { class: "rc-head" },
        h("span", { class: "pill neutral" }, spinner(), t(L.scanning)),
        h("span", { class: "url mono", text: label })),
      h("div", { class: "meter" }, h("i", { class: "scan s-full" })));
  }

  /* ------------------------------------------------------------------ renderers */
  function renderLive() {
    const sec = $("#live-result");
    const box = $("#live-box");
    const live = state.live;
    if (!live) { sec.hidden = true; return; }
    sec.hidden = false;
    if (live.loading) box.replaceChildren(loadingCard(live.label));
    else if (live.error) box.replaceChildren(errorCard(live.error.code, live.error.params, live.error.message));
    else box.replaceChildren(resultCard(live));
  }

  function fileHead(pillNode) {
    return h("div", { class: "pv-head" }, h("h3", {}, ...bi(L.preview[0], L.preview[1])), pillNode);
  }
  function fileRow(file) {
    return h("div", { class: "file-row" },
      h("div", { class: "thumb" }, icon("fileLines", "xl"), h("em", { text: badgeOf(file.name) })),
      h("div", {}, h("b", { class: "fname mono", text: file.name }),
        h("span", { class: "fsub" }, `${typeOf(file.name)} · `, h("span", { class: "en", text: fmtSize(file.size) }))));
  }
  function basicMeta(file) {
    return h("div", { class: "meta" },
      h("div", {}, h("small", {}, ...bi(L.fname[0], L.fname[1])), h("b", { class: "mono", text: file.name })),
      h("div", {}, h("small", {}, ...bi(L.size[0], L.size[1])), h("b", { class: "mono", text: fmtSize(file.size) })),
      h("div", {}, h("small", {}, ...bi(L.type[0], L.type[1])), h("b", { text: typeOf(file.name) })));
  }

  function renderPreview() {
    const p = state.preview;
    const panel = $("#file-preview");
    let nodes;
    if (p.phase === "empty") {
      nodes = [fileHead(h("span", { class: "pill neutral", text: t(L.waiting) })),
        h("div", { class: "pv-empty" }, h("div", { class: "thumb" }, icon("fileLines", "xl")), h("span", { text: t(L.noFile) }))];
    } else if (p.phase === "ready" || p.phase === "scanning") {
      const scanning = p.phase === "scanning";
      nodes = [
        fileHead(h("span", { class: "pill neutral" }, scanning ? spinner() : null, t(scanning ? L.scanning : L.ready))),
        fileRow(state.file), basicMeta(state.file),
        scanning ? [h("div", { class: "stat-line" }, h("span", {}, ...bi(L.status[0], L.status[1]))),
          h("div", { class: "meter" }, h("i", { class: "scan s-full" }))] : null,
      ];
    } else if (p.phase === "error") {
      nodes = [fileHead(h("span", { class: "pill red" }, icon("shieldWarn", "sm"), t(L.failed))),
        state.file ? fileRow(state.file) : null,
        h("p", { class: "rc-sum", role: "alert" }, rich(t(ERRORS[p.error.code] || ERRORS.generic), p.error.params || {}))];
    } else { // done
      const data = p.data, k = verdictKey(data), red = isRed(k), n = (data.signals || []).length;
      nodes = [
        fileHead(h("span", { class: `pill ${red ? "red" : "green"}` }, icon(pillIcon(k), "sm"), t(pillLabel(k, data)))),
        fileRow(state.file),
        h("div", { class: `pv-body ${red ? "red" : "green"}` },
          h("div", { class: "stat-line" }, h("span", {}, ...bi(L.risk[0], L.risk[1])), h("b", { text: `${data.score}%` })),
          meter(data.score),
          h("p", { class: "rc-sum", text: summary(k, n, "file") }),
          ...indicators(data),
          data.file ? h("div", { class: "hash mono" }, h("small", { text: "SHA-256" }), data.file.sha256) : null),
      ];
    }
    panel.replaceChildren(...nodes.flat(Infinity).filter(Boolean));
  }

  function renderHistory() {
    const wrap = $("#history-wrap");
    wrap.hidden = state.history.length === 0;
    $("#history").replaceChildren(...state.history.map((e) => {
      const red = isRed(e.k);
      return h("div", { class: `fres ${red ? "red" : "green"}` },
        h("div", { class: "fres-top" }, h("div", { class: "fres-ico" }, icon(pillIcon(e.k), "lg")),
          h("span", { class: `pill ${red ? "red" : "green"}`, text: t(pillLabel(e.k, e.data)) })),
        h("h4", { class: "mono", text: e.name }),
        h("div", { class: "sub mono", text: `${badgeOf(e.name)} · ${fmtSize(e.size)}` }),
        h("p", { text: summary(e.k, (e.data.signals || []).length, "file") }),
        meter(e.data.score),
        h("div", { class: "tiny" }, h("span", {}, ...bi(L.risk[0], L.risk[1])), h("b", { class: "en", text: `${e.data.score}%` })));
    }));
  }

  function renderHeroPick() {
    const pick = $("#hero-pick");
    const f = $("#hero-file").files[0];
    pick.classList.toggle("has", !!f);
    pick.replaceChildren(...(f ? [document.createTextNode(`${f.name} (${fmtSize(f.size)})`)] : bi(L.pickFile[0], L.pickFile[1])));
  }

  function applyLang() {
    const en = state.lang === "en";
    app.classList.toggle("lang-en", en);
    app.classList.toggle("lang-ar", !en);
    app.dir = en ? "ltr" : "rtl";
    app.lang = en ? "en" : "ar";
    document.documentElement.lang = app.lang;
    document.documentElement.dir = app.dir;
    document.title = en ? "Link Checker" : "فاحص اللينكات";
    $("#lang-ar").classList.toggle("on", !en);
    $("#lang-en").classList.toggle("on", en);
    document.querySelectorAll("[data-aria]").forEach((el) => { el.setAttribute("aria-label", t(ATTR[el.dataset.aria])); });
    document.querySelectorAll("[data-ph]").forEach((el) => { el.setAttribute("placeholder", t(PH[el.dataset.ph])); });
    renderHeroPick(); renderLive(); renderPreview(); renderHistory();
  }

  /* ------------------------------------------------------------------ scanning */
  async function postJson(url, options) {
    try {
      const res = await fetch(url, options);
      const data = await res.json();
      return { ok: res.ok, data };
    } catch (_) {
      return { ok: false, data: { code: "network", error: "network" } };
    }
  }
  const errInfo = (data) => ({ code: data.code || "generic", params: { max: data.max_mb || data.max }, message: data.code ? "" : data.error });

  function setBusy(busy) {
    state.busy = busy;
    ["btn-link", "btn-hero-file", "btn-file"].forEach((id) => {
      const b = document.getElementById(id);
      if (b) b.disabled = busy;
    });
  }
  function showLive(scroll = true) {
    renderLive();
    if (scroll) $("#live-result").scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "start" });
  }

  async function scanLink(raw) {
    const url = raw.trim();
    if (!url) { state.live = { error: { code: "empty_url" } }; showLive(false); $("#url-input").focus(); return; }
    if (state.busy) return;
    setBusy(true);
    state.live = { loading: true, label: url };
    showLive();
    const { ok, data } = await postJson("/check", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    state.live = ok ? { kind: "url", input: url, data } : { error: errInfo(data) };
    setBusy(false);
    showLive();
  }

  async function uploadFile(file) {
    const max = state.maxMb * 1024 * 1024;
    if (file.size > max) return { ok: false, data: { code: "too_large", max_mb: state.maxMb } };
    const form = new FormData();
    form.append("file", file);
    return postJson("/scan-file", { method: "POST", body: form });
  }
  function remember(file, data) {
    state.history.unshift({ name: file.name, size: file.size, data, k: verdictKey(data) });
    state.history = state.history.slice(0, 6);
    renderHistory();
  }

  async function scanFromHero() {
    const file = $("#hero-file").files[0];
    if (!file) { state.live = { error: { code: "no_file" } }; showLive(false); return; }
    if (state.busy) return;
    setBusy(true);
    state.live = { loading: true, label: file.name };
    showLive();
    const { ok, data } = await uploadFile(file);
    if (ok) { state.live = { kind: "file", input: file.name, data }; remember(file, data); }
    else state.live = { error: errInfo(data) };
    setBusy(false);
    showLive();
  }

  async function scanFromSection() {
    if (!state.file) { state.preview = { phase: "error", error: { code: "no_file" } }; renderPreview(); return; }
    if (state.busy) return;
    setBusy(true);
    state.preview = { phase: "scanning" };
    renderPreview();
    const { ok, data } = await uploadFile(state.file);
    if (ok) { state.preview = { phase: "done", data }; remember(state.file, data); }
    else state.preview = { phase: "error", error: errInfo(data) };
    setBusy(false);
    renderPreview();
  }

  function chooseFile(file) {
    state.file = file || null;
    state.preview = file ? { phase: "ready" } : { phase: "empty" };
    renderPreview();
  }

  /* ------------------------------------------------------------------ wiring */
  function setTab(which) {
    const link = which === "link";
    $("#tab-link").classList.toggle("on", link);
    $("#tab-file").classList.toggle("on", !link);
    $("#tab-link").setAttribute("aria-selected", String(link));
    $("#tab-file").setAttribute("aria-selected", String(!link));
    $("#panel-link").hidden = !link;
    $("#panel-file").hidden = link;
    $("#try-row").hidden = !link;
  }
  $("#tab-link").addEventListener("click", () => setTab("link"));
  $("#tab-file").addEventListener("click", () => setTab("file"));

  $("#panel-link").addEventListener("submit", (e) => { e.preventDefault(); scanLink($("#url-input").value); });
  $("#panel-file").addEventListener("submit", (e) => { e.preventDefault(); scanFromHero(); });
  $("#hero-file").addEventListener("change", renderHeroPick);
  $("#try-row").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-url]");
    if (!b) return;
    $("#url-input").value = b.dataset.url;
    scanLink(b.dataset.url);
  });

  const zone = $("#drop-zone");
  const fileInput = $("#file-input");
  const openPicker = () => fileInput.click();
  zone.addEventListener("click", openPicker);
  zone.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openPicker(); } });
  $("#btn-choose").addEventListener("click", openPicker);
  fileInput.addEventListener("change", () => { chooseFile(fileInput.files[0]); });
  ["dragenter", "dragover"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove("over"); }));
  zone.addEventListener("drop", (e) => { const f = e.dataTransfer && e.dataTransfer.files[0]; if (f) chooseFile(f); });
  $("#btn-file").addEventListener("click", scanFromSection);

  $("#lang-ar").addEventListener("click", () => setLang("ar"));
  $("#lang-en").addEventListener("click", () => setLang("en"));
  function setLang(l) {
    state.lang = l;
    try { localStorage.setItem("lc-lang", l); } catch (_) { /* ignore */ }
    applyLang();
  }

  /* قائمة الموبايل */
  const nav = $(".nav");
  const menuBtn = $("#menu-btn");
  const setMenu = (open) => { nav.classList.toggle("open", open); menuBtn.setAttribute("aria-expanded", String(open)); };
  menuBtn.addEventListener("click", () => setMenu(!nav.classList.contains("open")));
  $("#main-nav").addEventListener("click", (e) => { if (e.target.closest("a")) setMenu(false); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") setMenu(false); });

  /* تمييز الرابط الحالي في القائمة */
  const spyIds = ["file-scanner", "tips", "about"];
  const navLinks = [...document.querySelectorAll(".links a")];
  function spy() {
    let current = "home";
    for (const id of spyIds) {
      const el = document.getElementById(id);
      if (el && el.getBoundingClientRect().top <= 140) current = id;
    }
    navLinks.forEach((a) => a.classList.toggle("on", a.getAttribute("href") === "#" + current));
  }
  window.addEventListener("scroll", spy, { passive: true });

  /* إعدادات السيرفر */
  fetch("/api/info").then((r) => r.json()).then((info) => {
    state.maxMb = info.max_upload_mb || state.maxMb;
    document.querySelectorAll(".max-mb").forEach((el) => { el.textContent = String(state.maxMb); });
  }).catch(() => { /* الصفحة شغالة بالقيم الافتراضية */ });

  applyLang();
  spy();
})();
