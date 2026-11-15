const $ = (id) => document.getElementById(id);

function el(tag, text) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text; // textContent بدل innerHTML لمنع XSS
  return node;
}

function showResult(data) {
  const box = $("result");
  box.style.display = "block";
  box.replaceChildren();
  if (data.error) {
    box.className = "";
    box.textContent = data.error;
    return;
  }
  box.className = data.verdict.replace(/ /g, "_");

  box.append(el("strong", `${data.verdict} - نسبة الخطر ${data.score}%`));
  const bar = el("progress");
  bar.max = 100;
  bar.value = data.score;
  bar.style.width = "100%";
  box.append(bar, el("p", data.reason));

  if (data.signals && data.signals.length) {
    const ul = el("ul");
    data.signals.forEach((s) => ul.append(el("li", `${s.label} (+${s.points})`)));
    box.append(ul);
  }
  if (data.file) {
    box.append(el("p", `${data.file.name} | ${data.file.size} بايت | SHA-256: ${data.file.sha256}`));
  }
  if (data.virustotal) {
    const vt = data.virustotal;
    box.append(el("p", vt.error
      ? `VirusTotal: ${vt.error}`
      : `VirusTotal: ${vt.malicious} خبيث، ${vt.suspicious} مشبوه، ${vt.harmless} سليم`));
  }
}

async function send(url, options) {
  try {
    const res = await fetch(url, options);
    showResult(await res.json());
  } catch (e) {
    showResult({ error: "حصلت مشكلة في الاتصال بالسيرفر" });
  }
}

$("check-btn").addEventListener("click", () => {
  const url = $("url").value.trim();
  if (!url) return;
  send("/check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: url, use_vt: $("use-vt").checked }),
  });
});

$("file-btn").addEventListener("click", () => {
  const file = $("file").files[0];
  if (!file) return showResult({ error: "اختار ملف الأول" });
  const form = new FormData();
  form.append("file", file);
  form.append("use_vt", $("use-vt").checked);
  send("/scan-file", { method: "POST", body: form });
});
