const COOKIE_NAME = "admin_session";
const SESSION_HOURS = 12;
const ALLOWED_PARTS = ["1", "3", "5", "7.5", "10", "15", "20", "25", "30"];

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method;

      if (!env.DB) return json({ error: "قاعدة البيانات غير متصلة" }, 500);
      if (!env.ADMIN_PASSWORD) return json({ error: "إعداد كلمة مرور الإدارة غير موجود" }, 500);

      await ensureSettings(env.DB);

      if (path === "/api/login" && method === "POST") return login(request, env);

      if (path === "/api/logout" && method === "POST") {
        return json({ success: true }, 200, {
          "Set-Cookie": `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`
        });
      }

      if (path.startsWith("/api/admin/")) {
        if (!(await checkSession(request, env))) {
          return json({ error: "غير مصرح لك بالدخول" }, 401);
        }

        if (path === "/api/admin/registrations" && method === "GET") {
          const rows = await env.DB.prepare(
            "SELECT * FROM registrations ORDER BY id DESC"
          ).all();
          return json({ success: true, registrations: rows.results || [] });
        }

        if (path === "/api/admin/update" && method === "POST") {
          return updateRegistration(request, env);
        }

        if (path === "/api/admin/settings" && method === "GET") {
          return json({ success: true, settings: await getSettings(env.DB) });
        }

        if (path === "/api/admin/settings" && method === "POST") {
          return updateSettings(request, env);
        }
      }

      if (path === "/api/register" && method === "POST") return register(request, env);
      if (path === "/api/inquiry" && method === "POST") return inquiry(request, env);

      if (path === "/api/status" && method === "GET") {
        const settings = await getSettings(env.DB);
        return json({
          registration_open: Number(settings.registration_open) === 1,
          registration_start: settings.registration_start,
          registration_end: settings.registration_end,
          inquiry_start: settings.inquiry_start,
          wallet_number: settings.wallet_number
        });
      }

      if (path === "/" || path === "") return html(mainPage());
      return json({ error: "الصفحة غير موجودة" }, 404);
    } catch (error) {
      console.error("Worker error:", error);
      return json({ error: "حدث خطأ غير متوقع، حاول مرة أخرى" }, 500);
    }
  }
};

/* الأدوات العامة */
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    }
  });
}

function html(content) {
  return new Response(content, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "X-Frame-Options": "DENY"
    }
  });
}

function clean(value, max = 200) {
  return String(value ?? "").trim().slice(0, max);
}

function validPhone(value) {
  return /^01[0125][0-9]{8}$/.test(value);
}

function validNationalId(value) {
  return /^[0-9]{14}$/.test(value);
}

function currentEgyptDate() {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Africa/Cairo",
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).formatToParts(new Date());
  const get = type => parts.find(p => p.type === type)?.value;
  return `${get("year")}-${get("month")}-${get("day")}`;
}

function randomCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

async function ensureSettings(db) {
  await db.prepare(`
    INSERT OR IGNORE INTO site_settings
    (id, registration_open, wallet_number, registration_start, registration_end, inquiry_start)
    VALUES (1, 1, '01040367801', '2026-12-01', '2026-12-31', '2027-01-09')
  `).run();
}

async function getSettings(db) {
  return db.prepare("SELECT * FROM site_settings WHERE id = 1").first();
}

/* حماية لوحة الإدارة */
async function hmac(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC", key, new TextEncoder().encode(value)
  );
  return btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function createSession(secret) {
  const expires = String(Date.now() + SESSION_HOURS * 60 * 60 * 1000);
  return `${expires}.${await hmac(expires, secret)}`;
}

async function checkSession(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)admin_session=([^;]+)/);
  if (!match) return false;

  const parts = match[1].split(".");
  if (parts.length !== 2) return false;

  const [expires, signature] = parts;
  if (!/^[0-9]+$/.test(expires) || Number(expires) < Date.now()) return false;

  const expected = await hmac(expires, env.ADMIN_PASSWORD);
  return signature === expected;
}

async function login(request, env) {
  let data;
  try { data = await request.json(); }
  catch { return json({ error: "بيانات الدخول غير صحيحة" }, 400); }

  if (String(data.password || "") !== env.ADMIN_PASSWORD) {
    return json({ error: "كلمة المرور غير صحيحة" }, 401);
  }

  const token = await createSession(env.ADMIN_PASSWORD);
  return json({ success: true }, 200, {
    "Set-Cookie": `${COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_HOURS * 3600}`
  });
}

/* تسجيل المتسابق */
async function register(request, env) {
  const settings = await getSettings(env.DB);
  const today = currentEgyptDate();

  if (Number(settings.registration_open) !== 1) {
    return json({ error: "التسجيل مغلق حاليًا" }, 403);
  }
  if (today < settings.registration_start || today > settings.registration_end) {
    return json({ error: "التسجيل غير متاح في هذا التاريخ" }, 403);
  }

  let data;
  try { data = await request.json(); }
  catch { return json({ error: "البيانات المرسلة غير صحيحة" }, 400); }

  const full_name = clean(data.full_name, 150);
  const birth_date = clean(data.birth_date, 10);
  const national_id = clean(data.national_id, 14);
  const phone = clean(data.phone, 11);
  const guardian_phone = clean(data.guardian_phone, 11);
  const area = clean(data.area, 100);
  const education_type = clean(data.education_type, 30);
  const school_year = clean(data.school_year, 100);
  const level = clean(data.level, 100);
  const teacher = clean(data.teacher, 150);
  const notes = clean(data.notes, 500);
  const transaction_number = clean(data.transaction_number, 100);
  const partsRaw = clean(data.parts_count, 5);
  const parts_count = partsRaw ? Number(partsRaw) : null;

  if (!full_name || !birth_date || !national_id || !phone || !area ||
      !education_type || !level || !transaction_number) {
    return json({ error: "من فضلك أكمل البيانات المطلوبة" }, 400);
  }
  if (!validNationalId(national_id)) {
    return json({ error: "الرقم القومي يجب أن يتكون من 14 رقمًا" }, 400);
  }
  if (!validPhone(phone)) return json({ error: "رقم الهاتف غير صحيح" }, 400);
  if (guardian_phone && !validPhone(guardian_phone)) {
    return json({ error: "رقم هاتف ولي الأمر غير صحيح" }, 400);
  }
  if (parts_count !== null && !ALLOWED_PARTS.includes(String(parts_count))) {
    return json({ error: "عدد الأجزاء المختار غير صحيح" }, 400);
  }
  if (!["عام", "أزهري", "غير ملتحق بالتعليم"].includes(education_type)) {
    return json({ error: "نوع التعليم المختار غير صحيح" }, 400);
  }

  const tracking_code = randomCode();

  try {
    await env.DB.prepare(`
      INSERT INTO registrations (
        full_name, birth_date, national_id, phone, guardian_phone, area,
        education_type, school_year, level, parts_count, teacher, notes,
        transaction_number, tracking_code, application_status, payment_status
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'قيد المراجعة', 'قيد المراجعة')
    `).bind(
      full_name, birth_date, national_id, phone, guardian_phone || null, area,
      education_type, school_year || null, level, parts_count, teacher || null,
      notes || null, transaction_number, tracking_code
    ).run();

    return json({
      success: true,
      message: "تم تسجيل طلبك بنجاح، والطلب قيد المراجعة",
      tracking_code
    });
  } catch (error) {
    const message = String(error?.message || error);
    if (message.includes("UNIQUE")) {
      return json({ error: "الرقم القومي أو رقم العملية مسجل من قبل" }, 409);
    }
    throw error;
  }
}

/* الاستعلام عن النتيجة */
async function inquiry(request, env) {
  const settings = await getSettings(env.DB);
  const today = currentEgyptDate();

  if (today < settings.inquiry_start) {
    return json({
      error: `الاستعلام عن النتيجة سيبدأ يوم ${settings.inquiry_start}`
    }, 403);
  }

  let data;
  try { data = await request.json(); }
  catch { return json({ error: "البيانات المرسلة غير صحيحة" }, 400); }

  const national_id = clean(data.national_id, 14);
  const phone = clean(data.phone, 11);
  if (!validNationalId(national_id) || !validPhone(phone)) {
    return json({ error: "تأكد من الرقم القومي ورقم الهاتف" }, 400);
  }

  const row = await env.DB.prepare(`
    SELECT full_name, level, application_status, payment_status
    FROM registrations WHERE national_id = ? AND phone = ?
  `).bind(national_id, phone).first();

  if (!row) return json({ error: "لا توجد بيانات مطابقة" }, 404);
  return json({ success: true, result: row });
}

/* إدارة الطلبات */
async function updateRegistration(request, env) {
  let data;
  try { data = await request.json(); }
  catch { return json({ error: "البيانات المرسلة غير صحيحة" }, 400); }

  const id = Number(data.id);
  const application_status = clean(data.application_status, 30);
  const payment_status = clean(data.payment_status, 30);
  const validApplication = ["قيد المراجعة", "مقبول", "مرفوض"];
  const validPayment = ["قيد المراجعة", "تم التأكيد", "مرفوض"];

  if (!Number.isInteger(id) || id < 1) return json({ error: "رقم الطلب غير صحيح" }, 400);
  if (!validApplication.includes(application_status)) return json({ error: "حالة القبول غير صحيحة" }, 400);
  if (!validPayment.includes(payment_status)) return json({ error: "حالة الدفع غير صحيحة" }, 400);

  const result = await env.DB.prepare(`
    UPDATE registrations SET application_status = ?, payment_status = ? WHERE id = ?
  `).bind(application_status, payment_status, id).run();

  if (!result.meta?.changes) return json({ error: "الطلب غير موجود" }, 404);
  return json({ success: true, message: "تم تحديث الطلب" });
}

/* إعدادات الموقع */
async function updateSettings(request, env) {
  let data;
  try { data = await request.json(); }
  catch { return json({ error: "البيانات المرسلة غير صحيحة" }, 400); }

  const registration_open = data.registration_open ? 1 : 0;
  const wallet_number = clean(data.wallet_number, 20);
  const registration_start = clean(data.registration_start, 10);
  const registration_end = clean(data.registration_end, 10);
  const inquiry_start = clean(data.inquiry_start, 10);
  const datePattern = /^\d{4}-\d{2}-\d{2}$/;

  if (!wallet_number || !datePattern.test(registration_start) ||
      !datePattern.test(registration_end) || !datePattern.test(inquiry_start) ||
      registration_start > registration_end) {
    return json({ error: "راجع رقم المحفظة والتواريخ" }, 400);
  }

  await env.DB.prepare(`
    UPDATE site_settings
    SET registration_open = ?, wallet_number = ?, registration_start = ?,
        registration_end = ?, inquiry_start = ?
    WHERE id = 1
  `).bind(
    registration_open, wallet_number, registration_start,
    registration_end, inquiry_start
  ).run();

  return json({ success: true, message: "تم حفظ الإعدادات" });
}

/* واجهة الموقع */
function mainPage() {
  return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>مسابقة أهل القرآن الكريم - السلاموني</title>
<style>
*{box-sizing:border-box}
body{margin:0;font-family:Tahoma,Arial,sans-serif;background:#f3f6f4;color:#18352b}
header{background:linear-gradient(135deg,#064e3b,#087f5b);color:white;text-align:center;padding:35px 15px;border-radius:0 0 28px 28px}
header h1{font-size:25px;margin:5px}
header p{margin:10px 0;color:#e2f5e9}
.badge{display:inline-block;background:#d6f5df;color:#075c40;padding:8px 18px;border-radius:30px;font-weight:bold}
.container{width:min(94%,700px);margin:20px auto}
.card{background:white;padding:22px;margin:16px 0;border-radius:18px;box-shadow:0 5px 20px #0000000b}
h2{font-size:20px;color:#08734e}
label{display:block;margin:14px 0 6px;font-weight:bold}
input,select,textarea{width:100%;padding:13px;border:1px solid #d5e2da;border-radius:10px;font-size:15px;background:#fff}
input[type=checkbox]{width:auto}
textarea{min-height:80px}
button{border:0;border-radius:11px;padding:14px;width:100%;margin-top:15px;background:#087f5b;color:white;font-size:16px;font-weight:bold;cursor:pointer}
button:disabled{opacity:.5}
.secondary{background:#234d3d}
.notice{background:#fff8df;border-right:4px solid #e0ad27;padding:13px;border-radius:8px;line-height:1.8}
.success{background:#e5f8eb;color:#12613b;padding:14px;border-radius:10px;margin-top:12px;line-height:1.8}
.error{background:#ffe9e9;color:#a22222;padding:14px;border-radius:10px;margin-top:12px}
.hidden{display:none!important}
footer{text-align:center;padding:25px;color:#60766b}
.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:500px){.row{grid-template-columns:1fr}header h1{font-size:21px}}
.result{border:1px solid #dbe8df;border-radius:12px;padding:15px;margin-top:12px;line-height:2}
.admin-item{border:1px solid #dce8df;padding:14px;border-radius:12px;margin:12px 0;overflow-wrap:anywhere}
.admin-item button{margin-top:8px}
</style>
</head>
<body>
<header>
  <div class="badge">بالقرآن نحيا</div>
  <h1>مسابقة أهل القرآن الكريم</h1>
  <p>قرية السلاموني - العام الرابع عشر</p>
  <p>1448 هـ | 2026 - 2027 م</p>
</header>
<main class="container">
<section class="card">
<h2>أهلًا بكم في مسابقة القرآن الكريم</h2>
<p>مسابقة أهل القرآن الكريم بقرية السلاموني، متاحة لجميع الأعمار وجميع المستويات.</p>
<div class="notice">
<b>مواعيد التسجيل:</b> من 1 ديسمبر 2026 حتى 31 ديسمبر 2026.<br>
<b>موعد الاستعلام:</b> يبدأ يوم 9 يناير 2027.<br>
<b>رسوم الاشتراك:</b> 10 جنيهات.
</div>
</section>

<section class="card">
<h2>الشروط والتعليمات</h2>
<ul style="line-height:2">
<li>المسابقة لأبناء قرية السلاموني فقط.</li>
<li>المسابقة متاحة لجميع الأعمار وجميع المستويات.</li>
<li>يُمنع الاشتراك بنفس المستوى الذي فاز به المتسابق في السنة الماضية.</li>
<li>يجب إدخال البيانات بصورة صحيحة.</li>
<li>يجب الاحتفاظ برقم الهاتف المستخدم في التسجيل للاستعلام.</li>
<li>يتم مراجعة الطلبات يدويًا ولا يعني التسجيل القبول النهائي.</li>
<li>يجب إدخال رقم عملية تحويل الرسوم بصورة صحيحة.</li>
</ul>
<label><input type="checkbox" id="agree"> أوافق على الشروط والتعليمات</label>
</section>

<section class="card" id="registerCard">
<h2>استمارة التسجيل</h2>
<div id="registerClosed" class="notice hidden">التسجيل غير متاح حاليًا.</div>
<form id="registerForm">
<label>الاسم رباعي *</label><input name="full_name" required maxlength="150">
<div class="row">
<div><label>تاريخ الميلاد *</label><input name="birth_date" type="date" required></div>
<div><label>الرقم القومي *</label><input name="national_id" inputmode="numeric" maxlength="14" minlength="14" required></div>
</div>
<div class="row">
<div><label>رقم الهاتف *</label><input name="phone" inputmode="numeric" maxlength="11" required></div>
<div><label>رقم ولي الأمر</label><input name="guardian_phone" inputmode="numeric" maxlength="11"></div>
</div>
<label>المنطقة أو النجع داخل السلاموني *</label><input name="area" required>
<label>نوع التعليم *</label>
<select name="education_type" required>
<option value="">اختر</option><option>عام</option><option>أزهري</option><option>غير ملتحق بالتعليم</option>
</select>
<label>السنة الدراسية</label><input name="school_year">
<label>المستوى الذي تريد الاشتراك فيه *</label><input name="level" required>
<label>عدد الأجزاء (اختياري)</label>
<select name="parts_count">
<option value="">لم أحدد</option><option value="1">1 جزء</option><option value="3">3 أجزاء</option>
<option value="5">5 أجزاء</option><option value="7.5">7.5 أجزاء</option><option value="10">10 أجزاء</option>
<option value="15">15 جزء</option><option value="20">20 جزء</option><option value="25">25 جزء</option><option value="30">30 جزء</option>
</select>
<label>اسم الشيخ المحفظ</label><input name="teacher">
<label>ملاحظات إضافية</label><textarea name="notes"></textarea>
<div class="notice">رسوم الاشتراك 10 جنيهات.<br>رقم فودافون كاش: <b id="wallet">01040367801</b><br>بعد التحويل، أدخل رقم العملية في الخانة التالية.</div>
<label>رقم عملية التحويل *</label><input name="transaction_number" required>
<button type="submit" id="registerButton">إرسال طلب التسجيل</button>
<div id="registerMessage"></div>
</form>
</section>

<section class="card hidden" id="inquiryCard">
<h2>الاستعلام عن نتيجة القبول</h2>
<p>يمكنك الاستعلام باستخدام الرقم القومي ورقم الهاتف المسجل.</p>
<form id="inquiryForm">
<label>الرقم القومي</label><input name="national_id" maxlength="14" minlength="14" inputmode="numeric" required>
<label>رقم الهاتف المسجل</label><input name="phone" maxlength="11" inputmode="numeric" required>
<button type="submit">استعلام عن النتيجة</button>
<div id="inquiryMessage"></div>
</form>
</section>

<section class="card">
<h2>لوحة الإدارة</h2>
<p>هذه الصفحة مخصصة لإدارة المسابقة فقط.</p>
<button class="secondary" type="button" onclick="showAdmin()">دخول الإدارة</button>
<div id="adminArea" class="hidden">
<form id="loginForm">
<label>كلمة مرور الإدارة</label><input name="password" type="password" required>
<button>دخول</button>
</form>
<div id="adminPanel" class="hidden">
<h2>طلبات المتسابقين</h2><button type="button" onclick="loadRegistrations()">تحديث الطلبات</button>
<div id="registrationList"></div>
<h2>إعدادات الموقع</h2>
<form id="settingsForm">
<label>رقم فودافون كاش</label><input name="wallet_number" required>
<label>تاريخ بداية التسجيل</label><input name="registration_start" type="date" required>
<label>تاريخ نهاية التسجيل</label><input name="registration_end" type="date" required>
<label>بداية الاستعلام</label><input name="inquiry_start" type="date" required>
<label><input name="registration_open" type="checkbox"> فتح التسجيل</label>
<button>حفظ الإعدادات</button>
</form>
<button style="background:#a32d2d" type="button" onclick="logout()">تسجيل الخروج</button>
</div>
</div>
</section>
</main>
<footer>مسابقة أهل القرآن الكريم - قرية السلاموني<br>العام الرابع عشر - بالقرآن نحيا</footer>

<script>
const $ = id => document.getElementById(id);

async function api(path, data, method = "POST") {
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: method === "GET" ? undefined : JSON.stringify(data)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "حدث خطأ");
  return result;
}

function message(id, text, ok = true) {
  $(id).replaceChildren();
  const box = document.createElement("div");
  box.className = ok ? "success" : "error";
  box.textContent = text;
  $(id).appendChild(box);
}

async function loadStatus() {
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "تعذر تحميل حالة الموقع");

    $("wallet").textContent = data.wallet_number;
    const today = new Intl.DateTimeFormat("en-CA", {
      timeZone: "Africa/Cairo", year: "numeric", month: "2-digit", day: "2-digit"
    }).format(new Date());

    const registrationOpen = data.registration_open &&
      today >= data.registration_start && today <= data.registration_end;
    $("registerForm").classList.toggle("hidden", !registrationOpen);
    $("registerClosed").classList.toggle("hidden", registrationOpen);

    // لا يظهر قسم الاستعلام إلا من التاريخ المحدد في إعدادات الموقع.
    const inquiryOpen = today >= data.inquiry_start;
    $("inquiryCard").classList.toggle("hidden", !inquiryOpen);
  } catch (error) {
    console.error(error);
  }
}

$("registerForm").addEventListener("submit", async event => {
  event.preventDefault();
  if (!$("agree").checked) {
    message("registerMessage", "يجب الموافقة على الشروط أولًا", false);
    return;
  }
  const data = Object.fromEntries(new FormData(event.target).entries());
  $("registerButton").disabled = true;
  try {
    const result = await api("/api/register", data);
    message("registerMessage", result.message + " - احتفظ برقم المتابعة: " + result.tracking_code);
    event.target.reset();
    $("agree").checked = false;
  } catch (error) {
    message("registerMessage", error.message, false);
  } finally {
    $("registerButton").disabled = false;
  }
});

$("inquiryForm").addEventListener("submit", async event => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  try {
    const result = await api("/api/inquiry", data);
    const r = result.result;
    $("inquiryMessage").replaceChildren();
    const box = document.createElement("div");
    box.className = "result";
    [
      "الاسم: " + r.full_name,
      "المستوى: " + r.level,
      "حالة الطلب: " + r.application_status,
      "حالة الدفع: " + r.payment_status
    ].forEach(line => {
      const p = document.createElement("p");
      p.textContent = line;
      box.appendChild(p);
    });
    $("inquiryMessage").appendChild(box);
  } catch (error) {
    message("inquiryMessage", error.message, false);
  }
});

function showAdmin() {
  $("adminArea").classList.toggle("hidden");
}

$("loginForm").addEventListener("submit", async event => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  try {
    await api("/api/login", data);
    $("loginForm").classList.add("hidden");
    $("adminPanel").classList.remove("hidden");
    await loadSettings();
    await loadRegistrations();
  } catch (error) {
    alert(error.message);
  }
});

async function loadRegistrations() {
  try {
    const data = await api("/api/admin/registrations", null, "GET");
    const list = $("registrationList");
    list.replaceChildren();
    if (!data.registrations.length) {
      list.textContent = "لا توجد طلبات حتى الآن";
      return;
    }

    data.registrations.forEach(row => {
      const item = document.createElement("div");
      item.className = "admin-item";
      const details = document.createElement("div");
      const fields = [
        "رقم الطلب: " + row.id,
        "الاسم: " + row.full_name,
        "تاريخ الميلاد: " + row.birth_date,
        "الرقم القومي: " + row.national_id,
        "الهاتف: " + row.phone,
        "هاتف ولي الأمر: " + (row.guardian_phone || "-"),
        "المنطقة: " + row.area,
        "التعليم: " + row.education_type,
        "السنة الدراسية: " + (row.school_year || "-"),
        "المستوى: " + row.level,
        "عدد الأجزاء: " + (row.parts_count ?? "-"),
        "الشيخ: " + (row.teacher || "-"),
        "رقم العملية: " + row.transaction_number,
        "رقم المتابعة: " + row.tracking_code,
        "حالة الطلب: " + row.application_status,
        "حالة الدفع: " + row.payment_status,
        "تاريخ التسجيل: " + (row.created_at || "-")
      ];
      fields.forEach(value => {
        const p = document.createElement("p");
        p.textContent = value;
        details.appendChild(p);
      });
      if (row.notes) {
        const p = document.createElement("p");
        p.textContent = "ملاحظات: " + row.notes;
        details.appendChild(p);
      }

      const application = document.createElement("select");
      ["قيد المراجعة", "مقبول", "مرفوض"].forEach(value => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = value;
        if (value === row.application_status) option.selected = true;
        application.appendChild(option);
      });

      const payment = document.createElement("select");
      ["قيد المراجعة", "تم التأكيد", "مرفوض"].forEach(value => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = value;
        if (value === row.payment_status) option.selected = true;
        payment.appendChild(option);
      });

      const save = document.createElement("button");
      save.textContent = "حفظ حالة المتسابق";
      save.onclick = async () => {
        try {
          await api("/api/admin/update", {
            id: row.id,
            application_status: application.value,
            payment_status: payment.value
          });
          alert("تم تحديث الطلب");
          await loadRegistrations();
        } catch (error) {
          alert(error.message);
        }
      };

      const print = document.createElement("button");
      print.textContent = "طباعة بطاقة التسجيل";
      print.className = "secondary";
      print.onclick = () => {
        const win = window.open("", "_blank");
        if (!win) {
          alert("اسمح بفتح النوافذ المنبثقة للطباعة");
          return;
        }
        const safe = value => String(value ?? "").replace(/[&<>"']/g, c => ({
          "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
        })[c]);
        const printableFields = fields.map(x => "<p>" + safe(x) + "</p>").join("");
        win.document.write(
          '<!doctype html><html dir="rtl"><head><meta charset="UTF-8">' +
          '<title>بطاقة تسجيل المتسابق</title>' +
          '<style>body{font-family:Arial;padding:25px;color:#173c2c}' +
          'h2{text-align:center}.box{border:2px solid #087f5b;padding:20px;' +
          'border-radius:12px;line-height:2}</style></head><body>' +
          '<h2>مسابقة أهل القرآن الكريم - السلاموني</h2>' +
          '<h3 style="text-align:center">بطاقة تسجيل المتسابق</h3>' +
          '<div class="box">' + printableFields + '</div>' +
          '<p style="text-align:center">بالقرآن نحيا</p>' +
          '<script>window.onload=function(){window.print()}<\/script>' +
          '</body></html>'
        );
        win.document.close();
      };

      item.appendChild(details);
      item.appendChild(document.createElement("hr"));
      item.appendChild(document.createTextNode("حالة القبول"));
      item.appendChild(application);
      item.appendChild(document.createTextNode("حالة الدفع"));
      item.appendChild(payment);
      item.appendChild(save);
      item.appendChild(print);
      list.appendChild(item);
    });
  } catch (error) {
    alert(error.message);
  }
}

async function loadSettings() {
  const data = await api("/api/admin/settings", null, "GET");
  const s = data.settings;
  const form = $("settingsForm");
  form.wallet_number.value = s.wallet_number;
  form.registration_start.value = s.registration_start;
  form.registration_end.value = s.registration_end;
  form.inquiry_start.value = s.inquiry_start;
  form.registration_open.checked = Number(s.registration_open) === 1;
}

$("settingsForm").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.target;
  const data = {
    wallet_number: form.wallet_number.value,
    registration_start: form.registration_start.value,
    registration_end: form.registration_end.value,
    inquiry_start: form.inquiry_start.value,
    registration_open: form.registration_open.checked
  };
  try {
    await api("/api/admin/settings", data);
    alert("تم حفظ الإعدادات بنجاح");
    await loadStatus();
  } catch (error) {
    alert(error.message);
  }
});

async function logout() {
  try {
    await api("/api/logout", {});
    $("adminPanel").classList.add("hidden");
    $("loginForm").classList.remove("hidden");
    $("loginForm").reset();
    alert("تم تسجيل الخروج");
  } catch (error) {
    alert(error.message);
  }
}

loadStatus();
</script>
</body>
</html>`;
}
