
import express from "express";
import session from "express-session";
import SQLiteStoreFactory from "connect-sqlite3";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import { z } from "zod";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const db = new Database(path.join(__dirname, "ruralx.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

try { db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'citizen'"); } catch (_) {}


db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  mobile TEXT NOT NULL UNIQUE,
  email TEXT UNIQUE,
  password_hash TEXT NOT NULL,
  security_pin_hash TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  role TEXT NOT NULL DEFAULT 'citizen',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS otp_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  code_hash TEXT NOT NULL,
  purpose TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  used INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS applications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ref TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL,
  service TEXT NOT NULL,
  department TEXT NOT NULL,
  payload TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Submitted',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS grievances (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ref TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL,
  department TEXT NOT NULL,
  description TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Registered',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);


db.exec(`
CREATE TABLE IF NOT EXISTS service_feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  service TEXT NOT NULL,
  rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
  comment TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS saved_services (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  service_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, service_id),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  read INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS issue_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ref TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  latitude REAL,
  longitude REAL,
  image_name TEXT,
  status TEXT NOT NULL DEFAULT 'Registered',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);


db.exec(`
CREATE TABLE IF NOT EXISTS ai_queries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  query TEXT NOT NULL,
  service_id TEXT,
  department TEXT,
  confidence INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS connector_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  service_id TEXT NOT NULL,
  action TEXT NOT NULL,
  status TEXT NOT NULL,
  reference TEXT,
  response_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

const SQLiteStore = SQLiteStoreFactory(session);
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: __dirname }),
  secret: process.env.SESSION_SECRET || "development-only-change-me",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 15 * 60 * 1000
  }
}));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: true, legacyHeaders: false });

function cleanMobile(v) { return String(v || "").replace(/\D/g, "").slice(-10); }
function newRef(prefix) { return `${prefix}-${new Date().getFullYear()}-${crypto.randomInt(100000, 999999)}`; }
function sendOtp(userId, purpose) {
  const code = crypto.randomInt(100000, 1000000).toString();
  db.prepare("UPDATE otp_codes SET used=1 WHERE user_id=? AND purpose=? AND used=0").run(userId, purpose);
  db.prepare("INSERT INTO otp_codes(user_id,code_hash,purpose,expires_at) VALUES(?,?,?,?)")
    .run(userId, bcrypt.hashSync(code, 10), purpose, Date.now() + 5*60*1000);
  // Production: replace this log with an approved SMS/email provider.
  console.log(`[DEV OTP] user=${userId} purpose=${purpose} code=${code}`);
  return code;
}
function requireAuth(req,res,next) {
  if (!req.session.userId) return res.status(401).json({error:"Authentication required"});
  next();
}
function requireVerified(req,res,next) {
  if (!req.session.userId || !req.session.verified) return res.status(401).json({error:"Verified login required"});
  next();
}
function requireAdmin(req,res,next) {
  if (!req.session.userId || !req.session.verified) return res.status(401).json({error:"Verified login required"});
  const u = db.prepare("SELECT role FROM users WHERE id=?").get(req.session.userId);
  if (!u || u.role !== "admin") return res.status(403).json({error:"Department console access required"});
  next();
}

const signupSchema = z.object({
  name: z.string().trim().min(2).max(100),
  mobile: z.string().regex(/^\d{10}$/),
  email: z.string().email().max(150).optional().or(z.literal("")),
  password: z.string().min(8).max(128),
  pin: z.string().regex(/^\d{4,6}$/)
});
const loginSchema = z.object({
  mobile: z.string().regex(/^\d{10}$/),
  password: z.string().min(1).max(128)
});

app.use("/api", apiLimiter);

app.get("/api/csrf", (req,res,next) => {
  // Keep one CSRF token for the lifetime of the browser session.
  // Do not regenerate it on every GET: multiple localhost tabs share the
  // same session cookie, and regenerating it in one tab invalidates another.
  if (!req.session.csrf) {
    req.session.csrf = crypto.randomBytes(24).toString("hex");
  }
  req.session.save(err => {
    if (err) return next(err);
    res.set("Cache-Control", "no-store");
    res.json({token:req.session.csrf});
  });
});
function csrf(req,res,next) {
  if (!req.session.csrf || req.get("x-csrf-token") !== req.session.csrf)
    return res.status(403).json({error:"CSRF validation failed"});
  next();
}

app.post("/api/auth/signup", authLimiter, csrf, async (req,res) => {
  const parsed = signupSchema.safeParse({...req.body, mobile: cleanMobile(req.body.mobile)});
  if (!parsed.success) return res.status(400).json({error:"Invalid registration details"});
  const {name,mobile,email,password,pin} = parsed.data;
  if (db.prepare("SELECT id FROM users WHERE mobile=?").get(mobile))
    return res.status(409).json({error:"An account already exists for this mobile number"});
  if (email && db.prepare("SELECT id FROM users WHERE email=?").get(email))
    return res.status(409).json({error:"An account already exists for this email"});
  const passwordHash = await bcrypt.hash(password, 12);
  const pinHash = await bcrypt.hash(pin, 12);
  const info = db.prepare("INSERT INTO users(name,mobile,email,password_hash,security_pin_hash,role) VALUES(?,?,?,?,?,?)")
    .run(name,mobile,email||null,passwordHash,pinHash,"citizen");
  sendOtp(info.lastInsertRowid, "signup");
  req.session.pendingUserId = Number(info.lastInsertRowid);
  req.session.pendingPurpose = "signup";
  res.status(201).json({ok:true, message:"OTP generated. In development it is printed in the server console."});
});

app.post("/api/auth/login", authLimiter, csrf, async (req,res) => {
  const parsed = loginSchema.safeParse({...req.body, mobile: cleanMobile(req.body.mobile)});
  if (!parsed.success) return res.status(400).json({error:"Invalid credentials"});
  const user = db.prepare("SELECT * FROM users WHERE mobile=?").get(parsed.data.mobile);
  if (!user || !(await bcrypt.compare(parsed.data.password, user.password_hash)))
    return res.status(401).json({error:"Invalid mobile number or password"});
  sendOtp(user.id, "login");
  req.session.pendingUserId = user.id;
  req.session.pendingPurpose = "login";
  res.json({ok:true, message:"OTP required"});
});

app.post("/api/auth/verify-otp", authLimiter, csrf, async (req,res) => {
  const userId = Number(req.session.pendingUserId);
  const purpose = req.session.pendingPurpose;
  const code = String(req.body.code || "");
  if (!userId || !purpose || !/^\d{6}$/.test(code)) return res.status(400).json({error:"Invalid OTP"});
  const row = db.prepare("SELECT * FROM otp_codes WHERE user_id=? AND purpose=? AND used=0 ORDER BY id DESC LIMIT 1").get(userId,purpose);
  if (!row || row.expires_at < Date.now() || row.attempts >= 5) return res.status(401).json({error:"OTP expired or unavailable"});
  if (!(await bcrypt.compare(code,row.code_hash))) {
    db.prepare("UPDATE otp_codes SET attempts=attempts+1 WHERE id=?").run(row.id);
    return res.status(401).json({error:"Incorrect OTP"});
  }
  db.prepare("UPDATE otp_codes SET used=1 WHERE id=?").run(row.id);
  const user = db.prepare("SELECT id,name,mobile,email,verified,role FROM users WHERE id=?").get(userId);
  db.prepare("UPDATE users SET verified=1 WHERE id=?").run(userId);
  req.session.userId = userId;
  req.session.verified = true;
  delete req.session.pendingUserId;
  delete req.session.pendingPurpose;
  res.json({ok:true,user:{...user,verified:1}});
});

app.post("/api/auth/logout", csrf, (req,res) => req.session.destroy(()=>res.json({ok:true})));
app.get("/api/auth/me", (req,res) => {
  if (!req.session.userId) return res.json({authenticated:false});
  const user = db.prepare("SELECT id,name,mobile,email,verified,role FROM users WHERE id=?").get(req.session.userId);
  if (!user) return res.json({authenticated:false});
  res.json({authenticated:true,user});
});

app.get("/api/applications", requireVerified, (req,res) => {
  const rows = db.prepare("SELECT ref,service,department,status,created_at FROM applications WHERE user_id=? ORDER BY id DESC").all(req.session.userId);
  res.json(rows);
});
app.post("/api/applications", csrf, requireVerified, (req,res) => {
  const body = req.body || {};
  if (typeof body.service !== "string" || typeof body.department !== "string") return res.status(400).json({error:"Invalid application"});
  const ref = newRef("RX");
  db.prepare("INSERT INTO applications(ref,user_id,service,department,payload) VALUES(?,?,?,?,?)")
    .run(ref,req.session.userId,body.service.slice(0,200),body.department.slice(0,200),JSON.stringify(body.data||{}));
  notify(req.session.userId,"Application submitted",`Your application ${ref} has been submitted.`);
  res.status(201).json({ok:true,ref});
});
app.get("/api/applications/:ref", requireVerified, (req,res) => {
  const a = db.prepare("SELECT ref,service,department,status,created_at FROM applications WHERE ref=? AND user_id=?").get(req.params.ref,req.session.userId);
  if (!a) return res.status(404).json({error:"Application not found"});
  res.json({...a,steps:[
    {t:"Application Submitted Online",s:a.created_at,done:true},
    {t:"Automated Document Verification",s:"Pending",active:true},
    {t:"Department Review",s:"Upcoming"},
    {t:"Final Sanction / Disbursement",s:"Upcoming"}
  ]});
});

app.get("/api/grievances", requireVerified, (req,res) => {
  res.json(db.prepare("SELECT ref,department,status,created_at FROM grievances WHERE user_id=? ORDER BY id DESC").all(req.session.userId));
});
app.post("/api/grievances", csrf, requireVerified, (req,res) => {
  const dept = String(req.body.department||"").slice(0,150);
  const description = String(req.body.description||"").trim().slice(0,2000);
  if (!dept || description.length < 5) return res.status(400).json({error:"Please provide a department and meaningful complaint"});
  const ref = newRef("RX-GRV");
  db.prepare("INSERT INTO grievances(ref,user_id,department,description) VALUES(?,?,?,?)")
    .run(ref,req.session.userId,dept,description);
  res.status(201).json({ok:true,ref});
});


function notify(userId, title, message) {
  db.prepare("INSERT INTO notifications(user_id,title,message) VALUES(?,?,?)").run(userId,title,message);
}


// Local demo admin. Change/remove this in production.
(async () => {
  const adminMobile = "9999999999";
  if (!db.prepare("SELECT id FROM users WHERE mobile=?").get(adminMobile)) {
    const passwordHash = await bcrypt.hash("Admin@12345", 12);
    const pinHash = await bcrypt.hash("1234", 12);
    db.prepare("INSERT INTO users(name,mobile,email,password_hash,security_pin_hash,verified,role) VALUES(?,?,?,?,?,?,?)")
      .run("RuralX Department Admin", adminMobile, "admin@ruralx.local", passwordHash, pinHash, 1, "admin");
  } else {
    db.prepare("UPDATE users SET verified=1, role='admin' WHERE mobile=?").run(adminMobile);
  }
})();

const SERVICE_CATALOG = [
  {id:"pm-kisan", name:"Farmer Income Support", department:"Agriculture & Farmers Welfare", icon:"🌾", tags:["farmer","income","agriculture"], desc:"Demo service flow for farmer income-support assistance.", docs:["Identity proof","Land/holding details","Bank account details"], eligibility:["Applicant is a farmer or cultivator","Land/holding information is available"], keywords:["farmer","farm","agriculture","kisan","crop","income support"]},
  {id:"pmay-g", name:"Rural Housing Assistance", department:"Rural Development", icon:"🏠", tags:["housing","home","rural"], desc:"Guided demo flow for rural household housing assistance.", docs:["Identity proof","Address/residence details","Household details"], eligibility:["Rural household","Housing need is established"], keywords:["house","home","housing","awas","shelter","toilet"]},
  {id:"mgnrega", name:"Rural Employment Assistance", department:"Rural Development", icon:"🧑‍🌾", tags:["employment","work","rural"], desc:"Demo job-demand and employment-assistance workflow.", docs:["Identity proof","Residence details","Job card details"], eligibility:["Rural resident","Employment demand is recorded"], keywords:["job","work","employment","mgnrega","labour","wage"]},
  {id:"pm-jay", name:"Health Coverage Assistance", department:"Health & Family Welfare", icon:"🏥", tags:["health","hospital","insurance"], desc:"Demo guidance for health-coverage service discovery.", docs:["Identity proof","Family details","Existing health documents if available"], eligibility:["Household eligibility needs to be checked against the official database"], keywords:["health","hospital","treatment","medicine","ayushman","medical"]},
  {id:"scholarship", name:"Student Scholarship Assistance", department:"Education", icon:"🎓", tags:["education","student","scholarship"], desc:"Demo scholarship discovery and document-check workflow.", docs:["Student identity","Institution details","Academic record","Bank account details"], eligibility:["Student status","Course/institution information"], keywords:["student","scholarship","college","school","education","fees"]},
  {id:"birth-certificate", name:"Birth Certificate Request", department:"Civil Registration", icon:"📜", tags:["certificate","birth","identity"], desc:"Guided demo workflow for a birth-certificate request.", docs:["Birth details","Parent/guardian details","Address details"], eligibility:["Birth event details are available"], keywords:["birth","certificate","newborn","registration"]},
  {id:"income-certificate", name:"Income Certificate Assistance", department:"Revenue Department", icon:"🧾", tags:["income","certificate","revenue"], desc:"Demo assisted flow for income-certificate service discovery.", docs:["Identity proof","Address details","Income declaration/supporting records"], eligibility:["Applicant can provide required income information"], keywords:["income","certificate","revenue","salary","earnings"]},
  {id:"soil-health", name:"Soil Health Assistance", department:"Agriculture & Farmers Welfare", icon:"🌱", tags:["soil","farm","agriculture"], desc:"Demo service discovery for soil-health support.", docs:["Farmer details","Farm/plot details","Sample details if required"], eligibility:["Farm/plot information is available"], keywords:["soil","fertilizer","farm","crop","agriculture"]},
  {id:"pension", name:"Social Security Pension Assistance", department:"Social Welfare", icon:"🤝", tags:["pension","social security"], desc:"Demo guided discovery for social-security pension services.", docs:["Identity proof","Age/date-of-birth details","Bank account details"], eligibility:["Applicable social-security category must be verified"], keywords:["pension","elderly","senior","widow","social security","disability"]},
  {id:"grievance", name:"Public Grievance Routing", department:"Citizen Grievance", icon:"📣", tags:["grievance","complaint","issue"], desc:"Route a citizen complaint to the most relevant department in the demo.", docs:["Complaint description","Optional location/evidence"], eligibility:["Any citizen can submit a public-service grievance"], keywords:["complaint","grievance","issue","problem","road","water","streetlight","garbage"]}
];

function findServiceById(id){ return SERVICE_CATALOG.find(s=>s.id===id); }
function scoreNeed(q, service){
  const text = String(q||"").toLowerCase();
  let score = 0;
  for (const k of service.keywords) if (text.includes(k)) score += 1;
  return score;
}
function analyzeNeed(q){
  const text = String(q||"").trim();
  const ranked = SERVICE_CATALOG.map(s=>({s,score:scoreNeed(text,s)}))
    .sort((a,b)=>b.score-a.score);
  const top = ranked[0];
  const second = ranked[1];
  const confidence = top.score ? Math.min(96, 62 + top.score*9) : 45;
  const matched = top.score ? top.s : SERVICE_CATALOG.find(s=>s.id==="grievance");
  return {
    query:text,
    intent: top.score ? `Likely need: ${matched.name}` : "General government-service request",
    service: matched,
    alternatives: [second?.s, ranked[2]?.s].filter(Boolean).map(x=>({id:x.id,name:x.name,department:x.department})),
    confidence,
    matchedKeywords: matched.keywords.filter(k=>text.toLowerCase().includes(k)).slice(0,6),
    explanation: top.score
      ? `RuralX matched your words to the ${matched.name} service area and its department.`
      : "RuralX could not confidently match a specific service, so grievance routing is offered as a safe fallback.",
    demoOnly: true
  };
}

app.get("/api/dashboard", requireVerified, (req,res) => {
  const applications = db.prepare("SELECT COUNT(*) n FROM applications WHERE user_id=?").get(req.session.userId).n;
  const grievances = db.prepare("SELECT COUNT(*) n FROM grievances WHERE user_id=?").get(req.session.userId).n;
  const saved = db.prepare("SELECT COUNT(*) n FROM saved_services WHERE user_id=?").get(req.session.userId).n;
  const unread = db.prepare("SELECT COUNT(*) n FROM notifications WHERE user_id=? AND read=0").get(req.session.userId).n;
  res.json({applications,grievances,saved,unread});
});

app.get("/api/notifications", requireVerified, (req,res) => {
  res.json(db.prepare("SELECT id,title,message,read,created_at FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 30").all(req.session.userId));
});
app.post("/api/notifications/read-all", csrf, requireVerified, (req,res) => {
  db.prepare("UPDATE notifications SET read=1 WHERE user_id=?").run(req.session.userId);
  res.json({ok:true});
});

app.get("/api/saved-services", requireVerified, (req,res) => {
  res.json(db.prepare("SELECT service_id,created_at FROM saved_services WHERE user_id=? ORDER BY id DESC").all(req.session.userId));
});
app.post("/api/saved-services/:serviceId", csrf, requireVerified, (req,res) => {
  const id = String(req.params.serviceId).slice(0,80);
  db.prepare("INSERT OR IGNORE INTO saved_services(user_id,service_id) VALUES(?,?)").run(req.session.userId,id);
  res.json({ok:true});
});
app.delete("/api/saved-services/:serviceId", csrf, requireVerified, (req,res) => {
  db.prepare("DELETE FROM saved_services WHERE user_id=? AND service_id=?").run(req.session.userId,req.params.serviceId);
  res.json({ok:true});
});

app.post("/api/feedback", csrf, requireVerified, (req,res) => {
  const service = String(req.body.service||"").slice(0,200);
  const rating = Number(req.body.rating);
  const comment = String(req.body.comment||"").slice(0,1000);
  if(!service || !Number.isInteger(rating) || rating < 1 || rating > 5) return res.status(400).json({error:"Invalid feedback"});
  db.prepare("INSERT INTO service_feedback(user_id,service,rating,comment) VALUES(?,?,?,?)")
    .run(req.session.userId,service,rating,comment);
  res.status(201).json({ok:true});
});

app.post("/api/issues", csrf, requireVerified, (req,res) => {
  const category = String(req.body.category||"").slice(0,100);
  const description = String(req.body.description||"").trim().slice(0,2000);
  const latitude = Number.isFinite(Number(req.body.latitude)) ? Number(req.body.latitude) : null;
  const longitude = Number.isFinite(Number(req.body.longitude)) ? Number(req.body.longitude) : null;
  const imageName = String(req.body.imageName||"").slice(0,200) || null;
  if(!category || description.length < 5) return res.status(400).json({error:"Please provide a category and meaningful description"});
  const ref = newRef("RX-ISS");
  db.prepare("INSERT INTO issue_reports(ref,user_id,category,description,latitude,longitude,image_name) VALUES(?,?,?,?,?,?,?)")
    .run(ref,req.session.userId,category,description,latitude,longitude,imageName);
  notify(req.session.userId,"Issue registered",`Your issue ${ref} has been registered.`);
  res.status(201).json({ok:true,ref});
});
app.get("/api/issues", requireVerified, (req,res) => {
  res.json(db.prepare("SELECT ref,category,description,latitude,longitude,status,created_at FROM issue_reports WHERE user_id=? ORDER BY id DESC").all(req.session.userId));
});



app.get("/api/services", (req,res) => {
  const q = String(req.query.q||"").toLowerCase().trim();
  const department = String(req.query.department||"").toLowerCase().trim();
  let items = SERVICE_CATALOG;
  if(q) items = items.filter(s => `${s.name} ${s.department} ${s.desc} ${s.tags.join(" ")}`.toLowerCase().includes(q));
  if(department) items = items.filter(s => s.department.toLowerCase() === department);
  res.json({services:items, departments:[...new Set(SERVICE_CATALOG.map(s=>s.department))]});
});

app.get("/api/services/:id", (req,res) => {
  const s = findServiceById(req.params.id);
  if(!s) return res.status(404).json({error:"Service not found"});
  res.json(s);
});


function aiChatResponse(query, language="en") {
  const text=String(query||"").trim();
  const lower=text.toLowerCase();
  const ranked=SERVICE_CATALOG.map(s=>({s,score:scoreNeed(lower,s)})).sort((a,b)=>b.score-a.score);
  const top=ranked[0], second=ranked[1];
  const hasService=top && top.score>0;
  const matched=hasService?top.s:null;
  const confidence=hasService?Math.min(97,64+top.score*8):38;
  const matchedKeywords=matched?matched.keywords.filter(k=>lower.includes(k)).slice(0,6):[];
  const asksDocs=/document|docs|paper|proof|certificate|papers|कागज|दस्तावेज|कागदपत्र/.test(lower);
  const asksEligibility=/eligible|eligibility|qualify|qualification|criteria|पात्र|योग्य|अर्ह|पात्रता/.test(lower);
  const asksApply=/apply|application|register|start|how do i get|आवेदन|अर्ज|apply कर/.test(lower);
  const asksDepartment=/department|office|which ministry|where|विभाग|कार्यालय|मंत्रालय/.test(lower);
  const asksTrack=/track|status|reference|application status|स्टेटस|स्थिति|अर्जाची स्थिती/.test(lower);
  const isGreeting=/^(hi|hello|hey|namaste|नमस्ते|नमस्कार|हाय)\b/i.test(lower);
  let answer="";
  let actions=[];
  if(isGreeting){
    answer=language==="hi"?"नमस्ते! मैं RuralX Assistant हूँ। आप अपनी जरूरत सामान्य भाषा में बताइए—जैसे छात्रवृत्ति, घर, किसान सहायता, स्वास्थ्य, प्रमाणपत्र या शिकायत। मैं संबंधित सेवा, विभाग, दस्तावेज और अगला कदम समझा सकता हूँ।":language==="mr"?"नमस्कार! मी RuralX Assistant आहे. तुमची गरज साध्या भाषेत सांगा—उदा. शिष्यवृत्ती, घर, शेतकरी मदत, आरोग्य, प्रमाणपत्र किंवा तक्रार. मी संबंधित सेवा, विभाग, कागदपत्रे आणि पुढील पाऊल समजावू शकतो.":"Hello! I’m the RuralX Assistant. Tell me what you need in everyday language—such as a scholarship, housing, farmer support, health help, a certificate, or a grievance. I’ll guide you to the relevant service, department, documents and next step.";
    actions=[{label:"Explore all services",type:"services"}];
  } else if(!hasService){
    answer=language==="hi"?"मैं आपकी बात समझने में मदद कर सकता हूँ। कृपया थोड़ा और बताएं—आप किसान, छात्र, घर, स्वास्थ्य, प्रमाणपत्र, पेंशन या किसी सरकारी सेवा/शिकायत के बारे में मदद चाहते हैं?":language==="mr"?"मी तुमची गरज समजून घेण्यास मदत करू शकतो. कृपया थोडे अधिक सांगा—तुम्हाला शेतकरी, विद्यार्थी, घर, आरोग्य, प्रमाणपत्र, पेन्शन किंवा सरकारी सेवा/तक्रारीबद्दल मदत हवी आहे का?":"I can help narrow this down. Tell me a little more: are you looking for farmer support, housing, education, health, a certificate, pension, employment, or a public-service grievance?";
    actions=[{label:"Explore services",type:"services"},{label:"Report a grievance",type:"grievance"}];
  } else if(asksDocs){
    answer=language==="hi"?`${matched.name} के लिए RuralX की डेमो checklist में ${matched.docs.join(", ")} शामिल हैं। विभाग अतिरिक्त दस्तावेज मांग सकता है।`:language==="mr"?`${matched.name} साठी RuralX च्या डेमो यादीत ${matched.docs.join(", ")} समाविष्ट आहेत. विभाग अतिरिक्त कागदपत्रे मागू शकतो.`:`For ${matched.name}, the RuralX demo checklist includes ${matched.docs.join(", ")}. The responsible department may request additional documents.`;
    actions=[{label:"View documents",type:"docs",id:matched.id},{label:"Check eligibility",type:"eligibility",id:matched.id},{label:"Start application",type:"apply",id:matched.id}];
  } else if(asksEligibility){
    answer=language==="hi"?`${matched.name} के लिए RuralX पहले एक basic pre-check करता है। डेमो में ${matched.eligibility.join("; ")} जैसी जानकारी देखी जाती है। यह अंतिम सरकारी eligibility decision नहीं है।`:language==="mr"?`${matched.name} साठी RuralX प्राथमिक pre-check करतो. डेमोमध्ये ${matched.eligibility.join("; ")} यासारखी माहिती पाहिली जाते. हा अंतिम सरकारी पात्रता निर्णय नाही.`:`For ${matched.name}, RuralX can run a basic pre-check. The demo looks for information such as ${matched.eligibility.join("; ")}. This is not the final government eligibility decision.`;
    actions=[{label:"Run eligibility check",type:"eligibility",id:matched.id},{label:"See documents",type:"docs",id:matched.id}];
  } else if(asksApply){
    answer=language==="hi"?`${matched.name} के लिए मैं आपको guided application शुरू करने में मदद कर सकता हूँ। पहले नाम, जरूरी जानकारी और उपलब्ध दस्तावेज की स्थिति भरें। इस demo में submission एक simulated RuralX workflow है।`:language==="mr"?`${matched.name} साठी मी guided application सुरू करण्यात मदत करू शकतो. आधी नाव, आवश्यक माहिती आणि उपलब्ध कागदपत्रांची स्थिती भरा. या डेमोमध्ये submission हा simulated RuralX workflow आहे.`:`I can help you start a guided application for ${matched.name}. You’ll provide your name, relevant information and document availability. In this demo, submission uses a simulated RuralX workflow.`;
    actions=[{label:"Start application",type:"apply",id:matched.id},{label:"Check eligibility first",type:"eligibility",id:matched.id}];
  } else if(asksDepartment){
    answer=language==="hi"?`${matched.name} को RuralX ने ${matched.department} से map किया है। यह mapping demo service catalog पर आधारित है।`:language==="mr"?`${matched.name} ही सेवा RuralX ने ${matched.department} विभागाशी जोडली आहे. हे mapping डेमो service catalog वर आधारित आहे.`:`RuralX maps ${matched.name} to the ${matched.department} department. This mapping is based on the demo service catalog.`;
    actions=[{label:"View service",type:"service",id:matched.id},{label:"Check eligibility",type:"eligibility",id:matched.id}];
  } else if(asksTrack){
    answer=language==="hi"?"अगर आपने RuralX में आवेदन जमा किया है, तो Track या My Applications में अपना reference number डालकर स्थिति देख सकते हैं।":language==="mr"?"तुम्ही RuralX मध्ये अर्ज केला असल्यास Track किंवा My Applications मध्ये reference number टाकून स्थिती पाहू शकता.":"If you submitted an application through RuralX, use Track or My Applications with your reference number to view its current demo workflow status.";
    actions=[{label:"Open Track",type:"track"}];
  } else {
    answer=language==="hi"?`आपकी बात ${matched.name} से सबसे ज्यादा मेल खाती है। RuralX इसे ${matched.department} से map करता है। मैं आपको eligibility, documents या application के अगले कदम में मदद कर सकता हूँ।`:language==="mr"?`तुमची गरज ${matched.name} शी सर्वाधिक जुळते. RuralX ती ${matched.department} विभागाशी जोडतो. मी पात्रता, कागदपत्रे किंवा अर्जाच्या पुढील टप्प्यात मदत करू शकतो.`:`Your request most closely matches ${matched.name}. RuralX maps it to ${matched.department}. I can help with eligibility, documents, or the application next.`;
    actions=[{label:"Check eligibility",type:"eligibility",id:matched.id},{label:"Documents",type:"docs",id:matched.id},{label:"Start application",type:"apply",id:matched.id}];
  }
  const recommendations=ranked.filter(x=>x.score>0).slice(0,3).map((x,i)=>({id:x.s.id,name:x.s.name,department:x.s.department,icon:x.s.icon,confidence:`${Math.min(96,58+x.score*10)}% match`}));
  return {answer,primary:matched,intent:matched?`Likely need: ${matched.name}`:"General service discovery",confidence,matchedKeywords,recommendations,actions,explanation:matched?`RuralX identified ${matched.name} from the words in your request and mapped it to ${matched.department}.`:"RuralX needs a little more information before selecting a specific service."};
}

app.post("/api/ai/chat", requireVerified, csrf, (req,res) => {
  const query=String(req.body.query||"").trim().slice(0,1000);
  const language=["en","hi","mr"].includes(req.body.language)?req.body.language:"en";
  if(query.length<2)return res.status(400).json({error:"Please tell the assistant what you need"});
  const result=aiChatResponse(query,language);
  db.prepare("INSERT INTO ai_queries(user_id,query,service_id,department,confidence) VALUES(?,?,?,?,?)")
    .run(req.session.userId,query,result.primary?.id||null,result.primary?.department||null,result.confidence);
  res.json(result);
});

app.post("/api/ai/analyze", requireVerified, csrf, (req,res) => {
  const query = String(req.body.query||"").trim().slice(0,1000);
  if(query.length < 3) return res.status(400).json({error:"Please describe what you need"});
  const result = analyzeNeed(query);
  db.prepare("INSERT INTO ai_queries(user_id,query,service_id,department,confidence) VALUES(?,?,?,?,?)")
    .run(req.session.userId,query,result.service.id,result.service.department,result.confidence);
  res.json(result);
});

app.post("/api/services/:id/eligibility", requireVerified, csrf, (req,res) => {
  const s = findServiceById(req.params.id);
  if(!s) return res.status(404).json({error:"Service not found"});
  const p = req.body || {};
  const answers = [
    {label:"Basic profile provided", ok:Boolean(p.name)},
    {label:"Relevant need/category selected", ok:Boolean(p.category)},
    {label:"Location/residence information", ok:Boolean(p.residence)},
    {label:"Supporting information available", ok:Boolean(p.supporting)}
  ];
  const score = answers.filter(x=>x.ok).length;
  res.json({
    service:s,
    score,
    total:answers.length,
    status:score===answers.length ? "Ready for official eligibility check" : "More information may be needed",
    answers,
    note:"This is a RuralX demonstration screening. Final eligibility must be verified by the responsible government system."
  });
});

app.get("/api/services/:id/documents", (req,res) => {
  const s = findServiceById(req.params.id);
  if(!s) return res.status(404).json({error:"Service not found"});
  res.json({service:s.name, documents:s.docs, note:"Demo checklist. The responsible department may require additional or different documents."});
});

app.post("/api/connectors/:id/run", requireVerified, csrf, (req,res) => {
  const s = findServiceById(req.params.id);
  if(!s) return res.status(404).json({error:"Service not found"});
  const action = String(req.body.action||"check-status").slice(0,80);
  const ref = `SIM-${new Date().getFullYear()}-${crypto.randomInt(100000,999999)}`;
  const response = {
    connector:"RuralX Adapter Simulator",
    targetSystem:`${s.department} service adapter`,
    action,
    status:"SIMULATED_SUCCESS",
    reference:ref,
    timestamp:new Date().toISOString(),
    message:"This response is simulated for demonstration; no live government system was contacted."
  };
  db.prepare("INSERT INTO connector_runs(user_id,service_id,action,status,reference,response_json) VALUES(?,?,?,?,?,?)")
    .run(req.session.userId,s.id,action,response.status,ref,JSON.stringify(response));
  res.json(response);
});

app.get("/api/applications/:ref/integration", requireVerified, (req,res) => {
  const a = db.prepare("SELECT ref,service,department,status FROM applications WHERE ref=? AND user_id=?").get(req.params.ref,req.session.userId);
  if(!a) return res.status(404).json({error:"Application not found"});
  const s = SERVICE_CATALOG.find(x=>x.name===a.service);
  res.json({
    application:a,
    connector:{
      adapter:s ? `${s.department} Adapter` : "Department Adapter",
      stages:[
        {name:"RuralX intake",status:"Complete"},
        {name:"Standardized API payload",status:"Ready"},
        {name:"Department connector",status:"Simulated"},
        {name:"Government system acknowledgement",status:"Demo response"},
        {name:"Unified tracking",status:"Active"}
      ],
      note:"Connector status is simulated in this local demo."
    }
  });
});

app.get("/api/admin/overview", requireAdmin, (req,res) => {
  const counts = {
    users:db.prepare("SELECT COUNT(*) n FROM users WHERE role='citizen'").get().n,
    applications:db.prepare("SELECT COUNT(*) n FROM applications").get().n,
    grievances:db.prepare("SELECT COUNT(*) n FROM grievances").get().n,
    issues:db.prepare("SELECT COUNT(*) n FROM issue_reports").get().n,
    aiQueries:db.prepare("SELECT COUNT(*) n FROM ai_queries").get().n,
    connectorRuns:db.prepare("SELECT COUNT(*) n FROM connector_runs").get().n
  };
  const connectors = [...new Set(SERVICE_CATALOG.map(s=>s.department))].map(d=>({department:d,status:"SIMULATOR READY"}));
  const recent = db.prepare("SELECT ref,service,department,status,created_at FROM applications ORDER BY id DESC LIMIT 8").all();
  const issues = db.prepare("SELECT ref,category,status,created_at FROM issue_reports ORDER BY id DESC LIMIT 8").all();
  res.json({counts,connectors,recent,issues,serviceCount:SERVICE_CATALOG.length});
});

app.get("/api/admin/ai-queries", requireAdmin, (req,res) => {
  res.json(db.prepare("SELECT query,service_id,department,confidence,created_at FROM ai_queries ORDER BY id DESC LIMIT 30").all());
});

app.get("/api/admin/connectors", requireAdmin, (req,res) => {
  const rows = db.prepare("SELECT service_id,action,status,reference,created_at FROM connector_runs ORDER BY id DESC LIMIT 30").all();
  res.json(rows);
});

app.use(express.static(path.join(__dirname,"public")));
app.get("/{*splat}", (req,res) => res.sendFile(path.join(__dirname,"public","index.html")));

app.listen(PORT, () => console.log(`RuralX running at http://localhost:${PORT}`));
