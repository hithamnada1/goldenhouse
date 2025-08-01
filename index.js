const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const JSZip = require('jszip');
const fetch = require('node-fetch');
const compression = require('compression');
const cache = require('./cache');

const app = express();
const PORT = 3000;

// إضافة compression لضغط البيانات
app.use(compression({
  level: 6,
  threshold: 1024,
  filter: (req, res) => {
    if (req.headers['x-no-compression']) {
      return false;
    }
    return compression.filter(req, res);
  }
}));

// تحسين إعدادات Express للأداء
app.set('trust proxy', 1);
app.set('x-powered-by', false);

// إضافة rate limiting بسيط - مؤقتاً معطل
// const rateLimit = require('express-rate-limit');
// const limiter = rateLimit({
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 1000, // limit each IP to 1000 requests per windowMs
//   message: 'Too many requests from this IP'
// });
// app.use('/api/', limiter);

// تحسين إعدادات body parser
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

// إضافة headers للأداء
app.use((req, res, next) => {
  res.header('Cache-Control', 'public, max-age=600'); // 10 minutes cache
  res.header('X-Content-Type-Options', 'nosniff');
  res.header('X-Frame-Options', 'DENY');
  res.header('X-DNS-Prefetch-Control', 'on');
  next();
});

// Serve uploaded files without authentication for images - يجب أن يكون أولاً
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  maxAge: '1d', // cache for 1 day
  etag: true,
  lastModified: true
}, (req, res, next) => {
  // إضافة CORS headers للصور
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  // إضافة cache للصور
  res.header('Cache-Control', 'public, max-age=86400'); // 24 hours for images
  next();
}));

app.use(cors());

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Route محدد للصور بدون مصادقة
app.get('/uploads/:filename', (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(__dirname, 'uploads', filename);
  
  // إضافة CORS headers للصور
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  
  if (fs.existsSync(filePath)) {
    res.sendFile(filePath);
  } else {
    res.status(404).json({error: 'الملف غير موجود'});
  }
});

// Middleware للمصادقة - يطبق فقط على API endpoints
app.use('/api', (req, res, next) => {
  // تقليل logging للأداء - إيقاف تماماً
  // if (process.env.NODE_ENV === 'development') {
  //   console.log('=== AUTH MIDDLEWARE START ===');
  //   console.log('Auth middleware - Method:', req.method);
  //   console.log('Auth middleware - Path:', req.path);
  // }
  
  // تجاهل المصادقة لمسارات المصادقة والملفات المرفوعة
  if (req.path.startsWith('/auth/') || req.path.startsWith('/uploads/')) {
    console.log('Auth middleware - Skipping auth for:', req.path);
    return next();
  }
  
  // التحقق من وجود token في headers أو query
  const token = req.headers.authorization || req.query.token;
  console.log('Auth middleware - Token:', token);
  
  if (!token) {
    console.log('Auth middleware - No token found');
    return res.status(401).json({error: 'غير مصرح - يرجى تسجيل الدخول'});
  }
  
  // في الإنتاج، يجب التحقق من صحة JWT token
  // هنا نستخدم token بسيط كـ user ID
  const userId = parseInt(token);
  console.log('Auth middleware - User ID:', userId);
  
  if (!userId || isNaN(userId)) {
    console.log('Auth middleware - Invalid token');
    return res.status(401).json({error: 'token غير صحيح'});
  }
  
  // جلب بيانات المستخدم
  db.get('SELECT * FROM users WHERE id = ? AND is_active = 1', [userId], (err, user) => {
    if (err) {
      console.log('Auth middleware - Database error:', err);
      return res.status(500).json({error: err.message});
    }
    if (!user) {
      console.log('Auth middleware - User not found');
      return res.status(401).json({error: 'المستخدم غير موجود'});
    }
    
    console.log('Auth middleware - User found:', user.username);
    req.user = user;
    console.log('=== AUTH MIDDLEWARE END ===');
    next();
  });
});

// إعدادات حفظ الملفات
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit - تقليل من 50MB
    fieldSize: 10 * 1024 * 1024, // 10MB field size limit
    files: 10 // حد أقصى 10 ملفات
  },
  fileFilter: (req, file, cb) => {
    // السماح بملفات الصور وملفات PDF
    if (file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('يسمح فقط بملفات الصور وملفات PDF'), false);
    }
  }
});

// Uploads are now served as static files without authentication

const db = new sqlite3.Database(path.join(__dirname, 'goldenhouse.db'), sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
  if (err) {
    console.error('خطأ في فتح قاعدة البيانات:', err.message);
  } else {
    console.log('تم فتح قاعدة البيانات بنجاح');
    
    // تحسين إعدادات قاعدة البيانات للأداء
    db.configure('busyTimeout', 30000);
    db.run('PRAGMA journal_mode = WAL');
    db.run('PRAGMA synchronous = NORMAL');
    db.run('PRAGMA cache_size = -64000'); // 64MB cache
    db.run('PRAGMA temp_store = MEMORY');
    db.run('PRAGMA mmap_size = 268435456'); // 256MB mmap
    
    // إضافة فهارس لتحسين الأداء
    db.run('CREATE INDEX IF NOT EXISTS idx_properties_operation_type ON properties(operation_type)');
    db.run('CREATE INDEX IF NOT EXISTS idx_properties_unit_type ON properties(unit_type)');
    db.run('CREATE INDEX IF NOT EXISTS idx_properties_created_by ON properties(created_by)');
    db.run('CREATE INDEX IF NOT EXISTS idx_properties_created_at ON properties(created_at)');
    db.run('CREATE INDEX IF NOT EXISTS idx_properties_price ON properties(price)');
    db.run('CREATE INDEX IF NOT EXISTS idx_properties_location ON properties(location)');
    // db.run('CREATE INDEX IF NOT EXISTS idx_properties_status ON properties(status)');
    // db.run('CREATE INDEX IF NOT EXISTS idx_units_building_id ON units(building_id)');
    
    console.log('تم إنشاء فهارس قاعدة البيانات لتحسين الأداء');
  }
});

const contractTable = `CREATE TABLE IF NOT EXISTS contracts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  contract_number TEXT,
  client_name TEXT,
  client_phone TEXT,
  client_email TEXT,
  unit_number TEXT,
  rent_value REAL,
  installments INTEGER,
  insurance REAL,
  office_commission REAL,
  service_fees REAL,
  municipality_file REAL,
  municipality_date REAL,
  municipality_notes TEXT,
  terms TEXT,
  online_fees REAL,
  electricity_fees REAL,
  water_fees REAL,
  broker_name TEXT,
  broker_name_unit TEXT,
  clearance_name TEXT,
  clearance_value REAL,
  total_commission REAL,
  commission_deduction REAL,
  attestation_value REAL,
  attestation_deduction REAL,
  representative_commission REAL,
  representative_commission_unit REAL,
  representative_attestation REAL,
  office_commission_internal REAL,
  internal_notes TEXT,
  broker_id INTEGER,
  contract_date TEXT,
  created_at TEXT
);`;

// إنشاء جدول عمولات الوسطاء
const brokerCommissionsTable = `CREATE TABLE IF NOT EXISTS broker_commissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  contract_id INTEGER,
  broker_name TEXT,
  commission_type TEXT,
  commission_value REAL,
  contract_number TEXT,
  unit_number TEXT,
  client_name TEXT,
  rent_value REAL,
  contract_date TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (contract_id) REFERENCES contracts (id)
);`;

const clearanceTable = `CREATE TABLE IF NOT EXISTS clearances (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT,
  email TEXT,
  commission_rate REAL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);`;

const receiptTable = `CREATE TABLE IF NOT EXISTS receipts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT,
  value REAL,
  description TEXT,
  date TEXT,
  client_name TEXT
);`;

const precontractTable = `CREATE TABLE IF NOT EXISTS precontracts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  contract_number TEXT,
  client_name TEXT,
  unit_number TEXT,
  rent_value REAL,
  payments TEXT,
  insurance REAL,
  phone TEXT,
  email TEXT,
  office_commission REAL,
  admin_expenses REAL,
  online_value REAL,
  sanitation REAL,
  extra_electricity REAL,
  details TEXT,
  created_at TEXT
);`;

// ===== نظام إدارة المستخدمين والصلاحيات =====
const usersTable = `CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  full_name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  role TEXT DEFAULT 'user',
  is_active INTEGER DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);`;

const permissionsTable = `CREATE TABLE IF NOT EXISTS user_permissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  permission_name TEXT NOT NULL,
  is_granted INTEGER DEFAULT 1,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);`;

const brokersTable = `CREATE TABLE IF NOT EXISTS brokers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT,
  email TEXT,
  commission_rate REAL DEFAULT 0,
  address TEXT,
  status TEXT DEFAULT 'active',
  notes TEXT,
  created_at TEXT,
  updated_at TEXT
);`;

// ===== نظام عقاراتي الجديد =====
const buildingsTable = `CREATE TABLE IF NOT EXISTS buildings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  address TEXT,
  description TEXT,
  total_floors INTEGER,
  total_units INTEGER,
  documents TEXT,
  created_by INTEGER,
  created_by_name TEXT,
  created_by_username TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);`;

const unitsTable = `CREATE TABLE IF NOT EXISTS units (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  building_id INTEGER,
  unit_number TEXT,
  unit_type TEXT,
  floor_number INTEGER,
  area REAL,
  rooms INTEGER,
  bathrooms INTEGER,
  price REAL,
  status TEXT DEFAULT 'available',
  description TEXT,
  documents TEXT,
  created_by INTEGER,
  created_by_name TEXT,
  created_by_username TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (building_id) REFERENCES buildings (id) ON DELETE CASCADE
);`;

const paymentsTable = `CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  unit_id INTEGER,
  payment_type TEXT,
  amount REAL,
  payment_date TEXT,
  due_date TEXT,
  status TEXT DEFAULT 'pending',
  description TEXT,
  documents TEXT,
  created_by INTEGER,
  created_by_name TEXT,
  created_by_username TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (unit_id) REFERENCES units (id) ON DELETE CASCADE
);`;

const invoicesTable = `CREATE TABLE IF NOT EXISTS invoices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  unit_id INTEGER,
  invoice_type TEXT,
  amount REAL,
  invoice_date TEXT,
  due_date TEXT,
  status TEXT DEFAULT 'pending',
  description TEXT,
  documents TEXT,
  created_by INTEGER,
  created_by_name TEXT,
  created_by_username TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (unit_id) REFERENCES units (id) ON DELETE CASCADE
);`;

db.serialize(() => {
  db.run(contractTable);
  db.run(brokerCommissionsTable);
  db.run(clearanceTable);
  db.run(receiptTable);
  db.run(precontractTable);
  db.run(brokersTable);
  db.run(usersTable);
  db.run(permissionsTable);
  db.run(buildingsTable);
  db.run(unitsTable);
  db.run(paymentsTable);
  db.run(invoicesTable);

  // إضافة مستخدم افتراضي للنظام
  const now = new Date().toLocaleString('ar-EG');
  db.run(`
    INSERT OR IGNORE INTO users (username, password, full_name, email, role, is_active, created_at, updated_at)
    VALUES ('admin', 'admin123', 'مدير النظام', 'admin@goldenhouse.com', 'admin', 1, ?, ?)
  `, [now, now], function(err) {
    if (err) {
      console.error('Error creating default admin user:', err);
    } else {
      console.log('Default admin user ready');
      
      // إضافة جميع الصلاحيات للمدير
      const adminId = this.lastID || 1;
      const allPermissions = [
        'add_contract',
        'view_contracts', 
        'receipts',
        'broker_commissions',
        'company_work',
        'user_management'
      ];
      
      allPermissions.forEach(permission => {
        db.run(`
          INSERT OR IGNORE INTO user_permissions (user_id, permission_name, is_granted, created_at)
          VALUES (?, ?, 1, ?)
        `, [adminId, permission, now]);
      });
    }
  });
  
  // إضافة تخليصات افتراضية
  db.run(`
    INSERT OR IGNORE INTO clearances (name, phone, email, commission_rate, created_at)
    VALUES 
    ('تخليص أبوظبي', '+971501234567', 'abudhabi@clearance.com', 5.0, ?),
    ('تخليص دبي', '+971502345678', 'dubai@clearance.com', 4.5, ?),
    ('تخليص الشارقة', '+971503456789', 'sharjah@clearance.com', 4.0, ?)
  `, [now, now, now], function(err) {
    if (err) {
      console.error('Error creating default clearances:', err);
    } else {
      console.log('Default clearances ready');
    }
  });
  
  // إضافة الأعمدة الجديدة إلى جدول العقود إذا لم تكن موجودة
  const newColumns = [
    "ALTER TABLE contracts ADD COLUMN created_at TEXT",
    "ALTER TABLE contracts ADD COLUMN client_phone TEXT",
    "ALTER TABLE contracts ADD COLUMN client_email TEXT",
    "ALTER TABLE contracts ADD COLUMN installments INTEGER",
    "ALTER TABLE contracts ADD COLUMN insurance REAL",
    "ALTER TABLE contracts ADD COLUMN office_commission REAL",
    "ALTER TABLE contracts ADD COLUMN service_fees REAL",
    "ALTER TABLE contracts ADD COLUMN municipality_file TEXT",
    "ALTER TABLE contracts ADD COLUMN municipality_date TEXT",
    "ALTER TABLE contracts ADD COLUMN municipality_notes TEXT",
    "ALTER TABLE contracts ADD COLUMN terms TEXT",
    "ALTER TABLE contracts ADD COLUMN online_fees REAL",
    "ALTER TABLE contracts ADD COLUMN electricity_fees REAL",
    // أعمدة المستندات
    "ALTER TABLE contracts ADD COLUMN identity_document TEXT",
    "ALTER TABLE contracts ADD COLUMN passport_document TEXT",
    "ALTER TABLE contracts ADD COLUMN address_document TEXT",
    "ALTER TABLE contracts ADD COLUMN income_document TEXT",
    "ALTER TABLE contracts ADD COLUMN additional_documents TEXT",
    "ALTER TABLE contracts ADD COLUMN documents_notes TEXT",
    "ALTER TABLE contracts ADD COLUMN water_fees REAL",
    "ALTER TABLE contracts ADD COLUMN broker_name TEXT",
    "ALTER TABLE contracts ADD COLUMN total_commission REAL",
    "ALTER TABLE contracts ADD COLUMN commission_deduction REAL",
    "ALTER TABLE contracts ADD COLUMN attestation_value REAL",
    "ALTER TABLE contracts ADD COLUMN attestation_deduction REAL",
    "ALTER TABLE contracts ADD COLUMN representative_commission REAL",
    "ALTER TABLE contracts ADD COLUMN office_commission_internal REAL",
    "ALTER TABLE contracts ADD COLUMN internal_notes TEXT",
    "ALTER TABLE contracts ADD COLUMN broker_id INTEGER",
    "ALTER TABLE contracts ADD COLUMN representative_attestation REAL",
    "ALTER TABLE brokers ADD COLUMN address TEXT",
    "ALTER TABLE brokers ADD COLUMN status TEXT DEFAULT 'active'",
    "ALTER TABLE brokers ADD COLUMN notes TEXT"
  ];
  
  newColumns.forEach(sql => {
    db.run(sql, (err) => {
      if (err && !err.message.includes('duplicate column name')) {
        console.error('Error adding column:', err);
      }
    });
  });

  // إضافة أعمدة جديدة إذا لم تكن موجودة
  const newBuildingsColumns = [
    'ALTER TABLE buildings ADD COLUMN documents TEXT',
    'ALTER TABLE buildings ADD COLUMN created_by_name TEXT',
    'ALTER TABLE buildings ADD COLUMN created_by_username TEXT',
    'ALTER TABLE units ADD COLUMN documents TEXT',
    'ALTER TABLE units ADD COLUMN created_by_name TEXT',
    'ALTER TABLE units ADD COLUMN created_by_username TEXT',
    'ALTER TABLE units ADD COLUMN rent_value REAL',
    'ALTER TABLE units ADD COLUMN tenant_name TEXT',
    'ALTER TABLE units ADD COLUMN tenant_phone TEXT',
    'ALTER TABLE units ADD COLUMN tenant_email TEXT',
    'ALTER TABLE units ADD COLUMN electricity_account TEXT',
    'ALTER TABLE units ADD COLUMN water_account TEXT',
    'ALTER TABLE units ADD COLUMN contract_start_date TEXT',
    'ALTER TABLE units ADD COLUMN contract_end_date TEXT',
    'ALTER TABLE payments ADD COLUMN documents TEXT',
    'ALTER TABLE payments ADD COLUMN created_by_name TEXT',
    'ALTER TABLE payments ADD COLUMN created_by_username TEXT',
    'ALTER TABLE invoices ADD COLUMN documents TEXT',
    'ALTER TABLE invoices ADD COLUMN created_by_name TEXT',
    'ALTER TABLE invoices ADD COLUMN created_by_username TEXT'
  ];
  
  newBuildingsColumns.forEach(columnQuery => {
    db.run(columnQuery, (err) => {
      if (err && !err.message.includes('duplicate column name')) {
        console.error('Error adding column:', err);
      }
    });
  });
});

// Routes for pages
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'login.html'));
});

app.get('/users', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'users.html'));
});

app.get('/test-company-work', (req, res) => {
  res.sendFile(path.join(__dirname, 'test-company-work.html'));
});

app.get('/company-work-simple', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'company-work-simple.html'));
});

app.get('/company-work-fixed', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'company-work-fixed.html'));
});

app.use(express.static(path.join(__dirname, 'frontend'), {
  maxAge: '1h', // cache for 1 hour
  etag: true,
  lastModified: true
}));

// إضافة عقد جديد مع رقم تسلسلي تلقائي
app.post('/api/contract', upload.any(), (req, res) => {
  console.log('=== CONTRACT SAVE REQUEST ===');
  console.log('Received contract data:', req.body);
  console.log('Received files:', req.files);
  console.log('Request headers:', req.headers);
  
  const {
    clientName, clientPhone, clientEmail, unitNumber, rentValue, installments, insurance, officeCommission, serviceFees,
    municipalityFile, municipalityDate, municipalityNotes, terms, onlineFees, electricityFees, waterFees,
    brokerName, totalCommission, commissionDeduction, attestationValueInternal, attestationDeduction, 
    representativeCommission, officeCommissionInternal, internalNotes, representativeAttestation, documentsNotes
  } = req.body;
  
  // التحقق من البيانات المطلوبة
  if (!clientName || !clientPhone || !unitNumber || !rentValue || !installments || !terms) {
    return res.status(400).json({error: 'جميع الحقول المطلوبة يجب أن تكون مملوءة'});
  }
  
  const now = new Date();
  const contract_date = now.toLocaleDateString('ar-EG');
  const created_at = now.toLocaleString('ar-EG');
  
  // إنشاء رقم تسلسلي: سنة-شهر-يوم-تسلسل
  const year = now.getFullYear();
  const month = (now.getMonth() + 1).toString().padStart(2, '0');
  const day = now.getDate().toString().padStart(2, '0');
  const datePrefix = `${year}${month}${day}`;
  
  // جلب آخر تسلسل لنفس اليوم
  console.log('Looking for existing contracts with prefix:', datePrefix);
  db.get('SELECT contract_number FROM contracts WHERE contract_number LIKE ? ORDER BY id DESC LIMIT 1', [`${datePrefix}%`], (err, row) => {
    if (err) {
      console.error('Error getting last contract number:', err);
      return res.status(500).json({error: 'خطأ في إنشاء رقم العقد'});
    }
    let nextSeq = 1;
    if (row && row.contract_number) {
      const parts = row.contract_number.split('-');
      if (parts.length === 2) {
        nextSeq = parseInt(parts[1]) + 1;
      }
    }
    const contractNumber = `${datePrefix}-${nextSeq.toString().padStart(3, '0')}`;
    
    console.log('Contract number generated:', contractNumber);
    console.log('About to insert contract with data:', {
      contractNumber, clientName, clientPhone, clientEmail, unitNumber, rentValue, installments, insurance, officeCommission, serviceFees,
      municipalityFile, municipalityDate, municipalityNotes, terms, onlineFees, electricityFees, waterFees,
      brokerName, totalCommission, commissionDeduction, attestationValueInternal, attestationDeduction,
      representativeCommission, officeCommissionInternal, internalNotes, representativeAttestation, contract_date, created_at
    });
    
    // معالجة الملفات المرفقة
    const files = req.files || [];
    console.log('Received files:', files.map(f => ({ fieldname: f.fieldname, filename: f.filename })));
    
    const identityDocument = files.find(f => f.fieldname === 'identityDocument')?.filename || null;
    const passportDocument = files.find(f => f.fieldname === 'passportDocument')?.filename || null;
    const addressDocument = files.find(f => f.fieldname === 'addressDocument')?.filename || null;
    const incomeDocument = files.find(f => f.fieldname === 'incomeDocument')?.filename || null;
    const additionalDocuments = files.filter(f => f.fieldname === 'additionalDocuments').map(f => f.filename).join(',') || null;
    
    // إنشاء استعلام INSERT مع الحقول الجديدة
    const insertQuery = `
      INSERT INTO contracts (
        contract_number, client_name, client_phone, client_email, unit_number, rent_value, installments, insurance, office_commission, service_fees,
        municipality_file, municipality_date, municipality_notes, terms, online_fees, electricity_fees, water_fees, 
        broker_name, broker_name_unit, clearance_name, clearance_value, total_commission, commission_deduction, attestation_value, attestation_deduction, 
        representative_commission, representative_commission_unit, office_commission_internal, internal_notes, representative_attestation, broker_id, contract_date, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    
    const insertValues = [
      contractNumber, clientName, clientPhone, clientEmail, unitNumber, rentValue, installments, insurance, officeCommission, serviceFees,
      municipalityFile, municipalityDate, municipalityNotes, terms, onlineFees, electricityFees, waterFees,
      brokerName, req.body.brokerNameUnit || null, req.body.clearanceName || null, req.body.clearanceValue || null, totalCommission, commissionDeduction, attestationValueInternal, attestationDeduction,
      representativeCommission, req.body.representativeCommissionUnit || null, officeCommissionInternal, internalNotes, null, contract_date, created_at
    ];
    
    console.log('Insert query:', insertQuery);
    console.log('Insert values count:', insertValues.length);
    console.log('Insert values:', insertValues);
    
    db.run(insertQuery, insertValues,
      function(err) {
        if (err) {
          console.error('DB Error:', err);
          console.error('Error details:', err.message);
          return res.status(500).json({error: err.message});
        }
        console.log('Contract saved successfully with ID:', this.lastID);
        
        // إذا كان هناك مستندات، قم بتحديث العقد لحفظ المستندات
        if (identityDocument || passportDocument || addressDocument || incomeDocument || additionalDocuments || documentsNotes) {
          const updateQuery = `
            UPDATE contracts SET 
              identity_document = ?, 
              passport_document = ?, 
              address_document = ?, 
              income_document = ?, 
              additional_documents = ?, 
              documents_notes = ?
            WHERE id = ?
          `;
          
          const updateValues = [
            identityDocument, passportDocument, addressDocument, incomeDocument, additionalDocuments, documentsNotes, this.lastID
          ];
          
          db.run(updateQuery, updateValues, (updateErr) => {
            if (updateErr) {
              console.error('Error updating documents:', updateErr);
            } else {
              console.log('Documents updated successfully');
            }
            res.json({success: true, contract_number: contractNumber, created_at: created_at, id: this.lastID});
          });
        } else {
          res.json({success: true, contract_number: contractNumber, created_at: created_at, id: this.lastID});
        }
      }
    );
  });
});

// جلب جميع العقود مع البحث
app.get('/api/contracts', (req, res) => {
  const q = req.query.q ? `%${req.query.q}%` : null;
  let sql = `
    SELECT c.id, c.contract_number, c.client_name, c.unit_number, c.rent_value, c.contract_date
    FROM contracts c
  `;
  let params = [];
  if (q) {
    sql += ' WHERE c.contract_number LIKE ? OR c.client_name LIKE ? OR c.unit_number LIKE ?';
    params = [q, q, q];
  }
  sql += ' ORDER BY c.id DESC';
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

// جلب عقد واحد
app.get('/api/contract/:id', (req, res) => {
  db.get(`
    SELECT c.*
    FROM contracts c 
    WHERE c.id = ?
  `, [req.params.id], (err, row) => {
    if (err) return res.status(500).json({error: err.message});
    if (!row) return res.status(404).json({error: 'عقد غير موجود'});
    res.json(row);
  });
});

// تحديث عقد
app.put('/api/contract/:id', (req, res) => {
  const {
    clientName, clientPhone, clientEmail, unitNumber, rentValue, installments, insurance, officeCommission, serviceFees,
    municipalityFile, municipalityDate, municipalityNotes, terms, onlineFees, electricityFees, waterFees,
    brokerName, brokerNameUnit, clearanceName, clearanceValue, totalCommission, commissionDeduction, attestationValueInternal, attestationDeduction, 
    representativeCommission, representativeCommissionUnit, representativeAttestation, officeCommissionInternal, internalNotes
  } = req.body;
  
  // التحقق من البيانات المطلوبة
  if (!clientName || !clientPhone || !unitNumber || !rentValue || !installments || !terms) {
    return res.status(400).json({error: 'جميع الحقول المطلوبة يجب أن تكون مملوءة'});
  }
  
  const now = new Date().toLocaleString('ar-EG');
  
  db.run(
    `UPDATE contracts SET 
      client_name = ?, client_phone = ?, client_email = ?, unit_number = ?, rent_value = ?, 
      installments = ?, insurance = ?, office_commission = ?, service_fees = ?,
      municipality_file = ?, municipality_date = ?, municipality_notes = ?, terms = ?, 
      online_fees = ?, electricity_fees = ?, water_fees = ?,
      broker_name = ?, broker_name_unit = ?, clearance_name = ?, clearance_value = ?, total_commission = ?, commission_deduction = ?, attestation_value = ?, 
      attestation_deduction = ?, representative_commission = ?, representative_commission_unit = ?, representative_attestation = ?, office_commission_internal = ?, 
      internal_notes = ?, broker_id = ?, created_at = ?
    WHERE id = ?`,
    [clientName, clientPhone, clientEmail, unitNumber, rentValue, installments, insurance, officeCommission, serviceFees,
      municipalityFile, municipalityDate, municipalityNotes, terms, onlineFees, electricityFees, waterFees,
      brokerName, brokerNameUnit || null, clearanceName || null, clearanceValue || null, totalCommission, commissionDeduction, attestationValueInternal, attestationDeduction,
      representativeCommission, representativeCommissionUnit || null, representativeAttestation, officeCommissionInternal, internalNotes, null, now, req.params.id],
    function(err) {
      if (err) {
        console.error('DB Error (contract update):', err);
        return res.status(500).json({error: err.message});
      }
      res.json({success: true, message: 'تم تحديث العقد بنجاح'});
    }
  );
});

// حذف عقد
app.delete('/api/contract/:id', (req, res) => {
  db.run('DELETE FROM contracts WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({error: err.message});
    res.json({success: true});
  });
});

// إضافة سند قبض/صرف
app.post('/api/receipt', (req, res) => {
  const { type, value, description, client_name } = req.body;
  const date = new Date().toLocaleDateString('ar-EG');
  db.run(
    `INSERT INTO receipts (type, value, description, date, client_name) VALUES (?, ?, ?, ?, ?)` ,
    [type, value, description, date, client_name],
    function(err) {
      if (err) return res.status(500).json({error: err.message});
      res.json({success: true, id: this.lastID});
    }
  );
});

// جلب جميع السندات مع بحث
app.get('/api/receipts', (req, res) => {
  const q = req.query.q ? `%${req.query.q}%` : null;
  let sql = 'SELECT * FROM receipts';
  let params = [];
  if (q) {
    sql += ' WHERE client_name LIKE ? OR description LIKE ?';
    params = [q, q];
  }
  sql += ' ORDER BY id DESC';
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

// جلب سند واحد
app.get('/api/receipt/:id', (req, res) => {
  db.get('SELECT * FROM receipts WHERE id = ?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({error: err.message});
    if (!row) return res.status(404).json({error: 'سند غير موجود'});
    res.json(row);
  });
});

// حذف سند
app.delete('/api/receipt/:id', (req, res) => {
  db.run('DELETE FROM receipts WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({error: err.message});
    res.json({success: true});
  });
});

// إضافة عقد مبدئي مع رقم تسلسلي شهر-سنة-تسلسل
app.post('/api/precontract', (req, res) => {
  const { client_name, unit_number, rent_value, payments, insurance, phone, email, office_commission, admin_expenses, online_value, sanitation, extra_electricity, details } = req.body;
  const now = new Date();
  const month = (now.getMonth() + 1).toString().padStart(2, '0');
  const year = now.getFullYear().toString().slice(-2);
  // جلب آخر تسلسل لنفس الشهر والسنة
  db.get('SELECT contract_number FROM precontracts WHERE contract_number LIKE ? ORDER BY id DESC LIMIT 1', [`${month}-${year}-%`], (err, row) => {
    let nextSeq = 1;
    if (row && row.contract_number) {
      const parts = row.contract_number.split('-');
      if (parts.length === 3) nextSeq = parseInt(parts[2]) + 1;
    }
    const contract_number = `${month}-${year}-${nextSeq.toString().padStart(5, '0')}`;
    const created_at = now.toLocaleString('ar-EG');
    db.run(
      `INSERT INTO precontracts (contract_number, client_name, unit_number, rent_value, payments, insurance, phone, email, office_commission, admin_expenses, online_value, sanitation, extra_electricity, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)` ,
      [contract_number, client_name, unit_number, rent_value, payments, insurance, phone, email, office_commission, admin_expenses, online_value, sanitation, extra_electricity, details, created_at],
      function(err) {
        if (err) {
          console.error('DB Error (precontract add):', err, req.body);
          return res.status(500).json({error: err.message});
        }
        res.json({success: true, id: this.lastID, contract_number});
      }
    );
  });
});

// جلب جميع العقود المبدئية
app.get('/api/precontracts', (req, res) => {
  db.all('SELECT * FROM precontracts ORDER BY id DESC', [], (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

// حذف عقد مبدئي
app.delete('/api/precontract/:id', (req, res) => {
  db.run('DELETE FROM precontracts WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({error: err.message});
    res.json({success: true});
  });
});

// تحديث عقد مبدئي جزئيًا (متتابع)
app.patch('/api/precontract/:id', (req, res) => {
  const fields = req.body;
  const allowed = [
    'client_name','unit_number','rent_value','payments','insurance','phone','email','office_commission','admin_expenses','online_value','sanitation','extra_electricity','details'
  ];
  const updates = [];
  const values = [];
  for (const key of allowed) {
    if (fields[key] !== undefined) {
      updates.push(`${key} = ?`);
      values.push(fields[key]);
    }
  }
  if (!updates.length) return res.status(400).json({error: 'لا يوجد بيانات للتحديث'});
  values.push(req.params.id);
  db.run(`UPDATE precontracts SET ${updates.join(', ')} WHERE id = ?`, values, function(err) {
    if (err) return res.status(500).json({error: err.message});
    res.json({success: true});
  });
});

// لوحة التحكم الرئيسية
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});
// صفحة العقود
app.get('/contracts', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'contracts.html'));
});
// صفحة السندات
app.get('/receipts', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'receipts.html'));
});
// صفحة العقود المبدئية
app.get('/precontracts', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'precontracts.html'));
});

// صفحة استعراض العقود
app.get('/view-contracts', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'view-contracts.html'));
});

// صفحة شغل الشركة
app.get('/company-work', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'company-work.html'));
});

// صفحة العقارات
app.get('/properties', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'properties.html'));
});

app.get('/my-properties', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'my-properties.html'));
});

app.get('/payment-status', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'payment-status.html'));
});

// ===== نظام الوسطاء الجديد =====

// إضافة وسيط جديد
app.post('/api/brokers', (req, res) => {
  const { name, phone, email, commission_rate, address, status, notes } = req.body;
  
  if (!name) {
    return res.status(400).json({error: 'اسم الوسيط مطلوب'});
  }
  
  const now = new Date().toLocaleString('ar-EG');
  db.run(
    'INSERT INTO brokers (name, phone, email, commission_rate, address, status, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [name, phone || '', email || '', commission_rate || 0, address || '', status || 'active', notes || '', now, now],
    function(err) {
      if (err) {
        console.error('DB Error (broker add):', err);
        return res.status(500).json({error: err.message});
      }
      res.json({success: true, id: this.lastID});
    }
  );
});

// جلب جميع الوسطاء
app.get('/api/brokers', (req, res) => {
  db.all('SELECT * FROM brokers ORDER BY name', [], (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

// جلب وسيط واحد
app.get('/api/brokers/:id', (req, res) => {
  db.get('SELECT * FROM brokers WHERE id = ?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({error: err.message});
    if (!row) return res.status(404).json({error: 'وسيط غير موجود'});
    res.json(row);
  });
});

// تحديث وسيط
app.put('/api/brokers/:id', (req, res) => {
  const { name, phone, email, commission_rate, address, status, notes } = req.body;
  const now = new Date().toLocaleString('ar-EG');
  
  db.run(
    'UPDATE brokers SET name = ?, phone = ?, email = ?, commission_rate = ?, address = ?, status = ?, notes = ?, updated_at = ? WHERE id = ?',
    [name, phone || '', email || '', commission_rate || 0, address || '', status || 'active', notes || '', now, req.params.id],
    function(err) {
      if (err) return res.status(500).json({error: err.message});
      res.json({success: true});
    }
  );
});

// حذف وسيط
app.delete('/api/brokers/:id', (req, res) => {
  db.run('DELETE FROM brokers WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({error: err.message});
    res.json({success: true});
  });
});

// ===== نظام التخليص =====

// جلب جميع التخليصات
app.get('/api/clearances', (req, res) => {
  db.all('SELECT * FROM clearances ORDER BY name', (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

// إضافة تخليص جديد
app.post('/api/clearances', (req, res) => {
  const { name, phone, email, commission_rate } = req.body;
  
  if (!name) {
    return res.status(400).json({error: 'اسم التخليص مطلوب'});
  }
  
  const now = new Date().toLocaleString('ar-EG');
  db.run(
    'INSERT INTO clearances (name, phone, email, commission_rate, created_at) VALUES (?, ?, ?, ?, ?)',
    [name, phone || '', email || '', commission_rate || 0, now],
    function(err) {
      if (err) {
        console.error('DB Error (clearance add):', err);
        return res.status(500).json({error: err.message});
      }
      res.json({success: true, id: this.lastID});
    }
  );
});

// جلب تخليص واحد
app.get('/api/clearances/:id', (req, res) => {
  db.get('SELECT * FROM clearances WHERE id = ?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({error: err.message});
    if (!row) return res.status(404).json({error: 'تخليص غير موجود'});
    res.json(row);
  });
});

// تحديث تخليص
app.put('/api/clearances/:id', (req, res) => {
  const { name, phone, email, commission_rate } = req.body;
  const now = new Date().toLocaleString('ar-EG');
  
  db.run(
    'UPDATE clearances SET name = ?, phone = ?, email = ?, commission_rate = ?, created_at = ? WHERE id = ?',
    [name, phone || '', email || '', commission_rate || 0, now, req.params.id],
    function(err) {
      if (err) return res.status(500).json({error: err.message});
      res.json({success: true});
    }
  );
});

// حذف تخليص
app.delete('/api/clearances/:id', (req, res) => {
  db.run('DELETE FROM clearances WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({error: err.message});
    res.json({success: true});
  });
});

// إضافة معاملة وسيط
app.post('/api/broker-transactions', (req, res) => {
  const { 
    broker_id, contract_number, client_name, unit_number, rent_value, commission_amount, 
    total_commission, commission_deduction, attestation_value, attestation_deduction,
    representative_commission, office_commission_internal, transaction_date, notes 
  } = req.body;
  
  if (!contract_number || !client_name) {
    return res.status(400).json({error: 'بيانات المعاملة مطلوبة'});
  }
  
  const now = new Date().toLocaleString('ar-EG');
  db.run(
    `INSERT INTO broker_transactions (
      broker_id, contract_number, client_name, unit_number, rent_value, commission_amount,
      total_commission, commission_deduction, attestation_value, attestation_deduction,
      representative_commission, office_commission_internal, transaction_date, notes, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      broker_id || null, contract_number, client_name, unit_number, rent_value, commission_amount,
      total_commission || 0, commission_deduction || 0, attestation_value || 0, attestation_deduction || 0,
      representative_commission || 0, office_commission_internal || 0, transaction_date || now, notes, now
    ],
    function(err) {
      if (err) {
        console.error('DB Error (transaction add):', err);
        return res.status(500).json({error: err.message});
      }
      res.json({success: true, id: this.lastID});
    }
  );
});

// جلب معاملات وسيط معين
app.get('/api/broker-transactions/:brokerId', (req, res) => {
  if (req.params.brokerId === 'null' || req.params.brokerId === 'undefined') {
    // جلب المعاملات التي ليس لها broker_id (تم إدخالها يدوياً)
    db.all('SELECT * FROM broker_transactions WHERE broker_id IS NULL ORDER BY created_at DESC', [], (err, rows) => {
      if (err) return res.status(500).json({error: err.message});
      res.json(rows);
    });
  } else {
    // جلب معاملات وسيط معين
    db.all('SELECT * FROM broker_transactions WHERE broker_id = ? ORDER BY created_at DESC', [req.params.brokerId], (err, rows) => {
      if (err) return res.status(500).json({error: err.message});
      res.json(rows);
    });
  }
});

// جلب جميع المعاملات
app.get('/api/broker-transactions', (req, res) => {
  db.all(`
    SELECT bt.*, b.name as broker_name 
    FROM broker_transactions bt 
    LEFT JOIN brokers b ON bt.broker_id = b.id 
    ORDER BY bt.created_at DESC
  `, [], (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

// حذف معاملة
app.delete('/api/broker-transactions/:id', (req, res) => {
  db.run('DELETE FROM broker_transactions WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({error: err.message});
    res.json({success: true});
  });
});

// إحصائيات الوسطاء
app.get('/api/brokers-stats', (req, res) => {
  db.all(`
    SELECT 
      b.id,
      b.name,
      b.commission_rate,
      COUNT(bt.id) as total_transactions,
      COALESCE(SUM(bt.rent_value), 0) as total_rent_value,
      COALESCE(SUM(bt.commission_amount), 0) as total_commission,
      COALESCE(SUM(bt.total_commission), 0) as total_broker_commission,
      COALESCE(SUM(bt.commission_deduction), 0) as total_commission_deduction,
      COALESCE(SUM(bt.attestation_value), 0) as total_attestation_value,
      COALESCE(SUM(bt.attestation_deduction), 0) as total_attestation_deduction,
      COALESCE(SUM(bt.representative_commission), 0) as total_representative_commission,
      COALESCE(SUM(bt.office_commission_internal), 0) as total_office_commission_internal,
      b.status
    FROM brokers b
    LEFT JOIN broker_transactions bt ON b.id = bt.broker_id
    GROUP BY b.id, b.name, b.commission_rate, b.status
    ORDER BY total_commission DESC
  `, [], (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

// جلب عمولات الوسطاء من جدول العقود
app.get('/api/broker-commissions', (req, res) => {
  db.all(`
    SELECT 
      id,
      contract_number,
      broker_name,
      unit_number,
      client_name,
      client_phone,
      rent_value,
      total_commission,
      commission_deduction,
      attestation_value,
      attestation_deduction,
      representative_commission,
      representative_attestation,
      office_commission_internal,
      contract_date,
      created_at
    FROM contracts 
    WHERE broker_name IS NOT NULL 
       AND broker_name != ''
       AND (
         (total_commission IS NOT NULL AND total_commission > 0) 
         OR (representative_commission IS NOT NULL AND representative_commission > 0)
         OR (representative_attestation IS NOT NULL AND representative_attestation > 0)
         OR (commission_deduction IS NOT NULL AND commission_deduction > 0)
         OR (attestation_value IS NOT NULL AND attestation_value > 0)
         OR (attestation_deduction IS NOT NULL AND attestation_deduction > 0)
         OR (office_commission_internal IS NOT NULL AND office_commission_internal > 0)
       )
    ORDER BY created_at DESC
  `, [], (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

// Route for broker commissions page
app.get('/broker-commissions', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'broker-commissions.html'));
});

// API endpoint لتقارير الوسطاء
app.get('/api/broker-reports/:brokerId', (req, res) => {
  const brokerId = req.params.brokerId;
  
  if (brokerId === 'all') {
    // تقرير شامل لجميع الوسطاء
    const query = `
      SELECT 
        c.id,
        c.contract_number,
        c.broker_name,
        c.client_name,
        c.unit_number,
        c.rent_value,
        c.total_commission,
        c.commission_deduction,
        c.attestation_value,
        c.attestation_deduction,
        c.representative_commission,
        c.representative_attestation,
        c.office_commission_internal,
        c.contract_date,
        c.created_at,
        b.name as broker_full_name,
        b.phone as broker_phone,
        b.email as broker_email,
        b.commission_rate as broker_commission_rate
      FROM contracts c
      LEFT JOIN brokers b ON c.broker_id = b.id
      WHERE (c.broker_name IS NOT NULL AND c.broker_name != '')
         OR c.broker_id IS NOT NULL
      ORDER BY c.contract_date DESC
    `;
    
    db.all(query, [], (err, rows) => {
      if (err) {
        console.error('Error in broker reports (all):', err);
        return res.status(500).json({error: err.message});
      }
      res.json(rows);
    });
  } else {
    // تقرير لوسيط محدد
    // أولاً، احصل على اسم الوسيط
    db.get('SELECT name FROM brokers WHERE id = ?', [brokerId], (err, broker) => {
      if (err) {
        console.error('Error getting broker:', err);
        return res.status(500).json({error: err.message});
      }
      
      if (!broker) {
        return res.json([]);
      }
      
      // الآن ابحث عن العقود التي تخص هذا الوسيط فقط
      const query = `
        SELECT 
          c.id,
          c.contract_number,
          c.broker_name,
          c.client_name,
          c.unit_number,
          c.rent_value,
          c.total_commission,
          c.commission_deduction,
          c.attestation_value,
          c.attestation_deduction,
          c.representative_commission,
          c.representative_attestation,
          c.office_commission_internal,
          c.contract_date,
          c.created_at,
          b.name as broker_full_name,
          b.phone as broker_phone,
          b.email as broker_email,
          b.commission_rate as broker_commission_rate
        FROM contracts c
        LEFT JOIN brokers b ON c.broker_id = b.id
        WHERE c.broker_id = ? OR c.broker_name = ?
        ORDER BY c.contract_date DESC
      `;
      
      db.all(query, [brokerId, broker.name], (err, rows) => {
        if (err) {
          console.error('Error in broker reports (specific):', err);
          return res.status(500).json({error: err.message});
        }
        
        res.json(rows);
      });
    });
  }
});

// API endpoint لإحصائيات الوسطاء
app.get('/api/broker-statistics/:brokerId', (req, res) => {
  const brokerId = req.params.brokerId;
  
  if (brokerId === 'all') {
    // إحصائيات شاملة
    const query = `
      SELECT 
        COUNT(*) as total_contracts,
        COALESCE(SUM(c.rent_value), 0) as total_rent_value,
        COALESCE(SUM(c.total_commission), 0) as total_commission,
        COALESCE(SUM(c.commission_deduction), 0) as total_commission_deduction,
        COALESCE(SUM(c.attestation_value), 0) as total_attestation_value,
        COALESCE(SUM(c.attestation_deduction), 0) as total_attestation_deduction,
        COALESCE(SUM(c.representative_commission), 0) as total_representative_commission,
        COALESCE(SUM(c.representative_attestation), 0) as total_representative_attestation,
        COALESCE(SUM(c.office_commission_internal), 0) as total_office_commission,
        COALESCE(SUM(
          COALESCE(c.total_commission, 0) - COALESCE(c.commission_deduction, 0) + 
          COALESCE(c.attestation_value, 0) - COALESCE(c.attestation_deduction, 0)
        ), 0) as net_commission
      FROM contracts c
      WHERE (c.broker_name IS NOT NULL AND c.broker_name != '')
         OR c.broker_id IS NOT NULL
    `;
    
    db.get(query, [], (err, row) => {
      if (err) {
        console.error('Error in broker statistics (all):', err);
        return res.status(500).json({error: err.message});
      }
      res.json(row);
    });
  } else {
    // إحصائيات لوسيط محدد
    // أولاً، احصل على اسم الوسيط
    db.get('SELECT name FROM brokers WHERE id = ?', [brokerId], (err, broker) => {
      if (err) {
        console.error('Error getting broker:', err);
        return res.status(500).json({error: err.message});
      }
      
      if (!broker) {
        return res.json({
          total_contracts: 0,
          total_rent_value: 0,
          total_commission: 0,
          total_commission_deduction: 0,
          total_attestation_value: 0,
          total_attestation_deduction: 0,
          total_representative_commission: 0,
          total_representative_attestation: 0,
          total_office_commission: 0,
          net_commission: 0
        });
      }
      
      // الآن ابحث عن إحصائيات هذا الوسيط فقط
      const query = `
        SELECT 
          COUNT(*) as total_contracts,
          COALESCE(SUM(c.rent_value), 0) as total_rent_value,
          COALESCE(SUM(c.total_commission), 0) as total_commission,
          COALESCE(SUM(c.commission_deduction), 0) as total_commission_deduction,
          COALESCE(SUM(c.attestation_value), 0) as total_attestation_value,
          COALESCE(SUM(c.attestation_deduction), 0) as total_attestation_deduction,
          COALESCE(SUM(c.representative_commission), 0) as total_representative_commission,
          COALESCE(SUM(c.representative_attestation), 0) as total_representative_attestation,
          COALESCE(SUM(c.office_commission_internal), 0) as total_office_commission,
          COALESCE(SUM(
            COALESCE(c.total_commission, 0) - COALESCE(c.commission_deduction, 0) + 
            COALESCE(c.attestation_value, 0) - COALESCE(c.attestation_deduction, 0)
          ), 0) as net_commission
        FROM contracts c
        WHERE c.broker_id = ? OR c.broker_name = ?
      `;
      
      db.get(query, [brokerId, broker.name], (err, row) => {
        if (err) {
          console.error('Error in broker statistics (specific):', err);
          return res.status(500).json({error: err.message});
        }
        
        res.json(row);
      });
    });
  }
});

// ===== نظام السندات الجديد =====

// إنشاء جدول السندات إذا لم يكن موجوداً
db.run(`
  CREATE TABLE IF NOT EXISTS receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_number TEXT UNIQUE,
    type TEXT NOT NULL,
    value REAL NOT NULL,
    client_name TEXT NOT NULL,
    phone TEXT,
    description TEXT,
    payment_method TEXT,
    reference_number TEXT,
    date TEXT NOT NULL,
    time TEXT,
    created_at TEXT NOT NULL
  )
`, (err) => {
  if (err) {
    console.error('Error creating receipts table:', err);
  } else {
    console.log('Receipts table ready');
  }
});

// ===== نظام العقارات الجديد =====

// إنشاء جدول العقارات إذا لم يكن موجوداً
db.run(`
  CREATE TABLE IF NOT EXISTS properties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_type TEXT NOT NULL,
    unit_type TEXT NOT NULL,
    price REAL NOT NULL,
    installments INTEGER,
    insurance REAL,
    external_commission REAL,
    online_commission REAL,
    management TEXT,
    location TEXT,
    description TEXT,
    rooms INTEGER,
    bathrooms INTEGER,
    area REAL,
    floor TEXT,
    documents TEXT,
    created_by INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )
`, (err) => {
  if (err) {
    console.error('Error creating properties table:', err);
  } else {
    console.log('Properties table ready');
  }
});

// إضافة أعمدة جديدة إذا لم تكن موجودة
const newPropertiesColumns = [
  'ALTER TABLE properties ADD COLUMN created_by_name TEXT',
  'ALTER TABLE properties ADD COLUMN created_by_username TEXT',
  'ALTER TABLE properties ADD COLUMN created_date TEXT',
  'ALTER TABLE properties ADD COLUMN created_time TEXT',
  'ALTER TABLE properties ADD COLUMN contact_phone TEXT',
  'ALTER TABLE properties ADD COLUMN contact_name TEXT',
  'ALTER TABLE properties ADD COLUMN insurance_method TEXT',
  'ALTER TABLE properties ADD COLUMN insurance_notes TEXT'
];

newPropertiesColumns.forEach(columnQuery => {
  db.run(columnQuery, (err) => {
    if (err && !err.message.includes('duplicate column name')) {
      console.error('Error adding column:', err);
    }
  });
});

// إضافة سند جديد
app.post('/api/receipt', (req, res) => {
  const {
    type, value, client_name, phone, description, 
    payment_method, reference_number
  } = req.body;

  if (!type || !value || !client_name || !description) {
    return res.status(400).json({error: 'جميع الحقول المطلوبة يجب أن تكون مملوءة'});
  }

  const now = new Date();
  const date = now.toLocaleDateString('ar-EG');
  const time = now.toLocaleTimeString('ar-EG');
  const created_at = now.toLocaleString('ar-EG');

  // إنشاء رقم تسلسلي للسند: سنة-شهر-يوم-تسلسل
  const year = now.getFullYear();
  const month = (now.getMonth() + 1).toString().padStart(2, '0');
  const day = now.getDate().toString().padStart(2, '0');
  const datePrefix = `${year}${month}${day}`;

  // جلب آخر تسلسل لنفس اليوم
  db.get('SELECT receipt_number FROM receipts WHERE receipt_number LIKE ? ORDER BY id DESC LIMIT 1', [`${datePrefix}%`], (err, row) => {
    if (err) {
      console.error('Error getting last receipt number:', err);
      return res.status(500).json({error: 'خطأ في إنشاء رقم السند'});
    }

    let nextSeq = 1;
    if (row && row.receipt_number) {
      const parts = row.receipt_number.split('-');
      if (parts.length === 2) {
        nextSeq = parseInt(parts[1]) + 1;
      }
    }
    const receiptNumber = `${datePrefix}-${nextSeq.toString().padStart(3, '0')}`;

    const insertQuery = `
      INSERT INTO receipts (
        receipt_number, type, value, client_name, phone, description, 
        payment_method, reference_number, date, time, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const insertValues = [
      receiptNumber, type, value, client_name, phone || null, description,
      payment_method || null, reference_number || null, date, time, created_at
    ];

    db.run(insertQuery, insertValues, function(err) {
      if (err) {
        console.error('DB Error:', err);
        return res.status(500).json({error: 'خطأ في حفظ السند'});
      }
      res.json({
        success: true,
        id: this.lastID,
        receipt_number: receiptNumber
      });
    });
  });
});

// جلب جميع السندات
app.get('/api/receipts', (req, res) => {
  const query = req.query.q;
  let sql = 'SELECT * FROM receipts ORDER BY created_at DESC';
  let params = [];

  if (query) {
    sql = `
      SELECT * FROM receipts 
      WHERE client_name LIKE ? OR description LIKE ? 
      ORDER BY created_at DESC
    `;
    params = [`%${query}%`, `%${query}%`];
  }

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

// جلب سند واحد
app.get('/api/receipt/:id', (req, res) => {
  db.get('SELECT * FROM receipts WHERE id = ?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({error: err.message});
    if (!row) return res.status(404).json({error: 'السند غير موجود'});
    res.json(row);
  });
});

// حذف سند
app.delete('/api/receipt/:id', (req, res) => {
  db.run('DELETE FROM receipts WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({error: err.message});
    res.json({success: true});
  });
});

// إحصائيات السندات
app.get('/api/receipts-stats', (req, res) => {
  db.all(`
    SELECT 
      COUNT(*) as total_receipts,
      SUM(CASE WHEN type = 'قبض' THEN value ELSE 0 END) as total_receipt_amount,
      SUM(CASE WHEN type = 'صرف' THEN value ELSE 0 END) as total_payment_amount,
      SUM(CASE WHEN type = 'قبض' THEN value ELSE -value END) as balance
    FROM receipts
  `, [], (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows[0] || {
      total_receipts: 0,
      total_receipt_amount: 0,
      total_payment_amount: 0,
      balance: 0
    });
  });
});

// ===== API العقارات =====

// إضافة عقار جديد
app.post('/api/properties', upload.any(), (req, res, next) => {
  try {
    const {
      operationType, unitType, price, installments, insurance, insuranceMethod, insuranceNotes,
      externalCommission, onlineCommission, management, location, description,
      rooms, bathrooms, area, floor, contactPhone, contactName
    } = req.body;

    // التحقق من البيانات المطلوبة
    if (!operationType || !unitType || !price) {
      return res.status(400).json({error: 'نوع العملية ونوع الوحدة والسعر مطلوبة'});
    }

    // الحصول على معرف المستخدم من middleware المصادقة
    const userId = req.user.id;
    if (!userId) {
      return res.status(401).json({error: 'معرف المستخدم مطلوب'});
    }

    // جلب معلومات المستخدم
    db.get('SELECT username, full_name FROM users WHERE id = ?', [userId], (err, user) => {
      if (err) {
        console.error('Error getting user info:', err);
        return res.status(500).json({error: 'خطأ في جلب معلومات المستخدم'});
      }
      
      if (!user) {
        return res.status(404).json({error: 'المستخدم غير موجود'});
      }

      // معالجة الملفات المرفوعة
      let documents = '';
      if (req.files && req.files.length > 0) {
        documents = req.files.map(file => file.filename).join(',');
      }

      const now = new Date();
      const created_at = now.toLocaleString('ar-EG');
      const created_date = now.toLocaleDateString('ar-EG');
      const created_time = now.toLocaleTimeString('ar-EG');
    
      db.run(`
        INSERT INTO properties (
          operation_type, unit_type, price, installments, insurance, insurance_method, insurance_notes,
          external_commission, online_commission, management, location,
          description, rooms, bathrooms, area, floor, documents,
          created_by, created_by_name, created_by_username, created_date, created_time,
          contact_phone, contact_name, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        operationType, unitType, price, installments || null, insurance || null, insuranceMethod || null, insuranceNotes || null,
        externalCommission || null, onlineCommission || null, management || null,
        location || null, description || null, rooms || null, bathrooms || null,
        area || null, floor || null, documents, userId, user.full_name, user.username,
        created_date, created_time, contactPhone || null, contactName || null, created_at, created_at
      ], function(err) {
        if (err) {
          console.error('Error adding property:', err);
          return res.status(500).json({error: 'خطأ في حفظ العقار: ' + err.message});
        }
        res.json({success: true, id: this.lastID});
      });
    });
  } catch (error) {
    console.error('Unexpected error in /api/properties:', error);
    next(error);
  }
});

// جلب جميع العقارات - محسن للأداء مع cache
app.get('/api/properties', (req, res) => {
  const { priceSort, location, user, dateSort, operationType, unitType, limit = 50 } = req.query;
  
  // إنشاء cache key فريد
  const cacheKey = `properties_${JSON.stringify(req.query)}`;
  
  // التحقق من cache أولاً
  const cachedResult = cache.get(cacheKey);
  if (cachedResult) {
    return res.json(cachedResult);
  }
  
  let query = `
    SELECT p.id, p.description, p.price, p.location, p.operation_type, p.unit_type, 
           p.area, p.rooms, p.bathrooms, p.documents, p.created_at, p.created_by,
           u.full_name as owner_name, u.username as owner_username 
    FROM properties p 
    LEFT JOIN users u ON p.created_by = u.id
  `;
  let params = [];
  let conditions = [];
  
  if (operationType) {
    conditions.push('p.operation_type = ?');
    params.push(operationType);
  }
  
  if (unitType) {
    conditions.push('p.unit_type = ?');
    params.push(unitType);
  }
  
  if (location) {
    conditions.push('p.location LIKE ?');
    params.push(`%${location}%`);
  }
  
  if (user) {
    if (!isNaN(user)) {
      conditions.push('p.created_by = ?');
      params.push(parseInt(user));
    } else {
      conditions.push('(u.full_name LIKE ? OR u.username LIKE ?)');
      params.push(`%${user}%`);
      params.push(`%${user}%`);
    }
  }
  
  if (conditions.length > 0) {
    query += ' WHERE ' + conditions.join(' AND ');
  }
  
  // ترتيب النتائج مع تحسين الأداء
  let orderBy = 'p.created_at DESC';
  if (priceSort === 'asc') {
    orderBy = 'p.price ASC';
  } else if (priceSort === 'desc') {
    orderBy = 'p.price DESC';
  } else if (dateSort === 'newest') {
    orderBy = 'p.created_at DESC';
  } else if (dateSort === 'oldest') {
    orderBy = 'p.created_at ASC';
  }
  
  query += ` ORDER BY ${orderBy} LIMIT ?`;
  params.push(parseInt(limit));
  
  // إضافة cache header للاستعلامات المتكررة
  res.header('Cache-Control', 'public, max-age=300'); // 5 minutes cache
  res.header('ETag', `"${Date.now()}"`);
  
  db.all(query, params, (err, rows) => {
    if (err) {
      console.error('Properties API Error:', err);
      return res.status(500).json({error: err.message});
    }
    
    // حفظ النتيجة في cache
    cache.set(cacheKey, rows, 300000); // 5 minutes
    
    res.json(rows);
  });
});

// جلب إحصائيات العقارات
app.get('/api/properties-stats', (req, res) => {
  db.all(`
    SELECT 
      operation_type,
      unit_type,
      COUNT(*) as count
    FROM properties
    GROUP BY operation_type, unit_type
  `, [], (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    
    // تنظيم البيانات حسب النوع والفئة
    const stats = {
      rent: {},
      sale: {},
      monthly: {},
      'arabic-houses': {}
    };
    
    rows.forEach(row => {
      if (stats[row.operation_type]) {
        stats[row.operation_type][row.unit_type] = row.count;
      }
    });
    
    res.json(stats);
  });
});

// جلب عقار واحد
app.get('/api/properties/:id', (req, res) => {
  db.get(`
    SELECT p.*, 
           COALESCE(u.full_name, p.created_by_name) as created_by_name,
           COALESCE(u.username, p.created_by_username) as created_by_username,
           u.full_name as owner_name,
           u.username as owner_username
    FROM properties p
    LEFT JOIN users u ON p.created_by = u.id
    WHERE p.id = ?
  `, [req.params.id], (err, row) => {
    if (err) return res.status(500).json({error: err.message});
    if (!row) return res.status(404).json({error: 'العقار غير موجود'});
    res.json(row);
  });
});

// تحميل جميع مستندات عقار كملف ZIP
app.get('/api/download-all-documents', async (req, res) => {
  const files = req.query.files;
  
  if (!files) {
    return res.status(400).json({error: 'لا توجد ملفات للتحميل'});
  }

  const fileList = files.split(',');
  const uploadsDir = path.join(__dirname, 'uploads');
  
  // التحقق من وجود مجلد uploads
  if (!fs.existsSync(uploadsDir)) {
    return res.status(404).json({error: 'مجلد الملفات غير موجود'});
  }

  // إنشاء ملف ZIP مؤقت
  const zipPath = path.join(__dirname, 'temp_documents.zip');
  
  try {
    const JSZip = require('jszip');
    const zip = new JSZip();
    
    // إضافة الملفات للـ ZIP
    let addedFiles = 0;
    for (const filename of fileList) {
      const filePath = path.join(uploadsDir, filename.trim());
      if (fs.existsSync(filePath)) {
        const fileContent = fs.readFileSync(filePath);
        zip.file(filename.trim(), fileContent);
        addedFiles++;
      }
    }

    if (addedFiles === 0) {
      return res.status(404).json({error: 'لا توجد ملفات صالحة للتحميل'});
    }

    // إنشاء ملف ZIP
    const zipBuffer = await zip.generateAsync({type: 'nodebuffer', compression: 'DEFLATE', compressionOptions: {level: 9}});
    
    // إرسال الملف
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="مستندات_العقار.zip"');
    res.send(zipBuffer);
  } catch (error) {
    console.error('Error creating ZIP:', error);
    res.status(500).json({error: 'خطأ في إنشاء ملف ZIP'});
  }
});

// تحديث عقار
app.put('/api/properties/:id', upload.any(), (req, res, next) => {
  try {
    const propertyId = req.params.id;
    const {
      operationType, unitType, price, installments, insurance, insuranceMethod, insuranceNotes,
      externalCommission, onlineCommission, management, location, description,
      rooms, bathrooms, area, floor, contactPhone, contactName
    } = req.body;

    // الحصول على معرف المستخدم من middleware المصادقة
    const userId = req.user.id;
    if (!userId) {
      return res.status(401).json({error: 'معرف المستخدم مطلوب'});
    }

    // التحقق من أن المستخدم هو من أضاف العقار أو مدير
    db.get('SELECT created_by FROM properties WHERE id = ?', [propertyId], (err, property) => {
      if (err) {
        return res.status(500).json({error: 'خطأ في جلب بيانات العقار'});
      }
      
      if (!property) {
        return res.status(404).json({error: 'العقار غير موجود'});
      }

      // التحقق من الصلاحيات
      db.get('SELECT role FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) {
          return res.status(500).json({error: 'خطأ في التحقق من صلاحيات المستخدم'});
        }

        // السماح بالتعديل إذا كان المستخدم هو من أضاف العقار أو مدير
        if (property.created_by != userId && user.role !== 'admin') {
          return res.status(403).json({error: 'ليس لديك صلاحية لتعديل هذا العقار'});
        }

        // معالجة الملفات المرفوعة
        let documents = '';
        if (req.files && req.files.length > 0) {
          documents = req.files.map(file => file.filename).join(',');
        }

        const now = new Date().toLocaleString('ar-EG');
        
        const updateQuery = `
          UPDATE properties SET 
            operation_type = ?, unit_type = ?, price = ?, installments = ?, 
            insurance = ?, insurance_method = ?, insurance_notes = ?, external_commission = ?, online_commission = ?, 
            management = ?, location = ?, description = ?, rooms = ?, 
            bathrooms = ?, area = ?, floor = ?, contact_phone = ?, contact_name = ?, updated_at = ?
            ${documents ? ', documents = ?' : ''}
          WHERE id = ?
        `;

        const updateValues = [
          operationType, unitType, price, installments || null, insurance || null, insuranceMethod || null, insuranceNotes || null,
          externalCommission || null, onlineCommission || null, management || null,
          location || null, description || null, rooms || null, bathrooms || null,
          area || null, floor || null, contactPhone || null, contactName || null, now
        ];

        if (documents) {
          updateValues.push(documents);
        }
        updateValues.push(propertyId);

        db.run(updateQuery, updateValues, function(err) {
          if (err) {
            console.error('Error updating property:', err);
            return res.status(500).json({error: 'خطأ في تحديث العقار: ' + err.message});
          }
          res.json({success: true});
        });
      });
    });
  } catch (error) {
    console.error('Unexpected error in /api/properties/:id:', error);
    next(error);
  }
});

// جلب معلومات التواصل لعقار معين
app.get('/api/properties/:id/contact', (req, res) => {
  const propertyId = req.params.id;
  
  db.get('SELECT contact_name, contact_phone, created_by_name FROM properties WHERE id = ?', [propertyId], (err, property) => {
    if (err) {
      return res.status(500).json({error: 'خطأ في جلب معلومات التواصل'});
    }
    
    if (!property) {
      return res.status(404).json({error: 'العقار غير موجود'});
    }
    
    res.json({
      contactName: property.contact_name,
      contactPhone: property.contact_phone,
      createdByName: property.created_by_name
    });
  });
});

// حذف عقار
app.delete('/api/properties/:id', (req, res) => {
  const propertyId = req.params.id;
  const userId = req.user.id;

  if (!userId) {
    return res.status(401).json({error: 'معرف المستخدم مطلوب'});
  }

  // التحقق من أن المستخدم هو من أضاف العقار أو مدير
  db.get('SELECT created_by FROM properties WHERE id = ?', [propertyId], (err, property) => {
    if (err) {
      return res.status(500).json({error: 'خطأ في جلب بيانات العقار'});
    }
    
    if (!property) {
      return res.status(404).json({error: 'العقار غير موجود'});
    }

    // التحقق من الصلاحيات
    db.get('SELECT role FROM users WHERE id = ?', [userId], (err, user) => {
      if (err) {
        return res.status(500).json({error: 'خطأ في التحقق من صلاحيات المستخدم'});
      }

      // السماح بالحذف إذا كان المستخدم هو من أضاف العقار أو مدير
      if (property.created_by != userId && user.role !== 'admin') {
        return res.status(403).json({error: 'ليس لديك صلاحية لحذف هذا العقار'});
      }

      db.run('DELETE FROM properties WHERE id = ?', [propertyId], function(err) {
        if (err) return res.status(500).json({error: err.message});
        res.json({success: true});
      });
    });
  });
});

// ===== API إدارة المستخدمين والصلاحيات =====

// تسجيل الدخول
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({error: 'يرجى إدخال اسم المستخدم وكلمة المرور'});
  }
  
  db.get('SELECT * FROM users WHERE username = ? AND is_active = 1', [username], (err, user) => {
    if (err) return res.status(500).json({error: err.message});
    if (!user) return res.status(401).json({error: 'اسم المستخدم أو كلمة المرور غير صحيحة'});
    
    // في الإنتاج، يجب تشفير كلمة المرور
    if (user.password !== password) {
      return res.status(401).json({error: 'اسم المستخدم أو كلمة المرور غير صحيحة'});
    }
    
    // جلب صلاحيات المستخدم
    db.all('SELECT permission_name FROM user_permissions WHERE user_id = ? AND is_granted = 1', [user.id], (err, permissions) => {
      if (err) return res.status(500).json({error: err.message});
      
      const userPermissions = permissions.map(p => p.permission_name);
      
      res.json({
        success: true,
        user: {
          id: user.id,
          username: user.username,
          full_name: user.full_name,
          email: user.email,
          role: user.role,
          permissions: userPermissions
        }
      });
    });
  });
});

// إضافة مستخدم جديد
app.post('/api/users', (req, res) => {
  const { username, password, full_name, email, phone, role, permissions } = req.body;
  
  if (!username || !password || !full_name) {
    return res.status(400).json({error: 'يرجى ملء جميع الحقول المطلوبة'});
  }
  
  const now = new Date().toLocaleString('ar-EG');
  
  db.run(`
    INSERT INTO users (username, password, full_name, email, phone, role, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `, [username, password, full_name, email || null, phone || null, role || 'user', now, now], function(err) {
    if (err) {
      if (err.message.includes('UNIQUE constraint failed')) {
        return res.status(400).json({error: 'اسم المستخدم موجود مسبقاً'});
      }
      return res.status(500).json({error: err.message});
    }
    
    const userId = this.lastID;
    
    // إضافة الصلاحيات
    if (permissions && permissions.length > 0) {
      // إزالة التكرار من الصلاحيات
      const uniquePermissions = [...new Set(permissions)];
      const permissionValues = uniquePermissions.map(permission => [userId, permission, 1, now]);
      const placeholders = permissionValues.map(() => '(?, ?, ?, ?)').join(',');
      
      db.run(`
        INSERT INTO user_permissions (user_id, permission_name, is_granted, created_at)
        VALUES ${placeholders}
      `, permissionValues.flat(), (err) => {
        if (err) console.error('Error adding permissions:', err);
      });
    }
    
    res.json({success: true, id: userId});
  });
});

// جلب جميع المستخدمين
app.get('/api/users', (req, res) => {
  db.all(`
    SELECT u.*, 
           GROUP_CONCAT(up.permission_name) as permissions
    FROM users u
    LEFT JOIN user_permissions up ON u.id = up.user_id AND up.is_granted = 1
    GROUP BY u.id
    ORDER BY u.created_at DESC
  `, [], (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    
    const users = rows.map(user => ({
      ...user,
      permissions: user.permissions ? user.permissions.split(',') : []
    }));
    
    res.json(users);
  });
});

// جلب مستخدم واحد
app.get('/api/users/:id', (req, res) => {
  const userId = req.params.id;
  
  db.get(`
    SELECT u.*, 
           GROUP_CONCAT(up.permission_name) as permissions
    FROM users u
    LEFT JOIN user_permissions up ON u.id = up.user_id AND up.is_granted = 1
    WHERE u.id = ?
    GROUP BY u.id
  `, [userId], (err, user) => {
    if (err) return res.status(500).json({error: err.message});
    if (!user) return res.status(404).json({error: 'المستخدم غير موجود'});
    
    const userData = {
      ...user,
      permissions: user.permissions ? user.permissions.split(',') : []
    };
    
    res.json(userData);
  });
});

// تحديث مستخدم
app.put('/api/users/:id', (req, res) => {
  const { username, full_name, email, phone, role, is_active, permissions } = req.body;
  const userId = req.params.id;
  
  const now = new Date().toLocaleString('ar-EG');
  const updates = [];
  const values = [];
  
  if (username) { updates.push('username = ?'); values.push(username); }
  if (full_name) { updates.push('full_name = ?'); values.push(full_name); }
  if (email !== undefined) { updates.push('email = ?'); values.push(email); }
  if (phone !== undefined) { updates.push('phone = ?'); values.push(phone); }
  if (role) { updates.push('role = ?'); values.push(role); }
  if (is_active !== undefined) { updates.push('is_active = ?'); values.push(is_active); }
  
  updates.push('updated_at = ?');
  values.push(now);
  values.push(userId);
  
  db.run(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, values, function(err) {
    if (err) return res.status(500).json({error: err.message});
    
    // تحديث الصلاحيات
    if (permissions) {
      // حذف الصلاحيات القديمة
      db.run('DELETE FROM user_permissions WHERE user_id = ?', [userId], (err) => {
        if (err) console.error('Error deleting old permissions:', err);
        
        // إضافة الصلاحيات الجديدة
        if (permissions.length > 0) {
          // إزالة التكرار من الصلاحيات
          const uniquePermissions = [...new Set(permissions)];
          const permissionValues = uniquePermissions.map(permission => [userId, permission, 1, now]);
          const placeholders = permissionValues.map(() => '(?, ?, ?, ?)').join(',');
          
          db.run(`
            INSERT INTO user_permissions (user_id, permission_name, is_granted, created_at)
            VALUES ${placeholders}
          `, permissionValues.flat(), (err) => {
            if (err) console.error('Error adding new permissions:', err);
          });
        }
      });
    }
    
    res.json({success: true});
  });
});

// حذف مستخدم
app.delete('/api/users/:id', (req, res) => {
  db.run('DELETE FROM users WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({error: err.message});
    res.json({success: true});
  });
});

// جلب الصلاحيات المتاحة
app.get('/api/permissions', (req, res) => {
  const availablePermissions = [
    'add_contract',
    'view_contracts', 
    'receipts',
    'broker_commissions',
    'company_work',
    'user_management',
    'my_properties'
  ];
  
  res.json(availablePermissions);
});

// جلب تقارير المستخدمين
app.get('/api/user-reports', (req, res) => {
  const { userId } = req.query;
  
  let sql = `
    SELECT 
      u.id,
      u.username,
      u.full_name,
      p.operation_type,
      p.unit_type,
      COUNT(*) as count
    FROM users u
    LEFT JOIN properties p ON u.id = p.created_by
    WHERE u.is_active = 1
  `;
  
  let params = [];
  
  if (userId) {
    sql += ` AND u.id = ?`;
    params.push(userId);
  }
  
  sql += `
    GROUP BY u.id, u.username, u.full_name, p.operation_type, p.unit_type
    ORDER BY u.full_name, p.operation_type, p.unit_type
  `;
  
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    
    // تنظيم البيانات حسب المستخدم
    const userReports = {};
    
    rows.forEach(row => {
      if (!userReports[row.id]) {
        userReports[row.id] = {
          id: row.id,
          username: row.username,
          full_name: row.full_name,
          total_properties: 0,
          properties_by_type: {}
        };
      }
      
      if (row.operation_type && row.unit_type) {
        const key = `${row.operation_type}_${row.unit_type}`;
        if (!userReports[row.id].properties_by_type[key]) {
          userReports[row.id].properties_by_type[key] = {
            operation_type: row.operation_type,
            unit_type: row.unit_type,
            count: 0
          };
        }
        userReports[row.id].properties_by_type[key].count = row.count;
        userReports[row.id].total_properties += row.count;
      }
    });
    
    res.json(Object.values(userReports));
  });
});

// Middleware لمعالجة أخطاء multer
app.use((error, req, res, next) => {
  console.log('=== MULTER ERROR ===');
  console.log('Error:', error);
  console.log('Error type:', error.constructor.name);
  
  if (error instanceof multer.MulterError) {
    console.log('Multer error code:', error.code);
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({error: 'الملف كبير جداً. الحد الأقصى 50 ميجابايت'});
    }
    return res.status(400).json({error: 'خطأ في رفع الملف: ' + error.message});
  }
  next(error);
});

// Middleware عام لمعالجة الأخطاء
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({error: 'خطأ غير متوقع في الخادم'});
});

// إنشاء جدول العقارات (Buildings)
db.run(`
  CREATE TABLE IF NOT EXISTS buildings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    address TEXT,
    description TEXT,
    total_units INTEGER,
    created_by INTEGER,
    created_by_name TEXT,
    created_by_username TEXT,
    created_date TEXT,
    created_time TEXT,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id)
  )
`, (err) => {
  if (err) {
    console.error('Error creating buildings table:', err);
  } else {
    console.log('Buildings table ready');
  }
});

// إنشاء جدول الوحدات (Units)
db.run(`
  CREATE TABLE IF NOT EXISTS units (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    building_id INTEGER,
    unit_number TEXT NOT NULL,
    unit_type TEXT NOT NULL,
    area REAL,
    rooms INTEGER,
    bathrooms INTEGER,
    floor INTEGER,
    price REAL,
    status TEXT DEFAULT 'available',
    description TEXT,
    documents TEXT,
    created_by INTEGER,
    created_by_name TEXT,
    created_by_username TEXT,
    created_date TEXT,
    created_time TEXT,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (building_id) REFERENCES buildings(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
  )
`, (err) => {
  if (err) {
    console.error('Error creating units table:', err);
  } else {
    console.log('Units table ready');
  }
});

// إنشاء جدول الدفعات (Payments)
db.run(`
  CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    unit_id INTEGER,
    amount REAL NOT NULL,
    payment_date TEXT,
    payment_type TEXT,
    description TEXT,
    documents TEXT,
    created_by INTEGER,
    created_by_name TEXT,
    created_by_username TEXT,
    created_date TEXT,
    created_time TEXT,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (unit_id) REFERENCES units(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
  )
`, (err) => {
  if (err) {
    console.error('Error creating payments table:', err);
  } else {
    console.log('Payments table ready');
  }
});

// إنشاء جدول الفواتير (Invoices)
db.run(`
  CREATE TABLE IF NOT EXISTS invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    unit_id INTEGER,
    invoice_type TEXT NOT NULL,
    amount REAL NOT NULL,
    invoice_date TEXT,
    due_date TEXT,
    status TEXT DEFAULT 'unpaid',
    description TEXT,
    documents TEXT,
    created_by INTEGER,
    created_by_name TEXT,
    created_by_username TEXT,
    created_date TEXT,
    created_time TEXT,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (unit_id) REFERENCES units(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
  )
`, (err) => {
  if (err) {
    console.error('Error creating invoices table:', err);
  } else {
    console.log('Invoices table ready');
  }
}); 

// API للعقارات
app.get('/api/buildings', (req, res) => {
  const { userId } = req.query;
  let sql = `
    SELECT b.*, u.full_name as creator_name, u.username as creator_username
    FROM buildings b
    LEFT JOIN users u ON b.created_by = u.id
  `;
  let params = [];
  
  if (userId) {
    sql += ` WHERE b.created_by = ?`;
    params.push(userId);
  }
  
  sql += ` ORDER BY b.created_date DESC`;
  
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

app.post('/api/buildings', upload.array('documents', 10), (req, res) => {
  console.log('Buildings API - Request received');
  console.log('User:', req.user);
  console.log('Body:', req.body);
  console.log('Files:', req.files);
  
  const { name, address, description, total_units } = req.body;
  const documents = req.files ? req.files.map(file => file.filename).join(',') : '';
  
  if (!name) {
    return res.status(400).json({error: 'اسم البناية مطلوب'});
  }
  
  const now = new Date();
  const date = now.toLocaleDateString('ar-EG');
  const time = now.toLocaleTimeString('ar-EG');
  
  console.log('Inserting building with data:', {
    name, address, description, total_units, documents,
    created_by: req.user.id,
    created_by_name: req.user.full_name,
    created_by_username: req.user.username,
    date, time
  });
  
  db.run(`
    INSERT INTO buildings (name, address, description, total_units, documents, created_by, created_by_name, created_by_username, created_date, created_time)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [name, address, description, total_units, documents, req.user.id, req.user.full_name, req.user.username, date, time], function(err) {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({error: err.message});
    }
    console.log('Building saved successfully with ID:', this.lastID);
    res.json({success: true, id: this.lastID});
  });
});

app.put('/api/buildings/:id', upload.array('documents', 10), (req, res) => {
  const { name, address, description, total_units } = req.body;
  const documents = req.files ? req.files.map(file => file.filename).join(',') : '';
  
  db.run(`
    UPDATE buildings SET name = ?, address = ?, description = ?, total_units = ?, documents = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ? AND created_by = ?
  `, [name, address, description, total_units, documents, req.params.id, req.user.id], function(err) {
    if (err) return res.status(500).json({error: err.message});
    if (this.changes === 0) {
      return res.status(403).json({error: 'غير مصرح لك بتعديل هذه البناية'});
    }
    res.json({success: true});
  });
});

app.delete('/api/buildings/:id', (req, res) => {
  db.run('DELETE FROM buildings WHERE id = ? AND created_by = ?', [req.params.id, req.user.id], function(err) {
    if (err) return res.status(500).json({error: err.message});
    if (this.changes === 0) {
      return res.status(403).json({error: 'غير مصرح لك بحذف هذه البناية'});
    }
    res.json({success: true});
  });
});

// API للوحدات
app.get('/api/units', (req, res) => {
  const { building_id, buildingId, userId } = req.query;
  let sql = `
    SELECT u.*, b.name as building_name, creator.full_name as creator_name, creator.username as creator_username
    FROM units u
    LEFT JOIN buildings b ON u.building_id = b.id
    LEFT JOIN users creator ON u.created_by = creator.id
  `;
  let params = [];
  
  if (building_id || buildingId) {
    sql += ` WHERE u.building_id = ?`;
    params.push(building_id || buildingId);
  } else if (userId) {
    sql += ` WHERE u.created_by = ?`;
    params.push(userId);
  }
  
  sql += ` ORDER BY u.created_date DESC`;
  
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

app.post('/api/units', upload.array('documents', 10), (req, res) => {
  const { building_id, unit_number, unit_type, area, rooms, bathrooms, floor, price, status, description } = req.body;
  const documents = req.files ? req.files.map(file => file.filename).join(',') : '';
  
  if (!unit_number || !unit_type) {
    return res.status(400).json({error: 'رقم الوحدة ونوعها مطلوبان'});
  }
  
  const now = new Date();
  const date = now.toLocaleDateString('ar-EG');
  const time = now.toLocaleTimeString('ar-EG');
  
  db.run(`
    INSERT INTO units (building_id, unit_number, unit_type, area, rooms, bathrooms, floor, price, status, description, documents, created_by, created_by_name, created_by_username, created_date, created_time)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [building_id, unit_number, unit_type, area, rooms, bathrooms, floor, price, status, description, documents, req.user.id, req.user.full_name, req.user.username, date, time], function(err) {
    if (err) return res.status(500).json({error: err.message});
    res.json({success: true, id: this.lastID});
  });
});

app.put('/api/units/:id', upload.array('documents', 10), (req, res) => {
  const { 
    building_id, unit_number, unit_type, area, rooms, bathrooms, floor, price, status, description,
    rent_value, tenant_name, tenant_phone, tenant_email, electricity_account, water_account,
    contract_start_date, contract_end_date
  } = req.body;
  const documents = req.files ? req.files.map(file => file.filename).join(',') : '';
  
  if (!building_id || !unit_number || !unit_type) {
    return res.status(400).json({error: 'معرف المبنى ورقم الوحدة ونوع الوحدة مطلوبة'});
  }
  
  const updateQuery = `
    UPDATE units SET 
      building_id = ?, unit_number = ?, unit_type = ?, area = ?, rooms = ?, bathrooms = ?, floor = ?, 
      price = ?, status = ?, description = ?, rent_value = ?, tenant_name = ?, tenant_phone = ?, 
      tenant_email = ?, electricity_account = ?, water_account = ?, 
      contract_start_date = ?, contract_end_date = ?, documents = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `;
  
  const updateValues = [
    building_id, unit_number, unit_type, area || null, rooms || null, bathrooms || null, floor || null,
    price || null, status || 'available', description || null, rent_value || null, tenant_name || null,
    tenant_phone || null, tenant_email || null, electricity_account || null, water_account || null,
    contract_start_date || null, contract_end_date || null, documents, req.params.id
  ];
  
  db.run(updateQuery, updateValues, function(err) {
    if (err) return res.status(500).json({error: err.message});
    if (this.changes === 0) {
      return res.status(404).json({error: 'الوحدة غير موجودة'});
    }
    res.json({success: true});
  });
});

app.delete('/api/units/:id', (req, res) => {
  db.run('DELETE FROM units WHERE id = ? AND created_by = ?', [req.params.id, req.user.id], function(err) {
    if (err) return res.status(500).json({error: err.message});
    if (this.changes === 0) {
      return res.status(403).json({error: 'غير مصرح لك بحذف هذه الوحدة'});
    }
    res.json({success: true});
  });
});





// API للفواتير
app.get('/api/invoices', (req, res) => {
  const { unit_id, unitId, userId } = req.query;
  let sql = `
    SELECT i.*, u.unit_number, u.unit_type, b.name as building_name, creator.full_name as creator_name
    FROM invoices i
    LEFT JOIN units u ON i.unit_id = u.id
    LEFT JOIN buildings b ON u.building_id = b.id
    LEFT JOIN users creator ON i.created_by = creator.id
  `;
  let params = [];
  
  if (unit_id || unitId) {
    sql += ` WHERE i.unit_id = ?`;
    params.push(unit_id || unitId);
  } else if (userId) {
    sql += ` WHERE i.created_by = ?`;
    params.push(userId);
  }
  
  sql += ` ORDER BY i.invoice_date DESC`;
  
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

app.post('/api/invoices', upload.array('documents', 10), (req, res) => {
  const { unit_id, invoice_type, amount, invoice_date, due_date, status, description } = req.body;
  const documents = req.files ? req.files.map(file => file.filename).join(',') : '';
  
  if (!unit_id || !invoice_type || !amount) {
    return res.status(400).json({error: 'الوحدة ونوع الفاتورة والمبلغ مطلوبة'});
  }
  
  const now = new Date();
  const date = now.toLocaleDateString('ar-EG');
  const time = now.toLocaleTimeString('ar-EG');
  
  db.run(`
    INSERT INTO invoices (unit_id, invoice_type, amount, invoice_date, due_date, status, description, documents, created_by, created_by_name, created_by_username, created_date, created_time)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [unit_id, invoice_type, amount, invoice_date, due_date, status, description, documents, req.user.id, req.user.full_name, req.user.username, date, time], function(err) {
    if (err) return res.status(500).json({error: err.message});
    res.json({success: true, id: this.lastID});
  });
});

// إضافة endpoint لتحميل الصور كملف ZIP
app.get('/api/download-images-zip', async (req, res) => {
    try {
        const propertyId = req.query.propertyId;
        const token = req.query.token;
        
        if (!token) {
            return res.status(401).json({error: 'معرف المستخدم مطلوب'});
        }
        
        if (!propertyId) {
            return res.status(400).json({error: 'معرف العقار مطلوب'});
        }
        
        // جلب معلومات العقار
        const property = await new Promise((resolve, reject) => {
            db.get('SELECT documents FROM properties WHERE id = ?', [propertyId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
        
        if (!property || !property.documents) {
            return res.status(404).json({error: 'لا توجد صور للعقار'});
        }
        
        const documents = property.documents.split(',');
        const imageFiles = documents.filter(doc => {
            const fileExt = doc.split('.').pop().toLowerCase();
            return ['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(fileExt);
        });
        
        if (imageFiles.length === 0) {
            return res.status(404).json({error: 'لا توجد صور صالحة للعقار'});
        }
        
        const zip = new JSZip();
        
        // تحميل الصور وإضافتها للـ ZIP
        const downloadPromises = imageFiles.map(async (doc, index) => {
            try {
                const imagePath = path.join(__dirname, 'uploads', doc.trim());
                if (fs.existsSync(imagePath)) {
                    const imageBuffer = fs.readFileSync(imagePath);
                    const fileName = `image_${index + 1}.jpg`;
                    zip.file(fileName, imageBuffer);
                }
            } catch (error) {
                console.error('Error adding image to ZIP:', error);
            }
        });
        
        await Promise.all(downloadPromises);
        
        const content = await zip.generateAsync({type: 'nodebuffer'});
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="property_${propertyId}_images.zip"`);
        res.send(content);
        
    } catch (error) {
        console.error('Error creating ZIP:', error);
        res.status(500).json({error: 'حدث خطأ في إنشاء ملف ZIP'});
    }
});

// Uploads are now served as static files without authentication

// Uploads are now protected by authentication middleware

// ===== API endpoints للعقارات =====

// إضافة مبنى جديد
app.post('/api/buildings', upload.any(), (req, res) => {
  console.log('=== BUILDING SAVE REQUEST ===');
  console.log('Received building data:', req.body);
  console.log('Received files:', req.files);
  console.log('User:', req.user);
  
  const { name, address, description, total_floors, total_units } = req.body;
  
  if (!name) {
    return res.status(400).json({error: 'اسم المبنى مطلوب'});
  }
  
  const now = new Date().toLocaleString('ar-EG');
  const documents = req.files ? req.files.map(file => file.filename).join(',') : '';
  
  db.run(`
    INSERT INTO buildings (name, address, description, total_floors, total_units, documents, created_by, created_by_name, created_by_username, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [name, address || null, description || null, total_floors || null, total_units || null, documents, req.user.id, req.user.full_name, req.user.username, now, now], function(err) {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({error: err.message});
    }
    res.json({success: true, id: this.lastID});
  });
});

// جلب جميع المباني
app.get('/api/buildings', (req, res) => {
  db.all(`
    SELECT * FROM buildings 
    ORDER BY created_at DESC
  `, [], (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

// جلب مبنى واحد
app.get('/api/buildings/:id', (req, res) => {
  const buildingId = req.params.id;
  
  db.get('SELECT * FROM buildings WHERE id = ?', [buildingId], (err, building) => {
    if (err) return res.status(500).json({error: err.message});
    if (!building) return res.status(404).json({error: 'المبنى غير موجود'});
    res.json(building);
  });
});

// تحديث مبنى
app.put('/api/buildings/:id', upload.any(), (req, res) => {
  const buildingId = req.params.id;
  const { name, address, description, total_floors, total_units } = req.body;
  
  if (!name) {
    return res.status(400).json({error: 'اسم المبنى مطلوب'});
  }
  
  const now = new Date().toLocaleString('ar-EG');
  const documents = req.files ? req.files.map(file => file.filename).join(',') : '';
  
  db.run(`
    UPDATE buildings 
    SET name = ?, address = ?, description = ?, total_floors = ?, total_units = ?, documents = ?, updated_at = ?
    WHERE id = ?
  `, [name, address || null, description || null, total_floors || null, total_units || null, documents, now, buildingId], function(err) {
    if (err) return res.status(500).json({error: err.message});
    res.json({success: true});
  });
});

// حذف مبنى
app.delete('/api/buildings/:id', (req, res) => {
  const buildingId = req.params.id;
  
  db.run('DELETE FROM buildings WHERE id = ?', [buildingId], function(err) {
    if (err) return res.status(500).json({error: err.message});
    res.json({success: true});
  });
});

// إضافة وحدة جديدة
app.post('/api/units', upload.any(), (req, res) => {
  const { 
    building_id, unit_number, unit_type, floor_number, area, rooms, bathrooms, price, status, description,
    rent_value, tenant_name, tenant_phone, tenant_email, electricity_account, water_account,
    contract_start_date, contract_end_date
  } = req.body;
  
  if (!building_id || !unit_number || !unit_type) {
    return res.status(400).json({error: 'معرف المبنى ورقم الوحدة ونوع الوحدة مطلوبة'});
  }
  
  const now = new Date().toLocaleString('ar-EG');
  const documents = req.files ? req.files.map(file => file.filename).join(',') : '';
  
  db.run(`
    INSERT INTO units (
      building_id, unit_number, unit_type, floor_number, area, rooms, bathrooms, price, status, description, documents,
      rent_value, tenant_name, tenant_phone, tenant_email, electricity_account, water_account,
      contract_start_date, contract_end_date, created_by, created_by_name, created_by_username, created_at, updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [
    building_id, unit_number, unit_type, floor_number || null, area || null, rooms || null, bathrooms || null, price || null, status || 'available', description || null, documents,
    rent_value || null, tenant_name || null, tenant_phone || null, tenant_email || null, electricity_account || null, water_account || null,
    contract_start_date || null, contract_end_date || null, req.user.id, req.user.full_name, req.user.username, now, now
  ], function(err) {
    if (err) return res.status(500).json({error: err.message});
    res.json({success: true, id: this.lastID});
  });
});

// جلب جميع الوحدات
app.get('/api/units', (req, res) => {
  const buildingId = req.query.building_id;
  
  let query = `
    SELECT u.*, b.name as building_name 
    FROM units u 
    LEFT JOIN buildings b ON u.building_id = b.id
  `;
  let params = [];
  
  if (buildingId) {
    query += ' WHERE u.building_id = ?';
    params.push(buildingId);
  }
  
  query += ' ORDER BY u.created_at DESC';
  
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

// جلب وحدة معينة
app.get('/api/units/:id', (req, res) => {
  const unitId = req.params.id;
  
  db.get(`
    SELECT u.*, b.name as building_name 
    FROM units u 
    LEFT JOIN buildings b ON u.building_id = b.id
    WHERE u.id = ?
  `, [unitId], (err, unit) => {
    if (err) return res.status(500).json({error: err.message});
    if (!unit) return res.status(404).json({error: 'الوحدة غير موجودة'});
    
    res.json(unit);
  });
});





// حذف وحدة معينة
app.delete('/api/units/:id', (req, res) => {
  const unitId = req.params.id;
  
  db.run('DELETE FROM units WHERE id = ?', [unitId], function(err) {
    if (err) return res.status(500).json({error: err.message});
    res.json({success: true});
  });
});

// إضافة دفعة جديدة
app.post('/api/payments', (req, res, next) => {
  console.log('=== PAYMENT ROUTE START ===');
  console.log('Request method:', req.method);
  console.log('Request path:', req.path);
  console.log('Request headers:', req.headers);
  console.log('Content-Type:', req.headers['content-type']);
  
  // استخدام multer middleware مع معالجة الأخطاء
  upload.any()(req, res, (err) => {
    if (err) {
      console.log('=== MULTER ERROR IN PAYMENT ROUTE ===');
      console.log('Error:', err);
      console.log('Error type:', err.constructor.name);
      return res.status(400).json({error: 'خطأ في معالجة الطلب: ' + err.message});
    }
    console.log('=== MULTER SUCCESS ===');
    console.log('Request body after multer:', req.body);
    console.log('Request files after multer:', req.files);
    next();
  });
}, (req, res) => {
  console.log('=== PAYMENT SAVE REQUEST START ===');
  console.log('Request body:', req.body);
  console.log('Request files:', req.files);
  console.log('User:', req.user);
  
  // طباعة جميع مفاتيح req.body
  console.log('Request body keys:', Object.keys(req.body));
  
  // طباعة جميع قيم req.body للتشخيص
  console.log('Request body values:');
  Object.keys(req.body).forEach(key => {
    console.log(`${key}: ${req.body[key]}`);
  });
  
  const { unit_id, payment_type, amount, payment_date, due_date, status, description, installments } = req.body;
  
  console.log('Parsed fields:', { unit_id, payment_type, amount, payment_date, due_date, status, description, installments });
  
  if (!unit_id) {
    console.log('Missing unit_id. Available keys:', Object.keys(req.body));
    console.log('unit_id value:', req.body.unit_id);
    return res.status(400).json({error: 'معرف الوحدة مطلوب'});
  }
  
  // التحقق من وجود البيانات المطلوبة
  const installmentsCount = parseInt(installments) || 1;
  
  console.log('Installments count:', installmentsCount);
  
  if (installmentsCount === 1) {
    const installmentAmount = req.body['payment_installment_amount_1'];
    const amount = Array.isArray(installmentAmount) ? installmentAmount[0] : installmentAmount;
    if (!amount) {
      console.log('Missing amount for single payment:', { unit_id, amount });
      return res.status(400).json({error: 'المبلغ مطلوب للدفعة الواحدة'});
    }
  }
  
  const now = new Date().toLocaleString('ar-EG');
  const documents = req.files ? req.files.map(file => file.filename).join(',') : '';
  
  // إذا كان عدد الدفعات = 1، احفظ دفعة واحدة
  if (installmentsCount === 1) {
    // استخراج البيانات من الحقول المخصصة للدفعات
    const installmentAmount = req.body['payment_installment_amount_1'];
    const installmentDueDate = req.body['payment_installment_due_date_1'];
    const installmentStatus = req.body['payment_installment_status_1'] || 'pending';
    const installmentType = req.body['payment_installment_type_1'] || payment_type;
    const installmentMethod = req.body['payment_installment_method_1'] || null;
    const installmentNotes = req.body['payment_installment_notes_1'] || '';
    
    // استخراج القيم الفردية من المجموعات
    const amount = Array.isArray(installmentAmount) ? installmentAmount[0] : installmentAmount;
    const dueDate = Array.isArray(installmentDueDate) ? installmentDueDate[0] : installmentDueDate;
    const status = Array.isArray(installmentStatus) ? installmentStatus[0] : installmentStatus;
    const type = Array.isArray(installmentType) ? installmentType[0] : installmentType;
    const method = Array.isArray(installmentMethod) ? installmentMethod[0] : installmentMethod;
    const notes = Array.isArray(installmentNotes) ? installmentNotes[0] : installmentNotes;
    
    if (!amount || !dueDate) {
      return res.status(400).json({error: 'المبلغ وتاريخ الاستحقاق مطلوبان للدفعة الواحدة'});
    }
    
    const now = new Date();
    const date = now.toLocaleDateString('ar-EG');
    const time = now.toLocaleTimeString('ar-EG');
    
    db.run(`
      INSERT INTO payments (unit_id, payment_type, amount, payment_date, due_date, status, description, payment_method, documents, created_by, created_by_name, created_by_username, created_date, created_time, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [unit_id, type, amount, payment_date || null, dueDate, status, notes, method, documents, req.user.id, req.user.full_name, req.user.username, date, time, now], function(err) {
      if (err) return res.status(500).json({error: err.message});
      res.json({success: true, id: this.lastID, paymentsAdded: 1});
    });
  } else {
    // إذا كان عدد الدفعات > 1، احفظ عدة دفعات
    console.log('Processing multiple payments. Installments count:', installmentsCount);
    console.log('Request body keys:', Object.keys(req.body));
    
    // جمع جميع الدفعات في مصفوفة
    const paymentsToSave = [];
    
    console.log('Request body keys for installments:');
    Object.keys(req.body).forEach(key => {
      if (key.includes('payment_installment_')) {
        console.log(`${key}: ${req.body[key]}`);
      }
    });
    
    for (let i = 1; i <= installmentsCount; i++) {
      const installmentAmount = req.body[`payment_installment_amount_${i}`];
      const installmentDueDate = req.body[`payment_installment_due_date_${i}`];
      const installmentStatus = req.body[`payment_installment_status_${i}`] || 'pending';
      const installmentType = req.body[`payment_installment_type_${i}`] || payment_type;
      const installmentMethod = req.body[`payment_installment_method_${i}`] || null;
      const installmentNotes = req.body[`payment_installment_notes_${i}`] || '';
      
      // استخراج القيم الفردية من المجموعات
      const amount = Array.isArray(installmentAmount) ? installmentAmount[0] : installmentAmount;
      const dueDate = Array.isArray(installmentDueDate) ? installmentDueDate[0] : installmentDueDate;
      const status = Array.isArray(installmentStatus) ? installmentStatus[0] : installmentStatus;
      const type = Array.isArray(installmentType) ? installmentType[0] : installmentType;
      const method = Array.isArray(installmentMethod) ? installmentMethod[0] : installmentMethod;
      const notes = Array.isArray(installmentNotes) ? installmentNotes[0] : installmentNotes;
      
      console.log(`Processing installment ${i}:`, {
        amount: amount,
        dueDate: dueDate,
        status: status,
        type: type,
        method: method,
        notes: notes
      });
      
      // تحقق من وجود البيانات المطلوبة
      if (amount && dueDate) {
        console.log(`Adding installment ${i} to save list`);
        paymentsToSave.push({
          unit_id: unit_id,
          payment_type: type,
          amount: amount,
          payment_date: payment_date || null,
          due_date: dueDate,
          status: status,
          description: notes,
          payment_method: method,
          documents: documents,
          created_by: req.user.id,
          created_by_name: req.user.full_name,
          created_by_username: req.user.username,
          created_at: now,
          updated_at: now
        });
      } else {
        console.log(`Skipping installment ${i} - missing required data:`, {
          hasAmount: !!amount,
          hasDueDate: !!dueDate
        });
      }
    }
    
    if (paymentsToSave.length === 0) {
      console.log('No installments to save. Sending error response.');
      console.log('Request body keys for debugging:');
      Object.keys(req.body).forEach(key => {
        console.log(`${key}: ${req.body[key]}`);
      });
      return res.status(400).json({error: 'لم يتم حفظ أي دفعة. تأكد من إدخال جميع البيانات المطلوبة.'});
    }
    
    console.log(`Saving ${paymentsToSave.length} installments...`);
    
    // حفظ الدفعات بشكل متسلسل
    let savedCount = 0;
    let lastPaymentId = null;
    
    const saveNextPayment = (index) => {
      if (index >= paymentsToSave.length) {
        // تم حفظ جميع الدفعات
        console.log(`All ${savedCount} installments saved successfully`);
        res.json({success: true, id: lastPaymentId, paymentsAdded: savedCount});
        return;
      }
      
      const payment = paymentsToSave[index];
      
      const now = new Date();
      const date = now.toLocaleDateString('ar-EG');
      const time = now.toLocaleTimeString('ar-EG');
      
      db.run(`
        INSERT INTO payments (unit_id, payment_type, amount, payment_date, due_date, status, description, payment_method, documents, created_by, created_by_name, created_by_username, created_date, created_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        payment.unit_id, payment.payment_type, payment.amount, payment.payment_date, 
        payment.due_date, payment.status, payment.description, payment.payment_method, 
        payment.documents, payment.created_by, payment.created_by_name, payment.created_by_username, 
        date, time
      ], function(err) {
        if (err) {
          console.error('Error adding payment installment:', err);
          return res.status(500).json({error: 'خطأ في حفظ الدفعة: ' + err.message});
        } else {
          savedCount++;
          lastPaymentId = this.lastID;
          console.log(`Successfully saved installment ${index + 1}. Total saved: ${savedCount}`);
          
          // حفظ الدفعة التالية
          saveNextPayment(index + 1);
        }
      });
    };
    
    // بدء حفظ الدفعات
    saveNextPayment(0);
  }
  
  console.log('=== PAYMENT SAVE REQUEST END ===');
});

// جلب جميع الدفعات
app.get('/api/payments', (req, res) => {
  const unitId = req.query.unit_id;
  
  let query = `
    SELECT p.*, u.unit_number, b.name as building_name,
           CASE 
             WHEN p.paid_amount >= p.amount THEN 'paid_full'
             WHEN p.paid_amount > 0 THEN 'paid_partial'
             WHEN p.due_date < date('now') THEN 'overdue'
             ELSE 'pending'
           END as calculated_status,
           CASE 
             WHEN p.paid_amount >= p.amount THEN 'دفع كلي'
             WHEN p.paid_amount > 0 THEN 'دفع جزئي'
             WHEN p.due_date < date('now') THEN 'متأخر'
             ELSE 'معلق'
           END as status_arabic,
           (p.amount - COALESCE(p.paid_amount, 0)) as remaining_amount,
           CASE 
             WHEN p.amount > 0 THEN ROUND((COALESCE(p.paid_amount, 0) / p.amount) * 100, 2)
             ELSE 0
           END as payment_percentage
    FROM payments p 
    LEFT JOIN units u ON p.unit_id = u.id
    LEFT JOIN buildings b ON u.building_id = b.id
  `;
  let params = [];
  
  if (unitId) {
    query += ' WHERE p.unit_id = ?';
    params.push(unitId);
  }
  
  query += ' ORDER BY p.id DESC';
  
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

// جلب دفعة معينة
app.get('/api/payments/:id', (req, res) => {
  const paymentId = req.params.id;
  
  db.get(`
    SELECT p.*, u.unit_number, b.name as building_name 
    FROM payments p 
    LEFT JOIN units u ON p.unit_id = u.id
    LEFT JOIN buildings b ON u.building_id = b.id
    WHERE p.id = ?
  `, [paymentId], (err, payment) => {
    if (err) return res.status(500).json({error: err.message});
    if (!payment) return res.status(404).json({error: 'الدفعة غير موجودة'});
    res.json(payment);
  });
});

// تحديث دفعة معينة
app.put('/api/payments/:id', upload.any(), (req, res) => {
  const paymentId = req.params.id;
  const { unit_id, payment_type, amount, payment_date, due_date, status, description, payment_method } = req.body;
  
  if (!unit_id || !amount || !payment_date) {
    return res.status(400).json({error: 'معرف الوحدة والمبلغ وتاريخ الدفعة مطلوبة'});
  }
  
  const now = new Date().toLocaleString('ar-EG');
  const documents = req.files ? req.files.map(file => file.filename).join(',') : '';
  
  const updateQuery = `
    UPDATE payments SET 
      unit_id = ?, payment_type = ?, amount = ?, payment_date = ?, due_date = ?, 
      status = ?, description = ?, payment_method = ?, updated_at = ?
      ${documents ? ', documents = ?' : ''}
    WHERE id = ?
  `;
  
  const updateValues = [
    unit_id, payment_type || null, amount, payment_date, due_date || null,
    status || 'pending', description || null, payment_method || null, now
  ];
  
  if (documents) {
    updateValues.push(documents);
  }
  updateValues.push(paymentId);
  
  db.run(updateQuery, updateValues, function(err) {
    if (err) return res.status(500).json({error: err.message});
    res.json({success: true});
  });
});

// حذف دفعة معينة
app.delete('/api/payments/:id', (req, res) => {
  const paymentId = req.params.id;
  
  db.run('DELETE FROM payments WHERE id = ?', [paymentId], function(err) {
    if (err) return res.status(500).json({error: err.message});
    res.json({success: true});
  });
});

// إضافة فاتورة جديدة
app.post('/api/invoices', upload.any(), (req, res) => {
  const { unit_id, invoice_type, amount, invoice_date, due_date, status, description } = req.body;
  
  if (!unit_id || !invoice_type || !amount) {
    return res.status(400).json({error: 'معرف الوحدة ونوع الفاتورة والمبلغ مطلوبة'});
  }
  
  const now = new Date().toLocaleString('ar-EG');
  const documents = req.files ? req.files.map(file => file.filename).join(',') : '';
  
  db.run(`
    INSERT INTO invoices (unit_id, invoice_type, amount, invoice_date, due_date, status, description, documents, created_by, created_by_name, created_by_username, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [unit_id, invoice_type, amount, invoice_date || null, due_date || null, status || 'pending', description || null, documents, req.user.id, req.user.full_name, req.user.username, now, now], function(err) {
    if (err) return res.status(500).json({error: err.message});
    res.json({success: true, id: this.lastID});
  });
});

// جلب جميع الفواتير
app.get('/api/invoices', (req, res) => {
  const unitId = req.query.unit_id;
  
  let query = `
    SELECT i.*, u.unit_number, b.name as building_name 
    FROM invoices i 
    LEFT JOIN units u ON i.unit_id = u.id
    LEFT JOIN buildings b ON u.building_id = b.id
  `;
  let params = [];
  
  if (unitId) {
    query += ' WHERE i.unit_id = ?';
    params.push(unitId);
  }
  
  query += ' ORDER BY i.created_at DESC';
  
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

// ===== نظام العقود مع ربط عمولات الوسطاء =====

// إضافة عقد جديد مع ربط عمولات الوسطاء
app.post('/api/contract', (req, res) => {
  console.log('=== CONTRACT SAVE REQUEST START ===');
  console.log('Request body:', req.body);
  
  const {
    contractNumber, clientName, clientPhone, clientEmail, unitNumber, rentValue, installments, insurance, officeCommission, serviceFees,
    municipalityFile, municipalityDate, municipalityNotes, terms, onlineFees, electricityFees, waterFees,
    brokerName, brokerNameUnit, clearanceName, clearanceValue, totalCommission, commissionDeduction, attestationValueInternal, attestationDeduction, 
    representativeCommission, representativeCommissionUnit, representativeAttestation, officeCommissionInternal, internalNotes
  } = req.body;

  console.log('Parsed contract data:', {
    contractNumber, clientName, clientPhone, clientEmail, unitNumber, rentValue, installments, insurance, officeCommission, serviceFees,
    municipalityFile, municipalityDate, municipalityNotes, terms, onlineFees, electricityFees, waterFees,
    brokerName, brokerNameUnit, clearanceName, clearanceValue, totalCommission, commissionDeduction, attestationValueInternal, attestationDeduction, 
    representativeCommission, representativeCommissionUnit, representativeAttestation, officeCommissionInternal, internalNotes
  });

  if (!contractNumber || !clientName || !unitNumber || !rentValue) {
    return res.status(400).json({error: 'رقم العقد واسم العميل ورقم الوحدة وقيمة الإيجار مطلوبة'});
  }

  const contract_date = new Date().toLocaleDateString('ar-EG');
  const created_at = new Date().toLocaleString('ar-EG');

  // إنشاء استعلام INSERT مع الحقول الجديدة
  const insertQuery = `
    INSERT INTO contracts (
      contract_number, client_name, client_phone, client_email, unit_number, rent_value, installments, insurance, office_commission, service_fees,
      municipality_file, municipality_date, municipality_notes, terms, online_fees, electricity_fees, water_fees, 
      broker_name, broker_name_unit, clearance_name, clearance_value, total_commission, commission_deduction, attestation_value, attestation_deduction, 
      representative_commission, representative_commission_unit, representative_attestation, office_commission_internal, internal_notes, broker_id, contract_date, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  
  const insertValues = [
    contractNumber, clientName, clientPhone, clientEmail, unitNumber, rentValue, installments, insurance, officeCommission, serviceFees,
    municipalityFile, municipalityDate, municipalityNotes, terms, onlineFees, electricityFees, waterFees,
    brokerName, brokerNameUnit || null, clearanceName || null, clearanceValue || null, totalCommission, commissionDeduction, attestationValueInternal, attestationDeduction,
    representativeCommission, representativeCommissionUnit || null, representativeAttestation, officeCommissionInternal, internalNotes, null, contract_date, created_at
  ];

  console.log('Insert query:', insertQuery);
  console.log('Insert values count:', insertValues.length);
  console.log('Insert values:', insertValues);

  db.run(insertQuery, insertValues, function(err) {
    if (err) {
      console.error('Error saving contract:', err);
      return res.status(500).json({error: 'خطأ في حفظ العقد: ' + err.message});
    }

    const contractId = this.lastID;
    console.log('Contract saved successfully with ID:', contractId);
    console.log('=== STARTING BROKER COMMISSIONS LOGIC ===');

    // ربط عمولات الوسطاء تلقائياً
    const brokerCommissions = [];
    
    console.log('=== BROKER COMMISSIONS PROCESSING ===');
    console.log('req.body.brokerName:', req.body.brokerName);
    console.log('req.body.representativeCommission:', req.body.representativeCommission);
    console.log('req.body.brokerNameUnit:', req.body.brokerNameUnit);
    console.log('req.body.representativeCommissionUnit:', req.body.representativeCommissionUnit);
    console.log('req.body.clearanceName:', req.body.clearanceName);
    console.log('req.body.clearanceValue:', req.body.clearanceValue);
    console.log('req.body.officeCommissionInternal:', req.body.officeCommissionInternal);
    console.log('All req.body keys:', Object.keys(req.body));

    // عمولة وسيط صاحب الزبون
    if (req.body.brokerName && req.body.representativeCommission && parseFloat(req.body.representativeCommission) > 0) {
      console.log('Adding client broker commission:', { brokerName: req.body.brokerName, representativeCommission: req.body.representativeCommission });
      brokerCommissions.push({
        contract_id: contractId,
        broker_name: req.body.brokerName,
        commission_type: 'representative_commission',
        commission_value: parseFloat(req.body.representativeCommission),
        contract_number: contractNumber,
        unit_number: unitNumber,
        client_name: clientName,
        rent_value: parseFloat(rentValue),
        contract_date: contract_date
      });
    } else {
      console.log('Skipping client broker commission - missing data or zero value');
    }

    // عمولة وسيط صاحب الوحدة
    if (req.body.brokerNameUnit && req.body.representativeCommissionUnit && parseFloat(req.body.representativeCommissionUnit) > 0) {
      console.log('Adding unit broker commission:', { brokerNameUnit: req.body.brokerNameUnit, representativeCommissionUnit: req.body.representativeCommissionUnit });
      brokerCommissions.push({
        contract_id: contractId,
        broker_name: req.body.brokerNameUnit,
        commission_type: 'unit_representative_commission',
        commission_value: parseFloat(req.body.representativeCommissionUnit),
        contract_number: contractNumber,
        unit_number: unitNumber,
        client_name: clientName,
        rent_value: parseFloat(rentValue),
        contract_date: contract_date
      });
    } else {
      console.log('Skipping unit broker commission - missing data or zero value');
    }

    // عمولة التخليص
    if (req.body.clearanceName && req.body.clearanceValue && parseFloat(req.body.clearanceValue) > 0) {
      console.log('Adding clearance commission:', { clearanceName: req.body.clearanceName, clearanceValue: req.body.clearanceValue });
      brokerCommissions.push({
        contract_id: contractId,
        broker_name: req.body.clearanceName,
        commission_type: 'clearance_commission',
        commission_value: parseFloat(req.body.clearanceValue),
        contract_number: contractNumber,
        unit_number: unitNumber,
        client_name: clientName,
        rent_value: parseFloat(rentValue),
        contract_date: contract_date
      });
    } else {
      console.log('Skipping clearance commission - missing data or zero value');
    }

    // عمولة المكتب
    if (req.body.officeCommissionInternal && parseFloat(req.body.officeCommissionInternal) > 0) {
      console.log('Adding office commission:', { officeCommissionInternal: req.body.officeCommissionInternal });
      brokerCommissions.push({
        contract_id: contractId,
        broker_name: 'عمولة المكتب',
        commission_type: 'office_commission',
        commission_value: parseFloat(req.body.officeCommissionInternal),
        contract_number: contractNumber,
        unit_number: unitNumber,
        client_name: clientName,
        rent_value: parseFloat(rentValue),
        contract_date: contract_date
      });
    } else {
      console.log('Skipping office commission - missing data or zero value');
    }

    // حفظ عمولات الوسطاء
    console.log('=== SAVING BROKER COMMISSIONS ===');
    console.log('brokerCommissions array length:', brokerCommissions.length);
    console.log('brokerCommissions array:', brokerCommissions);
    console.log('About to check if brokerCommissions.length > 0');
    
    if (brokerCommissions.length > 0) {
      console.log('Saving broker commissions:', brokerCommissions);
      
      const now = new Date().toLocaleString('ar-EG');
      
      const commissionInsertQuery = `
        INSERT INTO broker_commissions (
          contract_id, broker_name, commission_type, commission_value, 
          contract_number, unit_number, client_name, rent_value, contract_date, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;

      let savedCommissions = 0;
      const saveNextCommission = (index) => {
        if (index >= brokerCommissions.length) {
          console.log(`All ${savedCommissions} broker commissions saved successfully`);
          res.json({success: true, id: contractId, commissionsSaved: savedCommissions});
          return;
        }

        const commission = brokerCommissions[index];
        const commissionValues = [
          commission.contract_id, commission.broker_name, commission.commission_type, commission.commission_value,
          commission.contract_number, commission.unit_number, commission.client_name, commission.rent_value, commission.contract_date, now
        ];

        db.run(commissionInsertQuery, commissionValues, function(err) {
          if (err) {
            console.error('Error saving broker commission:', err);
            return res.status(500).json({error: 'خطأ في حفظ عمولة الوسيط: ' + err.message});
          } else {
            savedCommissions++;
            console.log(`Successfully saved commission ${index + 1}. Total saved: ${savedCommissions}`);
            saveNextCommission(index + 1);
          }
        });
      };

      saveNextCommission(0);
    } else {
      console.log('=== NO BROKER COMMISSIONS TO SAVE ===');
      console.log('brokerCommissions array is empty');
      console.log('This means either:');
      console.log('1. No commission values were provided');
      console.log('2. Commission values are zero or empty');
      console.log('3. Required fields are missing');
      console.log('4. Data not reaching the server correctly');
      console.log('About to send response');
      res.json({success: true, id: contractId, commissionsSaved: 0});
      console.log('Response sent successfully');
    }
  });
});

// تحديث عقد مع ربط عمولات الوسطاء
app.put('/api/contract/:id', (req, res) => {
  console.log('=== UPDATE CONTRACT REQUEST ===');
  console.log('Contract ID:', req.params.id);
  console.log('req.body.brokerName:', req.body.brokerName);
  console.log('req.body.representativeCommission:', req.body.representativeCommission);
  console.log('req.body.brokerNameUnit:', req.body.brokerNameUnit);
  console.log('req.body.representativeCommissionUnit:', req.body.representativeCommissionUnit);
  console.log('req.body.clearanceName:', req.body.clearanceName);
  console.log('req.body.clearanceValue:', req.body.clearanceValue);
  console.log('req.body.officeCommissionInternal:', req.body.officeCommissionInternal);
  
  const {
    clientName, clientPhone, clientEmail, unitNumber, rentValue, installments, insurance, officeCommission, serviceFees,
    municipalityFile, municipalityDate, municipalityNotes, terms, onlineFees, electricityFees, waterFees,
    brokerName, brokerNameUnit, clearanceName, clearanceValue, totalCommission, commissionDeduction, attestationValueInternal, attestationDeduction, 
    representativeCommission, representativeCommissionUnit, representativeAttestation, officeCommissionInternal, internalNotes
  } = req.body;

  if (!clientName || !unitNumber || !rentValue) {
    return res.status(400).json({error: 'اسم العميل ورقم الوحدة وقيمة الإيجار مطلوبة'});
  }

  const now = new Date().toLocaleString('ar-EG');

  db.run(
    `UPDATE contracts SET 
      client_name = ?, client_phone = ?, client_email = ?, unit_number = ?, rent_value = ?, 
      installments = ?, insurance = ?, office_commission = ?, service_fees = ?,
      municipality_file = ?, municipality_date = ?, municipality_notes = ?, terms = ?, 
      online_fees = ?, electricity_fees = ?, water_fees = ?,
      broker_name = ?, broker_name_unit = ?, clearance_name = ?, clearance_value = ?, total_commission = ?, commission_deduction = ?, attestation_value = ?, 
      attestation_deduction = ?, representative_commission = ?, representative_commission_unit = ?, representative_attestation = ?, office_commission_internal = ?, 
      internal_notes = ?, broker_id = ?, created_at = ?
    WHERE id = ?`,
    [clientName, clientPhone, clientEmail, unitNumber, rentValue, installments, insurance, officeCommission, serviceFees,
      municipalityFile, municipalityDate, municipalityNotes, terms, onlineFees, electricityFees, waterFees,
      req.body.brokerName, req.body.brokerNameUnit || null, req.body.clearanceName || null, req.body.clearanceValue || null, req.body.totalCommission, req.body.commissionDeduction, req.body.attestationValueInternal, req.body.attestationDeduction,
      req.body.representativeCommission, req.body.representativeCommissionUnit || null, req.body.representativeAttestation, req.body.officeCommissionInternal, req.body.internalNotes, null, now, req.params.id],
    function(err) {
      if (err) return res.status(500).json({error: err.message});
      
      // حذف عمولات الوسطاء القديمة وإعادة إنشاؤها
      db.run('DELETE FROM broker_commissions WHERE contract_id = ?', [req.params.id], (err) => {
        if (err) {
          console.error('Error deleting old broker commissions:', err);
        } else {
          // إعادة إنشاء عمولات الوسطاء الجديدة
          const brokerCommissions = [];

          // عمولة وسيط صاحب الزبون
          if (req.body.brokerName && req.body.representativeCommission && parseFloat(req.body.representativeCommission) > 0) {
            brokerCommissions.push({
              contract_id: req.params.id,
              broker_name: req.body.brokerName,
              commission_type: 'representative_commission',
              commission_value: parseFloat(req.body.representativeCommission),
              contract_number: req.body.contractNumber,
              unit_number: unitNumber,
              client_name: clientName,
              rent_value: parseFloat(rentValue),
              contract_date: req.body.contract_date
            });
          }

          // عمولة وسيط صاحب الوحدة
          if (req.body.brokerNameUnit && req.body.representativeCommissionUnit && parseFloat(req.body.representativeCommissionUnit) > 0) {
            brokerCommissions.push({
              contract_id: req.params.id,
              broker_name: req.body.brokerNameUnit,
              commission_type: 'unit_representative_commission',
              commission_value: parseFloat(req.body.representativeCommissionUnit),
              contract_number: req.body.contractNumber,
              unit_number: unitNumber,
              client_name: clientName,
              rent_value: parseFloat(rentValue),
              contract_date: req.body.contract_date
            });
          }

          // عمولة التخليص
          if (req.body.clearanceName && req.body.clearanceValue && parseFloat(req.body.clearanceValue) > 0) {
            brokerCommissions.push({
              contract_id: req.params.id,
              broker_name: req.body.clearanceName,
              commission_type: 'clearance_commission',
              commission_value: parseFloat(req.body.clearanceValue),
              contract_number: req.body.contractNumber,
              unit_number: unitNumber,
              client_name: clientName,
              rent_value: parseFloat(rentValue),
              contract_date: req.body.contract_date
            });
          }

          // عمولة المكتب
          if (req.body.officeCommissionInternal && parseFloat(req.body.officeCommissionInternal) > 0) {
            brokerCommissions.push({
              contract_id: req.params.id,
              broker_name: 'عمولة المكتب',
              commission_type: 'office_commission',
              commission_value: parseFloat(req.body.officeCommissionInternal),
              contract_number: req.body.contractNumber,
              unit_number: unitNumber,
              client_name: clientName,
              rent_value: parseFloat(rentValue),
              contract_date: req.body.contract_date
            });
          }

          // حفظ عمولات الوسطاء الجديدة
          console.log('=== SAVING UPDATED BROKER COMMISSIONS ===');
          console.log('brokerCommissions length:', brokerCommissions.length);
          console.log('brokerCommissions:', brokerCommissions);
          
          if (brokerCommissions.length > 0) {
            const now = new Date().toLocaleString('ar-EG');
            
            const commissionInsertQuery = `
              INSERT INTO broker_commissions (
                contract_id, broker_name, commission_type, commission_value, 
                contract_number, unit_number, client_name, rent_value, contract_date, created_at
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;

            let savedCommissions = 0;
            const totalCommissions = brokerCommissions.length;

            brokerCommissions.forEach(commission => {
              const commissionValues = [
                commission.contract_id, commission.broker_name, commission.commission_type, commission.commission_value,
                commission.contract_number, commission.unit_number, commission.client_name, commission.rent_value, commission.contract_date, now
              ];

              db.run(commissionInsertQuery, commissionValues, (err) => {
                if (err) {
                  console.error('Error saving updated broker commission:', err);
                } else {
                  savedCommissions++;
                  console.log(`Saved commission ${savedCommissions}/${totalCommissions}`);
                }
                
                // إرسال الاستجابة بعد حفظ جميع العمولات
                if (savedCommissions === totalCommissions) {
                  console.log('All commissions saved successfully');
                  res.json({success: true, message: 'تم تحديث العقد بنجاح', commissionsSaved: savedCommissions});
                }
              });
            });
          } else {
            console.log('No commissions to save');
            res.json({success: true, message: 'تم تحديث العقد بنجاح', commissionsSaved: 0});
          }
        } // نهاية if (changes > 0)
      }); // نهاية db.run لتحديث العقد
    }); // نهاية app.put('/api/contract/:id')

// جلب جميع العقود
app.get('/api/contracts', (req, res) => {
  db.all(`
    SELECT * FROM contracts 
    ORDER BY created_at DESC
  `, [], (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

// جلب عقد معين
app.get('/api/contract/:id', (req, res) => {
  const contractId = req.params.id;
  
  db.get('SELECT * FROM contracts WHERE id = ?', [contractId], (err, contract) => {
    if (err) return res.status(500).json({error: err.message});
    if (!contract) return res.status(404).json({error: 'العقد غير موجود'});
    res.json(contract);
  });
});

// حذف عقد معين
app.delete('/api/contract/:id', (req, res) => {
  const contractId = req.params.id;
  console.log('=== DELETE CONTRACT REQUEST ===');
  console.log('Contract ID to delete:', contractId);
  console.log('User:', req.user);
  
  // حذف عمولات الوسطاء المرتبطة أولاً
  db.run('DELETE FROM broker_commissions WHERE contract_id = ?', [contractId], (err) => {
    if (err) {
      console.error('Error deleting broker commissions:', err);
    } else {
      console.log('Broker commissions deleted successfully for contract:', contractId);
    }
    
    // ثم حذف العقد
    db.run('DELETE FROM contracts WHERE id = ?', [contractId], function(err) {
      if (err) {
        console.error('Error deleting contract:', err);
        return res.status(500).json({error: err.message});
      }
      console.log('Contract deleted successfully:', contractId);
      res.json({success: true});
    });
  });
});

// جلب عمولات الوسطاء من جدول broker_commissions
app.get('/api/broker-commissions', (req, res) => {
  db.all(`
    SELECT 
      bc.*,
      c.contract_number,
      c.client_name,
      c.client_phone,
      c.rent_value,
      c.contract_date
    FROM broker_commissions bc
    LEFT JOIN contracts c ON bc.contract_id = c.id
    ORDER BY bc.created_at DESC
  `, [], (err, rows) => {
    if (err) return res.status(500).json({error: err.message});
    res.json(rows);
  });
});

// إضافة تخليصات افتراضية
db.run(`
  INSERT OR IGNORE INTO clearances (name, phone, email, commission_rate, created_at)
  VALUES 
  ('تخليص أبوظبي', '+971501234567', 'abudhabi@clearance.com', 5.0, ?),
  ('تخليص دبي', '+971502345678', 'dubai@clearance.com', 4.5, ?),
  ('تخليص الشارقة', '+971503456789', 'sharjah@clearance.com', 4.0, ?)
`, [now, now, now], function(err) {
  if (err) {
    console.error('Error creating default clearances:', err);
  } else {
    console.log('Default clearances ready');
  }
});

// إضافة جميع الصلاحيات للمدير
const adminId = this.lastID || 1;
const allPermissions = [
  'add_contract',
  'view_contracts', 
  'receipts',
  'broker_commissions',
  'company_work',
  'user_management'
];

allPermissions.forEach(permission => {
  db.run(`
    INSERT OR IGNORE INTO user_permissions (user_id, permission_name, is_granted, created_at)
    VALUES (?, ?, 1, ?)
  `, [adminId, permission, now]);
});
}); // نهاية db.serialize

// تحديث حالة الدفع
app.put('/api/payments/:id/payment-status', upload.array('receipt_documents', 5), (req, res) => {
  const paymentId = req.params.id;
  const { paid_amount, payment_status, payment_date_actual, notes } = req.body;
  
  if (!paid_amount || !payment_status) {
    return res.status(400).json({error: 'المبلغ المدفوع وحالة الدفع مطلوبان'});
  }
  
  const receiptDocuments = req.files ? req.files.map(file => file.filename).join(',') : '';
  const now = new Date().toLocaleString('ar-EG');
  
  // تحديث حالة الدفع
  db.run(`
    UPDATE payments SET 
      paid_amount = ?, 
      payment_status = ?, 
      payment_date_actual = ?, 
      receipt_documents = CASE 
        WHEN ? != '' THEN CASE 
          WHEN receipt_documents IS NULL OR receipt_documents = '' THEN ?
          ELSE receipt_documents || ',' || ?
        END
        ELSE receipt_documents
      END,
      updated_at = ?
    WHERE id = ?
  `, [
    parseFloat(paid_amount), 
    payment_status, 
    payment_date_actual || null, 
    receiptDocuments, 
    receiptDocuments, 
    receiptDocuments, 
    now, 
    paymentId
  ], function(err) {
    if (err) return res.status(500).json({error: err.message});
    
    if (this.changes === 0) {
      return res.status(404).json({error: 'الدفعة غير موجودة'});
    }
    
    res.json({success: true, message: 'تم تحديث حالة الدفع بنجاح'});
  });
});

// جلب تفاصيل دفعة معينة مع حساب حالة الدفع
app.get('/api/payments/:id/details', (req, res) => {
  const paymentId = req.params.id;
  
  db.get(`
    SELECT p.*, u.unit_number, b.name as building_name,
           CASE 
             WHEN p.paid_amount >= p.amount THEN 'paid_full'
             WHEN p.paid_amount > 0 THEN 'paid_partial'
             WHEN p.due_date < date('now') THEN 'overdue'
             ELSE 'pending'
           END as calculated_status
    FROM payments p 
    LEFT JOIN units u ON p.unit_id = u.id
    LEFT JOIN buildings b ON u.building_id = b.id
    WHERE p.id = ?
  `, [paymentId], (err, payment) => {
    if (err) return res.status(500).json({error: err.message});
    if (!payment) return res.status(404).json({error: 'الدفعة غير موجودة'});
    
    // حساب النسبة المئوية للدفع
    const paymentPercentage = payment.amount > 0 ? (payment.paid_amount / payment.amount) * 100 : 0;
    
    res.json({
      ...payment,
      payment_percentage: Math.round(paymentPercentage * 100) / 100,
      remaining_amount: payment.amount - payment.paid_amount
    });
  });
});

// تشغيل الخادم
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
