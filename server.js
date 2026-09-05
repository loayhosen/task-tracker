require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

// ============================================================
//  الاتصال بقاعدة البيانات مع خيارات محسّنة لتجاوز مشاكل DNS
// ============================================================
const MONGODB_URI = process.env.MONGODB_URI;

console.log('🚀 محاولة الاتصال بـ MongoDB Atlas...');

mongoose.connect(MONGODB_URI, {
    serverSelectionTimeoutMS: 10000, // مهلة اختيار الخادم 10 ثوانٍ
    socketTimeoutMS: 45000,
    family: 4, // إجبار استخدام IPv4
    retryWrites: true,
    w: 'majority'
})
.then(() => console.log('✅ MongoDB connected successfully'))
.catch(err => {
    console.error('❌ MongoDB connection error:', err);
    console.log('💡 تأكد من:');
    console.log('  1. أنك أضفت 0.0.0.0/0 في Network Access');
    console.log('  2. أن اسم المستخدم وكلمة المرور صحيحان');
    console.log('  3. أن الرابط في ملف .env صحيح');
});

// ============================================================
//  استيراد النماذج
// ============================================================
const User = require('./models/User');
const Project = require('./models/Project');

const JWT_SECRET = process.env.JWT_SECRET || 'mySuperSecretKey12345';

// ============================================================
//  دوال مساعدة
// ============================================================
function validatePassword(password) {
    const errors = [];
    if (password.length < 8) errors.push('يجب أن تكون كلمة المرور 8 محارف على الأقل');
    if (!/[A-Z]/.test(password)) errors.push('يجب أن تحتوي على حرف كبير واحد على الأقل');
    if (!/[a-z]/.test(password)) errors.push('يجب أن تحتوي على حرف صغير واحد على الأقل');
    if (!/[0-9]/.test(password)) errors.push('يجب أن تحتوي على رقم واحد على الأقل');
    return errors;
}

// ============================================================
//  واجهات API
// ============================================================

// -------------------- تسجيل مستخدم جديد --------------------
app.post('/api/signup', async (req, res) => {
    try {
        const { username, password } = req.body;

        // التحقق من صحة الإدخال
        if (!username || !password) {
            return res.status(400).json({ message: 'الرجاء ملء جميع الحقول' });
        }

        // التحقق من وجود المستخدم
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'اسم المستخدم محجوز، الرجاء اختيار اسم آخر' });
        }

        // التحقق من صحة كلمة المرور
        const errors = validatePassword(password);
        if (errors.length > 0) {
            return res.status(400).json({ message: errors.join(' • ') });
        }

        // تشفير كلمة المرور
        const hashedPassword = await bcrypt.hash(password, 10);

        // إنشاء المستخدم
        const user = new User({ username, password: hashedPassword });
        await user.save();

        // إنشاء ملف مشاريع فارغ للمستخدم
        const project = new Project({ username, projects: [] });
        await project.save();

        res.json({ message: 'تم إنشاء الحساب بنجاح' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'خطأ في الخادم' });
    }
});

// -------------------- تسجيل الدخول --------------------
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'الرجاء ملء جميع الحقول' });
        }

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ message: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ message: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
        }

        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ message: 'تم تسجيل الدخول بنجاح', token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'خطأ في الخادم' });
    }
});

// -------------------- تغيير كلمة المرور --------------------
app.post('/api/change-password', async (req, res) => {
    try {
        const { username, oldPassword, newPassword } = req.body;

        if (!username || !oldPassword || !newPassword) {
            return res.status(400).json({ message: 'الرجاء ملء جميع الحقول' });
        }

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).json({ message: 'المستخدم غير موجود' });
        }

        const valid = await bcrypt.compare(oldPassword, user.password);
        if (!valid) {
            return res.status(401).json({ message: 'كلمة المرور الحالية غير صحيحة' });
        }

        const errors = validatePassword(newPassword);
        if (errors.length > 0) {
            return res.status(400).json({ message: errors.join(' • ') });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();

        res.json({ message: 'تم تغيير كلمة المرور بنجاح' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'خطأ في الخادم' });
    }
});

// -------------------- جلب مشاريع المستخدم --------------------
app.get('/api/projects/:username', async (req, res) => {
    try {
        const { username } = req.params;
        const projectDoc = await Project.findOne({ username });

        if (!projectDoc) {
            return res.json({ projects: [] });
        }

        res.json(projectDoc.projects);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'خطأ في الخادم' });
    }
});

// -------------------- حفظ مشاريع المستخدم --------------------
app.post('/api/projects/:username', async (req, res) => {
    try {
        const { username } = req.params;
        const { projects } = req.body;

        const userExists = await User.findOne({ username });
        if (!userExists) {
            return res.status(404).json({ message: 'المستخدم غير موجود' });
        }

        await Project.findOneAndUpdate(
            { username },
            { projects },
            { upsert: true, new: true }
        );

        res.json({ message: 'تم حفظ المشاريع بنجاح' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'خطأ في الخادم' });
    }
});

// -------------------- تسجيل الخروج --------------------
app.post('/api/logout', (req, res) => {
    res.json({ message: 'تم تسجيل الخروج' });
});

// ============================================================
//  تشغيل الخادم
// ============================================================
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});