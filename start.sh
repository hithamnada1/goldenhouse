#!/bin/bash

# إنشاء المجلدات المطلوبة
mkdir -p uploads database

# تعيين الصلاحيات
chmod 755 uploads database

# تشغيل التطبيق
npm start 