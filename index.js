const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require('multer');
const path = require('path');
const fs = require("fs");
const { v4: uuidv4 } = require("uuid");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("cloudinary").v2;

require('dotenv').config();

const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Cloudinary Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || "YOUR_CLOUD_NAME",
  api_key: process.env.CLOUDINARY_API_KEY || "YOUR_API_KEY",
  api_secret: process.env.CLOUDINARY_API_SECRET || "YOUR_API_SECRET",
});

// -------------------
// Multer Storage Configurations
// -------------------

// Cloudinary Storage for Categories
const categoryStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "categories",
    allowed_formats: ["jpg", "jpeg", "png", "webp", "gif"],
    transformation: [
      { width: 800, height: 600, crop: "limit", quality: "auto" }
    ]
  },
});

// Cloudinary Storage for Banners
const bannerStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "banners",
    allowed_formats: ["jpg", "jpeg", "png", "webp", "gif"],
    transformation: [
      { width: 1200, height: 400, crop: "limit", quality: "auto" }
    ]
  },
});

// Cloudinary Storage for Products
const productStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "products",
    allowed_formats: ["jpg", "jpeg", "png", "webp", "gif"],
    transformation: [
      { width: 600, height: 600, crop: "limit", quality: "auto" }
    ]
  },
});

// Multer upload instances
const uploadCategory = multer({ 
  storage: categoryStorage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

const uploadBanner = multer({ 
  storage: bannerStorage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

const uploadProduct = multer({ 
  storage: productStorage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  }
});

mongoose.connect(process.env.MONGODB_URIs, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});
// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  loyaltyCoins: { type: Number, default: 0 },
  referralCode: { type: String, unique: true },
  referredBy: { type: String, default: null },
  referralCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);

// Product Schema
const ProductSchema = new mongoose.Schema({
  // Basic Information
  title: { type: String, required: true },
  subtitle: String,
  sku: { type: String, required: true, unique: true },
  
  // Pricing
  price: { type: Number, required: true },
  mrp: { type: Number, required: true },
  discount: Number,
  
  images: [String],
  // Inventory
  inStock: { type: Boolean, default: true },
  stockQuantity: { type: Number, default: 0 },
  lowStockAlert: { type: Number, default: 10 },
  
  // Categorization
  category: {
    mainCategory: { type: String, required: true },
    subCategory: String,
    offerCategory: { type: mongoose.Schema.Types.ObjectId, ref: 'OfferCategory' },
    offerSubCategory: { type: mongoose.Schema.Types.ObjectId, ref: 'OfferSubCategory' }
  },
  
  // Product Details
  brand: String,
  description: String,
  specifications: [{
    key: String,
    value: String
  }],
  
  // Physical Attributes
  weight: String,
  dimensions: String,
  
  // Shipping
  shippingWeight: Number,
  isFreeShipping: { type: Boolean, default: false },
  
  // Delivery & Logistics
  deliveryTime: String,
  
  // Marketing Flags
  isTopSelling: { type: Boolean, default: false },
  isTodaysDeal: { type: Boolean, default: false },
  isHotDeal: { type: Boolean, default: false },
  isFeatured: { type: Boolean, default: false },
  
  // SEO
  metaTitle: String,
  metaDescription: String,
  slug: String,
  
  // Status
  status: { type: String, enum: ['active', 'draft', 'archived'], default: 'draft' },
  
  // Analytics
  viewCount: { type: Number, default: 0 },
  purchaseCount: { type: Number, default: 0 },
  
  // Timestamps
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Generate SKU before saving
ProductSchema.pre('save', function(next) {
  if (!this.sku) {
    const timestamp = Date.now().toString().slice(-6);
    const random = Math.random().toString(36).substring(2, 5).toUpperCase();
    const brandPrefix = this.brand ? 
      this.brand.replace(/\s+/g, '').substring(0, 3).toUpperCase() : 'PRO';
    this.sku = `${brandPrefix}-${timestamp}-${random}`;
  }
  
  // Generate slug from title
  if (this.title && !this.slug) {
    this.slug = this.title
      .toLowerCase()
      .replace(/[^a-z0-9 -]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-');
  }
  
  // Calculate discount
  if (this.mrp && this.price) {
    this.discount = Math.round(((this.mrp - this.price) / this.mrp) * 100);
  }
  
  this.updatedAt = new Date();
  next();
});

const Product = mongoose.model('Product', ProductSchema);

// Cart Schema
const cartSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    productId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Product",
      required: true,
    },
    title: {
      type: String,
      required: true,
    },
    image: {
      type: String,
    },
    price: {
      type: Number,
      required: true,
    },
    quantity: {
      type: Number,
      default: 1,
      min: 1,
    },
  },
  {
    timestamps: true,
  }
);

cartSchema.index({ userId: 1, productId: 1 }, { unique: true });
const Cart = mongoose.model("Cart", cartSchema);

// Category Schema
const CategorySchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  type: { type: String, enum: ['main', 'sub'], required: true },
  parentCategory: String,
  icon: String,
  bannerImage: String, // This will store Cloudinary URL
  createdAt: { type: Date, default: Date.now }
});

const Category = mongoose.model('Category', CategorySchema);

// Order Schema
const orderSchema = new mongoose.Schema({
  orderId: {
    type: String,
    unique: true,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  items: [{
    productId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Product',
      required: true
    },
    title: String,
    image: String,
    quantity: {
      type: Number,
      required: true
    },
    price: {
      type: Number,
      required: true
    }
  }],
  address: {
    type: Object,
    required: true
  },
  paymentMethod: {
    type: String,
    enum: ['upi', 'card', 'cod', 'wallet'],
    required: true
  },
  deliverySlot: String,
  coupon: {
    code: String,
    discount: Number,
    description: String
  },
  referralCoinsUsed: {
    type: Number,
    default: 0
  },
  subtotal: Number,
  discount: Number,
  deliveryFee: Number,
  total: Number,

  status: {
    type: String,
    enum: ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'],
    default: 'pending'
  },
  paymentStatus: {
    type: String,
    enum: ['pending', 'paid', 'failed'],
    default: 'pending'
  },
  orderStatus: {
    type: String,
    enum: ['new', 'processing', 'shipped', 'delivered', 'cancelled'],
    default: 'new'
  }, 
  coinsEarned: {
    type: Number,
    default: 0
  },
  referralCoinsUsed: {
    type: Number,
    default: 0
  },
      statusHistory: [{
    status: {
      type: String,
      enum: ['new', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled']
    },
    timestamp: {
      type: Date,
      default: Date.now
    },
    notes: String,
    updatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  }],
  totalAmount: Number,
}, {
  timestamps: true
});

orderSchema.pre('save', function(next) {
  if (!this.orderId) {
    this.orderId = `ORD${Date.now()}${Math.random().toString(36).substr(2, 5)}`.toUpperCase();
  }
  next();
});

const Order = mongoose.model('Order', orderSchema);

// Address Schema
const addressSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  label: {
    type: String,
    enum: ['Home', 'Work', 'Other'],
    default: 'Home'
  },
  fullName: {
    type: String,
    required: true
  },
  mobile: {
    type: String,
    required: true
  },
  pincode: {
    type: String,
    required: true
  },
  address: {
    type: String,
    required: true
  },
  locality: String,
  city: {
    type: String,
    required: true
  },
  state: String,
  landmark: String,
  isDefault: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

const Address = mongoose.model('Address', addressSchema);

// Referral Schema
const referralSchema = new mongoose.Schema({
  referrerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  referredUserId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  referralCode: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'completed', 'cancelled'],
    default: 'pending'
  },
  rewardCoins: {
    type: Number,
    default: 0
  },
  completedAt: {
    type: Date
  },
  completedOrderId: {
    type: String
  }
}, {
  timestamps: true
});

referralSchema.index({ referredUserId: 1 }, { unique: true });
referralSchema.index({ referrerId: 1, status: 1 });

referralSchema.methods.completeReferral = function(orderId) {
  this.status = 'completed';
  this.rewardCoins = 50;
  this.completedAt = new Date();
  this.completedOrderId = orderId;
  return this.save();
};

const Referral = mongoose.model('Referral', referralSchema);

// Referral Usage Schema
const referralUsageSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  coinsUsed: {
    type: Number,
    required: true
  },
  discountAmount: {
    type: Number,
    required: true
  },
  orderId: String,
  previousBalance: Number,
  newBalance: Number
}, {
  timestamps: true
});

const ReferralUsage = mongoose.model('ReferralUsage', referralUsageSchema);

const zoneSchema = new mongoose.Schema({
  name: { type: String, required: true },
  pincodes: { type: [String], required: true },
  deliveryFee: { type: Number, required: true },
  deliveryTime: { type: String, required: true },
  minimumOrderValue: { type: Number, required: true },
});

const Zone = mongoose.model('Zone', zoneSchema);
// models/Notification.js

const NotificationSchema = new mongoose.Schema(
  {
    message: { type: String, required: true },
    read: { type: Boolean, default: false },

  },
  { timestamps: true }
);
const Notification = mongoose.model('Notification', NotificationSchema)
const BannerSchema = new mongoose.Schema({
  name: String,
  imageUrl: String // This will store Cloudinary URL
});

const Banner = mongoose.model("Banner", BannerSchema);
// Loyalty Transaction Schema
const loyaltyTransactionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  type: {
    type: String,
    enum: [
      'admin_added',
      'admin_deducted', 
      'purchase_earned',
      'referral_earned',
      'referral_used',
      'order_used',
      'expired'
    ],
    required: true
  },
  coins: {
    type: Number,
    required: true
  },
  previousBalance: {
    type: Number,
    required: true
  },
  newBalance: {
    type: Number,
    required: true
  },
  reason: {
    type: String,
    required: true
  },
  orderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Order'
  },
  adminId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  status: {
    type: String,
    enum: ['pending', 'completed', 'cancelled'],
    default: 'completed'
  }
}, {
  timestamps: true
});

const LoyaltyTransaction = mongoose.model('LoyaltyTransaction', loyaltyTransactionSchema);
// Delivery Staff Schema
const DeliveryStaffSchema = new mongoose.Schema({
  name: { type: String, required: true },
  contact: String,
  email: String,
  vehicleDetails: {
    type: String,
    number: String
  },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const DeliveryStaff = mongoose.model('DeliveryStaff', DeliveryStaffSchema);
const offerCategorySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  icon: {
    type: String,
    required: true
  },
  color: {
    type: String,
    default: '#EF4444'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  displayOrder: {
    type: Number,
    default: 0
  }
}, { timestamps: true });

const offerSubCategorySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  image: {
    type: String,
    required: true
  },
  category: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'OfferCategory',
    required: true
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, { timestamps: true });

const offerSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  discount: {
    type: String,
    required: true
  },
  code: {
    type: String,
    required: true,
    unique: true
  },
  image: {
    type: String,
    required: true
  },
  category: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'OfferCategory',
    required: true
  },
  subcategory: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'OfferSubCategory',
    required: true
  },
  startDate: {
    type: Date,
    default: Date.now
  },
  endDate: {
    type: Date
  },
  isActive: {
    type: Boolean,
    default: true
  },
  usageLimit: {
    type: Number,
    default: 1000
  },
  usedCount: {
    type: Number,
    default: 0
  },
  minOrderValue: {
    type: Number,
    default: 0
  },
  maxDiscount: {
    type: Number
  }
}, { timestamps: true });

const OfferCategory = mongoose.model('OfferCategory', offerCategorySchema);
const OfferSubCategory = mongoose.model('OfferSubCategory', offerSubCategorySchema);
const Offer = mongoose.model('Offer', offerSchema);

// ==================== MIDDLEWARE ====================

const authMiddleware = (req, res, next) => {
  const token = req.header("Authorization");
  if (!token) return res.status(401).json({ message: "Access denied, no token provided" });

  try {
    const tokenValue = token.startsWith('Bearer ') ? token.slice(7) : token;
    const decoded = jwt.verify(tokenValue, process.env.JWT_SECRET || "BANNU9");
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).json({ message: "Invalid token" });
  }
};


function generateReferralCode(name) {
  const random = Math.floor(1000 + Math.random() * 9000);
  const prefix = name ? name.slice(0, 3).toUpperCase() : "USR";
  return prefix + random;
}
// Example implementation of the utility function
async function deleteFromCloudinary(publicId) {
  if (!publicId) return; // Safety check

  // Assuming 'cloudinary' is configured globally
  const result = await cloudinary.uploader.destroy(publicId);
  
  if (result.result !== 'ok' && result.result !== 'not found') {
    // Treat unexpected results as a warning or error
    throw new Error(`Cloudinary returned non-success status: ${result.result}`);
  }
  return result;
}

// ==================== ROUTES ====================

// Health check
app.get("/", (req, res) => res.send("✅ Grocery Backend Running!"));

// ==================== AUTH ROUTES ====================

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const referralCode = (req.body.referralCode || "").trim().toUpperCase();

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ success: false, message: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const generatedCode = generateReferralCode(name);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      referralCode: generatedCode,
      referredBy: referralCode || null,
    });

    if (referralCode) {
      const referrer = await User.findOne({ referralCode });
      if (referrer) {
        referrer.loyaltyCoins += 50;
        referrer.referralCount += 1;
        await referrer.save();

        newUser.loyaltyCoins = 20;

        await Referral.create({
          referrerId: referrer._id,
          referredUserId: newUser._id,
          referralCode,
          status: "pending",
        });
      }
    }

    await newUser.save();

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      referralCode: generatedCode,
    });
  } catch (error) {
    console.error("Registration Error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { _id: user._id, email: user.email },
      process.env.JWT_SECRET || "BANNU9",
      { expiresIn: "7d" }
    );

    res.status(200).json({
      success: true,
      message: "Login successful",
      token,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        loyaltyCoins: user.loyaltyCoins,
        referralCode: user.referralCode
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Profile
app.get("/api/profile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select("-password");
    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ==================== CATEGORY ROUTES ====================

// Get all categories
app.get('/api/categories', async (req, res) => {
  try {
    const categories = await Category.find().sort({ type: 1, name: 1 });
    res.json(categories);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create category with Cloudinary upload
app.post('/api/categories', uploadCategory.single('bannerImage'), async (req, res) => {
  try {
    const { name, type, parentCategory, icon } = req.body;

    if (!name || !type) {
      return res.status(400).json({ message: 'Name and type are required' });
    }

    if (type === 'sub' && !parentCategory) {
      return res.status(400).json({ message: 'Parent category is required for sub-categories' });
    }

    const existingCategory = await Category.findOne({ name });
    if (existingCategory) {
      return res.status(400).json({ message: 'Category with this name already exists' });
    }

    // Cloudinary uploaded image URL
    const bannerImageUrl = req.file ? req.file.path : '';

    const category = await Category.create({
      name,
      type,
      parentCategory: type === "sub" ? parentCategory : null,
      icon,
      bannerImage: bannerImageUrl,
    });

    res.status(201).json(category);

  } catch (error) {
    console.error('Error creating category:', error);
    res.status(500).json({ message: error.message });
  }
});

// Update category with Cloudinary
app.put('/api/categories/:id', uploadCategory.single('bannerImage'), async (req, res) => {
  try {
    const { name, type, parentCategory, icon } = req.body;
    const categoryId = req.params.id;

    const existingCategory = await Category.findById(categoryId);
    if (!existingCategory) {
      return res.status(404).json({ message: 'Category not found' });
    }

    let bannerImageUrl = existingCategory.bannerImage;

    // If new image uploaded
    if (req.file) {
      // Delete old image from Cloudinary
      if (existingCategory.bannerImage) {
        await deleteFromCloudinary(existingCategory.bannerImage);
      }

      // Use new uploaded image from Cloudinary
      bannerImageUrl = req.file.path;
    }

    const updateData = {
      name,
      type,
      icon,
      parentCategory: type === "sub" ? parentCategory : null,
      bannerImage: bannerImageUrl
    };

    const updatedCategory = await Category.findByIdAndUpdate(
      categoryId,
      updateData,
      { new: true, runValidators: true }
    );

    res.json(updatedCategory);

  } catch (error) {
    console.error('Error updating category:', error);
    res.status(500).json({ message: error.message });
  }
});

// Delete category with Cloudinary cleanup
app.delete('/api/categories/:id', async (req, res) => {
  try {
    const category = await Category.findById(req.params.id);
    if (!category) {
      return res.status(404).json({ message: 'Category not found' });
    }

    if (category.type === 'main') {
      const subCategoriesCount = await Category.countDocuments({ 
        parentCategory: category.name, 
        type: 'sub' 
      });
      if (subCategoriesCount > 0) {
        return res.status(400).json({ 
          message: 'Cannot delete main category with existing sub-categories' 
        });
      }
    }

    // Delete banner image from Cloudinary
    if (category.bannerImage) {
      await deleteFromCloudinary(category.bannerImage);
    }

    await Category.findByIdAndDelete(req.params.id);
    res.json({ message: 'Category deleted successfully' });
  } catch (error) {
    console.error('Error deleting category:', error);
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/products', async (req, res) => {
  try {
    const { page = 1, limit = 10, search, category, stockStatus } = req.query;
    
    let query = {};

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { "category.mainCategory": { $regex: search, $options: "i" } }
      ];
    }

    if (category) {
      query["category.mainCategory"] = category;
    }

    if (stockStatus === "in_stock") {
      query.inStock = true;
    } else if (stockStatus === "out_of_stock") {
      query.inStock = false;
    }

    const products = await Product.find(query)
      .populate("category.offerCategory")       // ✅ populate main offer category
      .populate("category.offerSubCategory")    // ✅ populate sub-offer category
      .limit(Number(limit))
      .skip((page - 1) * Number(limit))
      .sort({ createdAt: -1 });

    const total = await Product.countDocuments(query);

    res.json({
      products,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// Get single product
app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json(product);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/products', uploadProduct.array('images', 10), async (req, res) => {
  try {
    console.log('Received product creation request');
    console.log('Body fields:', req.body);
    console.log('Files:', req.files);
    
    // Log all received fields
    Object.keys(req.body).forEach(key => {
      console.log(`${key}:`, req.body[key]);
    });

    const {
      title,
      subtitle,
      sku,
      price,
      mrp,
      description,
      brand,
      mainCategory,
      subCategory,
      offerCategory,
      offerSubCategory,
      weight,
      dimensions,
      shippingWeight,
      stockQuantity,
      inStock,
      deliveryTime,
      lowStockAlert,
      isFreeShipping,
      isTopSelling,
      isTodaysDeal,
      isHotDeal,
      isFeatured,
      metaTitle,
      metaDescription,
      status,
      specifications
    } = req.body;

    // Check required fields
    if (!title || !price || !mrp || !mainCategory) {
      console.log('Missing required fields:', { title, price, mrp, mainCategory });
      return res.status(400).json({ 
        error: 'Missing required fields: title, price, mrp, mainCategory' 
      });
    }


    // Check if SKU already exists
    if (sku) {
      const existingProduct = await Product.findOne({ sku });
      if (existingProduct) {
        return res.status(400).json({ error: 'SKU already exists' });
      }
    }

    // Parse specifications if provided
    let parsedSpecifications = [];
    try {
      if (specifications) {
        parsedSpecifications = JSON.parse(specifications);
      }
    } catch (parseError) {
      return res.status(400).json({ error: 'Invalid specifications format' });
    }

    // Handle images - use unified images array
    const images = req.files ? req.files.map(file => file.path) : [];

    // Prepare product data
    const productData = {
      title,
      subtitle,
      sku,
      price: parseFloat(price),
      mrp: parseFloat(mrp),
      description,
      brand,
      category: {
        mainCategory,
        subCategory,
        offerCategory: offerCategory || undefined,
        offerSubCategory: offerSubCategory || undefined
      },
      weight,
      dimensions,
      shippingWeight: shippingWeight ? parseFloat(shippingWeight) : undefined,
      deliveryTime,
      stockQuantity,
      lowStockAlert: parseInt(lowStockAlert) || 10,
      stockQuantity: parseInt(stockQuantity) || 0,
      inStock: inStock !== 'false',
      isFreeShipping: isFreeShipping === 'true',
      isTopSelling: isTopSelling === 'true',
      isTodaysDeal: isTodaysDeal === 'true',
      isHotDeal: isHotDeal === 'true',
      isFeatured: isFeatured === 'true',
      metaTitle,
      metaDescription,
      status: status || 'draft',
      specifications: parsedSpecifications,
      images // Use unified images array
    };

    // Create and save product
    const product = new Product(productData);
    await product.save();

    // Populate offer categories if they exist
    if (offerCategory || offerSubCategory) {
      await product.populate('category.offerCategory');
      await product.populate('category.offerSubCategory');
    }

    res.status(201).json({
      message: 'Product created successfully',
      product
    });

  } catch (error) {
    console.error('Error creating product:', error);
    
    // Clean up uploaded images if product creation fails
    if (req.files && req.files.length > 0) {
      try {
        for (const file of req.files) {
          await deleteFromCloudinary(file.path);
        }
      } catch (deleteError) {
        console.error('Error cleaning up images:', deleteError);
      }
    }
    
    res.status(400).json({ 
      error: error.message || 'Failed to create product' 
    });
  }
});
app.post('/api/products/upload', uploadProduct.array('images', 10), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'No images uploaded' });
    }

    const imageUrls = req.files.map(file => file.path);

    res.json({
      message: 'Images uploaded successfully',
      images: imageUrls,
      count: imageUrls.length
    });
  } catch (error) {
    console.error('Error uploading images:', error);
    res.status(500).json({ error: 'Failed to upload images' });
  }
});
app.put('/api/products/:id', uploadProduct.array('images', 10), async (req, res) => {
  try {
    const existingProduct = await Product.findById(req.params.id);
    if (!existingProduct) {
      return res.status(404).json({ error: 'Product not found' });
    }

    let images = existingProduct.images || [];

    // Handle new images
    if (req.files && req.files.length > 0) {
      // Delete old images if replacing
      if (req.body.replaceImages === 'true' && existingProduct.images.length > 0) {
        for (const oldImage of existingProduct.images) {
          await deleteFromCloudinary(oldImage);
        }
        images = [];
      }
      
      // Add new images
      const newImages = req.files.map(file => file.path);
      images = [...images, ...newImages];
    }

    // Parse specifications if provided
    let parsedSpecifications = existingProduct.specifications;
    try {
      if (req.body.specifications) {
        parsedSpecifications = JSON.parse(req.body.specifications);
      }
    } catch (parseError) {
      return res.status(400).json({ error: 'Invalid specifications format' });
    }

    const productData = {
      ...req.body,
      price: req.body.price ? parseFloat(req.body.price) : existingProduct.price,
      mrp: req.body.mrp ? parseFloat(req.body.mrp) : existingProduct.mrp,
      stockQuantity: req.body.stockQuantity ? parseInt(req.body.stockQuantity) : existingProduct.stockQuantity,
      lowStockAlert: req.body.lowStockAlert ? parseInt(req.body.lowStockAlert) : existingProduct.lowStockAlert,
      shippingWeight: req.body.shippingWeight ? parseFloat(req.body.shippingWeight) : existingProduct.shippingWeight,
      images: images,
      specifications: parsedSpecifications,
      updatedAt: new Date()
    };

    // Handle category updates
    if (req.body.mainCategory || req.body.subCategory || req.body.offerCategory || req.body.offerSubCategory) {
      productData.category = {
        mainCategory: req.body.mainCategory || existingProduct.category.mainCategory,
        subCategory: req.body.subCategory || existingProduct.category.subCategory,
        offerCategory: req.body.offerCategory || existingProduct.category.offerCategory,
        offerSubCategory: req.body.offerSubCategory || existingProduct.category.offerSubCategory
      };
    }

    const product = await Product.findByIdAndUpdate(
      req.params.id,
      productData,
      { new: true, runValidators: true }
    ).populate('category.offerCategory')
     .populate('category.offerSubCategory');
    
    res.json({
      message: 'Product updated successfully',
      product
    });
  } catch (error) {
    console.error('Error updating product:', error);
    
    // Clean up uploaded images if update fails
    if (req.files && req.files.length > 0) {
      try {
        for (const file of req.files) {
          await deleteFromCloudinary(file.path);
        }
      } catch (deleteError) {
        console.error('Error cleaning up images:', deleteError);
      }
    }
    
    res.status(400).json({ 
      error: error.message || 'Failed to update product' 
    });
  }
});

// Delete product with Cloudinary cleanup
app.delete('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // Delete product image from Cloudinary
    if (product.image) {
      await deleteFromCloudinary(product.image);
    }

    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: 'Product deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== BANNER ROUTES ====================

// Create banner with Cloudinary upload
app.post("/api/banner", uploadBanner.single("image"), async (req, res) => {
  try {
    const { name } = req.body;

    if (!name || !req.file) {
      return res.status(400).json({ error: "Name and image are required" });
    }

    const banner = await Banner.create({
      name,
      imageUrl: req.file.path, // Cloudinary secure URL
    });

    res.status(201).json(banner);
  } catch (error) {
    console.error("Banner Upload Error:", error);
    res.status(500).json({ error: "Failed to upload banner" });
  }
});

// Get all banners
app.get("/api/banners", async (req, res) => {
  try {
    const banners = await Banner.find();
    res.json(banners);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put("/api/banner/:id", uploadBanner.single("image"), async (req, res) => {
  try {
    const banner = await Banner.findById(req.params.id);
    if (!banner) {
      // 404: Resource not found
      return res.status(404).json({ error: "Banner not found" });
    }

    // 1. Prepare Update Data
    // Ensure 'name' is updated if provided, otherwise keep the old name
    let updateData = { 
      name: req.body.name || banner.name 
    };

    // 2. Handle Image Replacement (If a new file is uploaded)
    if (req.file) {
      // 2a. Delete old image from Cloudinary (using the stored publicId)
      if (banner.publicId) {
        try {
          // Use the stored publicId for deletion (safest method)
          await deleteFromCloudinary(banner.publicId);
        } catch (cleanupError) {
          // Log cleanup failure but DO NOT stop the main update flow
          console.warn(`Cloudinary cleanup failed for ID ${banner.publicId}. Continuing update. Error: ${cleanupError.message}`);
        }
      }

      // 2b. Update the database fields with new file details
      // req.file.path holds the new Cloudinary URL (secureUrl)
      updateData.imageUrl = req.file.path; 
      // req.file.filename or req.file.public_id holds the new public ID
      updateData.publicId = req.file.filename || req.file.public_id; 
    }

    // 3. Perform Database Update
    const updatedBanner = await Banner.findByIdAndUpdate(
      req.params.id,
      updateData,
      // { new: true } returns the updated document
      // { runValidators: true } ensures Mongoose schema validation runs on the update
      { new: true, runValidators: true } 
    );

    res.json(updatedBanner);

  } catch (error) {
    // 4. Handle Errors
    console.error("Update Banner Fatal Error:", error);

    // Mongoose Validation Error (e.g., required field is missing)
    if (error.name === 'ValidationError') {
        return res.status(400).json({ error: error.message });
    }

    // Generic Internal Server Error
    res.status(500).json({ error: error.message || "Update failed due to server error." });
  }
});
// Delete banner with Cloudinary cleanup
app.delete("/api/banner/:id", async (req, res) => {
  try {
    const banner = await Banner.findById(req.params.id);
    if (!banner) return res.status(404).json({ error: "Banner not found" });

    // Delete image from Cloudinary
    if (banner.imageUrl) {
      await deleteFromCloudinary(banner.imageUrl);
    }

    await Banner.findByIdAndDelete(req.params.id);

    res.json({ message: "Banner deleted successfully" });
  } catch (error) {
    console.error("Delete Banner Error:", error);
    res.status(500).json({ error: "Delete failed" });
  }
});

// ==================== CART ROUTES ====================

app.post("/api/cart", async (req, res) => {
  try {
    const { userId, productId, title, price, image, quantity } = req.body;

    // Validate required fields
    if (!userId || !productId || !title || !price || !image) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields (userId, productId, title, price, image)",
      });
    }

    const finalQuantity = quantity && quantity > 0 ? quantity : 1;

    let cartItem = await Cart.findOne({ userId, productId });

    if (cartItem) {
      cartItem.quantity += finalQuantity;
      await cartItem.save();

      return res.status(200).json({
        success: true,
        message: "Product quantity updated in cart",
        cartItem,
      });
    }

    const newCartItem = await Cart.create({
      userId,
      productId,
      title,
      price,
      image,
      quantity: finalQuantity,
    });

    return res.status(201).json({
      success: true,
      message: "Product added to cart successfully",
      cartItem: newCartItem,
    });
  } catch (error) {
    console.error("❌ Error adding to cart:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error while adding to cart",
      error: error.message,
    });
  }
});

app.get("/api/cart/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: "User ID is required in the URL",
      });
    }

    const cartItems = await Cart.find({ userId }).populate("productId");

    return res.status(200).json({
      success: true,
      message: "Cart items fetched successfully",
      cartItems,
    });
  } catch (error) {
    console.error("❌ Error fetching cart items:", error);
    return res.status(500).json({
      success: false,
      message: "Server error while fetching cart items",
      error: error.message,
    });
  }
});

app.delete("/api/cart/:userId/:productId", async (req, res) => {
  try {
    const { userId, productId } = req.params;

    const deletedItem = await Cart.findOneAndDelete({ userId, productId });

    if (!deletedItem) {
      return res.status(404).json({
        success: false,
        message: "Item not found in cart",
      });
    }

    return res.status(200).json({
      success: true,
      message: "Item removed from cart successfully",
    });
  } catch (error) {
    console.error("❌ Error deleting cart item:", error);
    return res.status(500).json({
      success: false,
      message: "Server error while deleting cart item",
      error: error.message,
    });
  }
});

app.get('/api/address', authMiddleware, async (req, res) => {
  try {
    const addresses = await Address.find({ userId: req.user._id });
    res.json(addresses);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/address', authMiddleware, async (req, res) => {
  const session = await mongoose.startSession();
  
  try {
    await session.startTransaction();

    const userId = req.user._id;
    const { isDefault, ...addressData } = req.body;

    if (!addressData.fullName || !addressData.mobile || !addressData.pincode || !addressData.address || !addressData.city) {
      await session.abortTransaction();
      return res.status(400).json({ 
        success: false, 
        message: "Missing required fields" 
      });
    }

    if (!/^[6-9]\d{9}$/.test(addressData.mobile)) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: "Invalid mobile number format"
      });
    }

    if (!/^\d{6}$/.test(addressData.pincode)) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: "Invalid pincode format"
      });
    }

    if (isDefault) {
      await Address.updateMany(
        { userId },
        { $set: { isDefault: false } },
        { session }
      );
    }

    const addressCount = await Address.countDocuments({ userId });
    const shouldSetDefault = isDefault || addressCount === 0;

    const address = new Address({
      ...addressData,
      userId,
      isDefault: shouldSetDefault,
    });

    const savedAddress = await address.save({ session });
    await session.commitTransaction();

    res.status(201).json({ 
      success: true, 
      address: savedAddress 
    });

  } catch (error) {
    await session.abortTransaction();
    console.error("Address save error:", error);
    
    if (error.name === 'ValidationError') {
      return res.status(400).json({ 
        success: false, 
        message: Object.values(error.errors).map(e => e.message).join(', ')
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: "Internal server error" 
    });
  } finally {
    await session.endSession();
  }
});

app.put('/api/address/:id', authMiddleware, async (req, res) => {
  try {
    const { isDefault, ...addressData } = req.body;
    const userId = req.user._id;
    const addressId = req.params.id;

    if (isDefault) {
      await Address.updateMany(
        { userId },
        { $set: { isDefault: false } }
      );
    }

    const address = await Address.findOneAndUpdate(
      { _id: addressId, userId },
      { ...addressData, isDefault },
      { new: true }
    );

    if (!address) {
      return res.status(404).json({ success: false, message: "Address not found" });
    }

    res.json({ success: true, address });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.delete('/api/address/:id', authMiddleware, async (req, res) => {
  try {
    const userId = req.user._id;
    const addressId = req.params.id;

    const address = await Address.findOneAndDelete({ _id: addressId, userId });

    if (!address) {
      return res.status(404).json({ success: false, message: "Address not found" });
    }

    // If deleted address was default, set another as default
    if (address.isDefault) {
      const remainingAddress = await Address.findOne({ userId });
      if (remainingAddress) {
        remainingAddress.isDefault = true;
        await remainingAddress.save();
      }
    }

    res.json({ success: true, message: "Address deleted successfully" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/order', authMiddleware, async (req, res) => {
  const session = await mongoose.startSession();

  try {
    await session.startTransaction();

    // Debug: Check authentication
    console.log('User in order endpoint:', req.user);
    
    if (!req.user || !req.user._id) {
      await session.abortTransaction();
      return res.status(401).json({ 
        success: false, 
        message: "User authentication failed" 
      });
    }

    const userId = req.user._id;
    const {
      items,
      address,
      paymentMethod,
      deliverySlot,
      coupon,
      // Remove referralCoinsUsed from here - handle separately
      subtotal,
      discount,
      deliveryFee,
      total,
      coinsEarned = Math.round(total * 0.05),
    } = req.body;

    // ✅ Enhanced validation
    if (!total || total <= 0) {
      await session.abortTransaction();
      return res.status(400).json({ 
        success: false, 
        message: "Invalid order total" 
      });
    }

    if (!address || !items || items.length === 0) {
      await session.abortTransaction();
      return res.status(400).json({ 
        success: false, 
        message: "Order data is incomplete" 
      });
    }

    // ✅ Validate items structure
    for (const item of items) {
      if (!item.productId || !item.quantity || item.quantity <= 0) {
        await session.abortTransaction();
        return res.status(400).json({ 
          success: false, 
          message: "Invalid item data" 
        });
      }
    }

    // ✅ Validate user exists
    const userExists = await User.findById(userId).session(session);
    if (!userExists) {
      await session.abortTransaction();
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }

    // ✅ Check COD limit
    if (paymentMethod === 'cod' && total > 5000) {
      await session.abortTransaction();
      return res.status(400).json({ 
        success: false, 
        message: "Cash on Delivery not available for orders above ₹5000" 
      });
    }

    // ✅ Generate unique orderId
    const orderId = "ORD-" + Date.now() + "-" + Math.random().toString(36).substr(2, 9).toUpperCase();

    // ✅ Create order object - set referralCoinsUsed to 0 initially
    const orderData = {
      orderId,
      userId,
      items: items.map(item => ({
        productId: item.productId,
        quantity: item.quantity,
        price: item.price,
        title: item.title,
        image: item.image
      })),
      address: {
        label: address.label,
        fullName: address.fullName,
        mobile: address.mobile,
        pincode: address.pincode,
        address: address.address,
        locality: address.locality,
        city: address.city,
        state: address.state,
        landmark: address.landmark
      },
      paymentMethod,
      deliverySlot,
      coupon: coupon ? {
        code: coupon.code,
        discount: coupon.discount,
        description: coupon.description
      } : undefined,
      referralCoinsUsed: 0, // Start with 0, will be updated in separate endpoint
      subtotal,
      discount,
      deliveryFee,
      total,
      coinsEarned,
      totalAmount: total,
      status: "confirmed",
      paymentStatus: paymentMethod === 'cod' ? 'pending' : 'paid',
      orderStatus: "new"
    };

    const order = new Order(orderData);
    const savedOrder = await order.save({ session });

    // ✅ Update user loyalty coins (only add earned coins, don't deduct used coins here)
    if (coinsEarned > 0) {
      await User.findByIdAndUpdate(
        userId,
        { $inc: { loyaltyCoins: coinsEarned } },
        { session }
      );
    }

    // ✅ Referral completion logic
    if (userExists.referredBy) {
      try {
        const referral = await Referral.findOne({
          referredUserId: userId,
          status: "pending",
        }).session(session);

        if (referral) {
          // Update referral status
          referral.status = "completed";
          referral.completedAt = new Date();
          referral.orderId = savedOrder.orderId;
          await referral.save({ session });

          // Award bonus coins to both users
          const bonusCoins = 50;

          await User.findByIdAndUpdate(
            referral.referrerId,
            { 
              $inc: { 
                loyaltyCoins: bonusCoins
              } 
            },
            { session }
          );

          await User.findByIdAndUpdate(
            userId,
            { $inc: { loyaltyCoins: bonusCoins } },
            { session }
          );

          console.log(`Referral completed: ${referral._id}, bonus coins awarded to both users`);
        }
      } catch (referralError) {
        console.error("Referral processing error:", referralError);
        // Don't fail the entire order if referral processing fails
      }
    }

    // ✅ Clear user's cart
    const cartDeleteResult = await Cart.deleteMany({ userId }).session(session);
    console.log(`Cleared cart for user ${userId}, deleted ${cartDeleteResult.deletedCount} items`);

    // ✅ Update product stock (if you have inventory management)
    try {
      for (const item of items) {
        const productUpdate = await Product.findByIdAndUpdate(
          item.productId,
          { $inc: { stock: -item.quantity } },
          { session, new: true }
        );
        if (productUpdate) {
          console.log(`Updated stock for product ${item.productId}, new stock: ${productUpdate.stock}`);
        }
      }
    } catch (stockError) {
      console.error("Stock update error:", stockError);
      // Don't fail the entire order if stock update fails
    }

    await session.commitTransaction();
    console.log(`Order ${savedOrder.orderId} placed successfully for user ${userId}`);

    // ✅ Send success response
    res.status(201).json({
      success: true,
      message: "Order placed successfully.",
      orderId: savedOrder.orderId,
      total: savedOrder.total,
      coinsEarned: savedOrder.coinsEarned,
      referralCoinsUsed: 0, // Will be updated in separate call
      order: {
        _id: savedOrder._id,
        orderId: savedOrder.orderId,
        items: savedOrder.items,
        address: savedOrder.address,
        paymentMethod: savedOrder.paymentMethod,
        deliverySlot: savedOrder.deliverySlot,
        subtotal: savedOrder.subtotal,
        discount: savedOrder.discount,
        deliveryFee: savedOrder.deliveryFee,
        total: savedOrder.total,
        coinsEarned: savedOrder.coinsEarned,
        status: savedOrder.status,
        paymentStatus: savedOrder.paymentStatus,
        createdAt: savedOrder.createdAt
      }
    });

  } catch (error) {
    await session.abortTransaction();
    console.error("Order placement error:", error);
    
    let errorMessage = "Internal server error during order processing.";
    let statusCode = 500;

    if (error.name === 'ValidationError') {
      errorMessage = "Invalid order data provided.";
      statusCode = 400;
    } else if (error.name === 'CastError') {
      errorMessage = "Invalid data format.";
      statusCode = 400;
    } else if (error.code === 11000) {
      errorMessage = "Order ID already exists, please try again.";
      statusCode = 400;
    }

    res.status(statusCode).json({
      success: false,
      message: errorMessage,
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  } finally {
    await session.endSession();
  }
});
app.get('/api/referrals/user', authMiddleware, async (req, res) => {
  try {
    // Debug: Check what's in req.user
    console.log('User in referral endpoint:', req.user);
    
    // Ensure req.user._id exists and is valid
    if (!req.user || !req.user._id) {
      return res.status(401).json({
        success: false,
        message: "User not authenticated properly"
      });
    }

    const userId = req.user._id;

    // Get user's referral data
    const user = await User.findById(userId).select('loyaltyCoins referredBy referralCode');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    // Get referrals made by this user
    const referrals = await Referral.find({ referrerId: userId });
    
    // Calculate stats
    const completedReferrals = referrals.filter(ref => ref.status === 'completed').length;
    const totalEarned = completedReferrals * 50; // 50 coins per completed referral

    res.json({
      success: true,
      user: {
        loyaltyCoins: user.loyaltyCoins || 0,
        referralCode: user.referralCode,
        referredBy: user.referredBy
      },
      referrals: referrals,
      completed: completedReferrals,
      totalEarned: totalEarned
    });

  } catch (error) {
    console.error("Referral data error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch referral data",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});
// Enhanced orders endpoint with complete details
app.get('/api/orders', authMiddleware, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const orders = await Order.find({ userId })
      .populate('userId', 'name email phone loyaltyCoins referralCode')
      .populate('items.productId', 'title subtitle image price mrp discount category brand inStock stockQuantity')
      .populate('statusHistory.updatedBy', 'name email')
      .sort({ createdAt: -1 });

    // Format the response with complete details
    const formattedOrders = orders.map(order => ({
      _id: order._id,
      orderId: order.orderId,
      user: {
        _id: order.userId._id,
        name: order.userId.name,
        email: order.userId.email,
        phone: order.userId.phone,
        loyaltyCoins: order.userId.loyaltyCoins,
        referralCode: order.userId.referralCode
      },
      items: order.items.map(item => ({
        _id: item._id,
        productId: {
          _id: item.productId?._id,
          title: item.productId?.title,
          subtitle: item.productId?.subtitle,
          image: item.productId?.image,
          price: item.productId?.price,
          mrp: item.productId?.mrp,
          discount: item.productId?.discount,
          category: item.productId?.category,
          brand: item.productId?.brand,
          inStock: item.productId?.inStock,
          stockQuantity: item.productId?.stockQuantity
        },
        title: item.title || item.productId?.title,
        image: item.image || item.productId?.image,
        quantity: item.quantity,
        price: item.price,
        itemTotal: item.price * item.quantity
      })),
      address: {
        // Handle both object and referenced address
        ...(order.address._id ? {
          _id: order.address._id,
          label: order.address.label,
          fullName: order.address.fullName,
          mobile: order.address.mobile,
          pincode: order.address.pincode,
          address: order.address.address,
          locality: order.address.locality,
          city: order.address.city,
          state: order.address.state,
          landmark: order.address.landmark,
          isDefault: order.address.isDefault
        } : order.address)
      },
      paymentMethod: order.paymentMethod,
      deliverySlot: order.deliverySlot,
      coupon: order.coupon,
      referralCoinsUsed: order.referralCoinsUsed,
      pricing: {
        subtotal: order.subtotal,
        discount: order.discount,
        deliveryFee: order.deliveryFee,
        referralDiscount: order.referralCoinsUsed,
        total: order.total,
        totalAmount: order.totalAmount
      },
      status: {
        orderStatus: order.orderStatus,
        paymentStatus: order.paymentStatus,
        legacyStatus: order.status // Keeping for backward compatibility
      },
      rewards: {
        coinsEarned: order.coinsEarned,
        referralCoinsUsed: order.referralCoinsUsed
      },
      statusHistory: order.statusHistory.map(history => ({
        status: history.status,
        timestamp: history.timestamp,
        notes: history.notes,
        updatedBy: history.updatedBy ? {
          _id: history.updatedBy._id,
          name: history.updatedBy.name,
          email: history.updatedBy.email
        } : null
      })),
      timestamps: {
        createdAt: order.createdAt,
        updatedAt: order.updatedAt
      },
      summary: {
        totalItems: order.items.reduce((sum, item) => sum + item.quantity, 0),
        itemCount: order.items.length,
        deliveryInfo: order.deliverySlot ? `Slot: ${order.deliverySlot}` : 'Standard Delivery'
      }
    }));

    res.json({ 
      success: true, 
      orders: formattedOrders,
      meta: {
        totalOrders: orders.length,
        totalAmount: orders.reduce((sum, order) => sum + (order.totalAmount || 0), 0),
        statusBreakdown: {
          new: orders.filter(o => o.orderStatus === 'new').length,
          processing: orders.filter(o => o.orderStatus === 'processing').length,
          shipped: orders.filter(o => o.orderStatus === 'shipped').length,
          delivered: orders.filter(o => o.orderStatus === 'delivered').length,
          cancelled: orders.filter(o => o.orderStatus === 'cancelled').length
        }
      }
    });
  } catch (error) {
    console.error('Orders fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch orders',
      error: error.message 
    });
  }
});

// Enhanced single order endpoint
app.get('/api/orders/:id', authMiddleware, async (req, res) => {
  try {
    const orderId = req.params.id;
    const userId = req.user._id;

    const order = await Order.findOne({ _id: orderId, userId })
      .populate('userId', 'name email phone loyaltyCoins referralCode createdAt')
      .populate('items.productId', 'title subtitle image price mrp discount category brand inStock stockQuantity description features')
      .populate('statusHistory.updatedBy', 'name email')
      .populate('address'); // If address is referenced

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    // Format the complete order response
    const formattedOrder = {
      _id: order._id,
      orderId: order.orderId,
      user: {
        _id: order.userId._id,
        name: order.userId.name,
        email: order.userId.email,
        phone: order.userId.phone,
        loyaltyCoins: order.userId.loyaltyCoins,
        referralCode: order.userId.referralCode,
        memberSince: order.userId.createdAt
      },
      items: order.items.map(item => ({
        _id: item._id,
        product: {
          _id: item.productId?._id,
          title: item.productId?.title,
          subtitle: item.productId?.subtitle,
          image: item.productId?.image,
          price: item.productId?.price,
          mrp: item.productId?.mrp,
          discount: item.productId?.discount,
          category: item.productId?.category,
          brand: item.productId?.brand,
          inStock: item.productId?.inStock,
          stockQuantity: item.productId?.stockQuantity,
          description: item.productId?.description,
          features: item.productId?.features
        },
        orderedItem: {
          title: item.title || item.productId?.title,
          image: item.image || item.productId?.image,
          quantity: item.quantity,
          price: item.price,
          itemTotal: item.price * item.quantity
        },
        currentStatus: {
          inStock: item.productId?.inStock,
          stockQuantity: item.productId?.stockQuantity,
          priceChanged: item.price !== item.productId?.price
        }
      })),
      delivery: {
        address: {
          // Handle both embedded and referenced address
          ...(order.address._id ? {
            _id: order.address._id,
            label: order.address.label,
            fullName: order.address.fullName,
            mobile: order.address.mobile,
            pincode: order.address.pincode,
            address: order.address.address,
            locality: order.address.locality,
            city: order.address.city,
            state: order.address.state,
            landmark: order.address.landmark,
            isDefault: order.address.isDefault,
            formattedAddress: `${order.address.address}, ${order.address.locality}, ${order.address.city}, ${order.address.state} - ${order.address.pincode}`
          } : {
            ...order.address,
            formattedAddress: `${order.address.address}, ${order.address.locality || ''}, ${order.address.city}, ${order.address.state} - ${order.address.pincode}`
          })
        },
        slot: order.deliverySlot,
        status: order.orderStatus
      },
      payment: {
        method: order.paymentMethod,
        status: order.paymentStatus,
        details: {
          subtotal: order.subtotal,
          discount: order.discount,
          deliveryFee: order.deliveryFee,
          referralDiscount: order.referralCoinsUsed,
          total: order.total,
          totalAmount: order.totalAmount
        }
      },
      promotions: {
        coupon: order.coupon,
        referralCoinsUsed: order.referralCoinsUsed
      },
      status: {
        current: order.orderStatus,
        payment: order.paymentStatus,
        legacy: order.status,
        history: order.statusHistory.map(history => ({
          status: history.status,
          timestamp: history.timestamp,
          notes: history.notes,
          updatedBy: history.updatedBy ? {
            _id: history.updatedBy._id,
            name: history.updatedBy.name,
            email: history.updatedBy.email
          } : null,
          formattedDate: new Date(history.timestamp).toLocaleString()
        }))
      },
      rewards: {
        coinsEarned: order.coinsEarned,
        referralCoinsUsed: order.referralCoinsUsed,
        netCoins: order.coinsEarned - order.referralCoinsUsed
      },
      timestamps: {
        createdAt: order.createdAt,
        updatedAt: order.updatedAt,
        formatted: {
          created: new Date(order.createdAt).toLocaleString(),
          updated: new Date(order.updatedAt).toLocaleString()
        }
      },
      summary: {
        totalItems: order.items.reduce((sum, item) => sum + item.quantity, 0),
        uniqueProducts: order.items.length,
        deliveryInfo: order.deliverySlot || 'Standard Delivery',
        canReorder: order.orderStatus === 'delivered',
        canCancel: ['new', 'confirmed'].includes(order.orderStatus)
      }
    };

    res.json({
      success: true,
      order: formattedOrder
    });

  } catch (error) {
    console.error('Order details fetch error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch order details',
      error: error.message
    });
  }
});

// Additional endpoint for order statistics
app.get('/api/orders/stats/summary', authMiddleware, async (req, res) => {
  try {
    const userId = req.user._id;

    const stats = await Order.aggregate([
      { $match: { userId: mongoose.Types.ObjectId(userId) } },
      {
        $group: {
          _id: null,
          totalOrders: { $sum: 1 },
          totalSpent: { $sum: '$totalAmount' },
          deliveredOrders: {
            $sum: { $cond: [{ $eq: ['$orderStatus', 'delivered'] }, 1, 0] }
          },
          pendingOrders: {
            $sum: {
              $cond: [
                { $in: ['$orderStatus', ['new', 'confirmed', 'processing', 'shipped']] },
                1, 0
              ]
            }
          },
          cancelledOrders: {
            $sum: { $cond: [{ $eq: ['$orderStatus', 'cancelled'] }, 1, 0] }
          },
          totalCoinsEarned: { $sum: '$coinsEarned' },
          averageOrderValue: { $avg: '$totalAmount' }
        }
      }
    ]);

    const statusBreakdown = await Order.aggregate([
      { $match: { userId: mongoose.Types.ObjectId(userId) } },
      {
        $group: {
          _id: '$orderStatus',
          count: { $sum: 1 },
          totalAmount: { $sum: '$totalAmount' }
        }
      }
    ]);

    const recentOrders = await Order.find({ userId })
      .sort({ createdAt: -1 })
      .limit(5)
      .select('orderId totalAmount orderStatus createdAt');

    res.json({
      success: true,
      stats: stats[0] || {
        totalOrders: 0,
        totalSpent: 0,
        deliveredOrders: 0,
        pendingOrders: 0,
        cancelledOrders: 0,
        totalCoinsEarned: 0,
        averageOrderValue: 0
      },
      statusBreakdown,
      recentOrders: recentOrders.map(order => ({
        orderId: order.orderId,
        totalAmount: order.totalAmount,
        orderStatus: order.orderStatus,
        createdAt: order.createdAt
      }))
    });

  } catch (error) {
    console.error('Order stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch order statistics',
      error: error.message
    });
  }
});

// Get single order
app.get('/api/orders/:id', authMiddleware, async (req, res) => {
  try {
    const userId = req.user._id;
    const order = await Order.findOne({ _id: req.params.id, userId });
    
    if (!order) {
      return res.status(404).json({ success: false, message: "Order not found" });
    }
    
    res.json({ success: true, order });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ==================== REFERRAL ROUTES ====================

// Get referral code
app.get("/api/referral-code/:userId", async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ referralCode: user.referralCode });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get referral details
app.get("/api/referrals/:userId", async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    const referrals = await Referral.find({ referrerId: req.params.userId })
      .populate("referredUserId", "name email")
      .sort({ createdAt: -1 });

    const completed = referrals.filter(r => r.status === "completed").length;
    const pending = referrals.filter(r => r.status === "pending").length;
    const totalEarned = completed * 50;

    res.json({
      referrals,
      completed,
      pending,
      totalEarned,
      user,
    });
  } catch (error) {
    console.error("Referral fetch error:", error);
    res.status(500).json({ message: "Failed to fetch referral data", error: error.message });
  }
});
app.post('/api/referrals/use-coins', authMiddleware, async (req, res) => {
  const session = await mongoose.startSession();
  
  try {
    await session.startTransaction();

    const userId = req.user._id;
    const { coinsToUse, orderId } = req.body;
    
    if (!coinsToUse || coinsToUse <= 0) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: "Invalid coins amount"
      });
    }

    if (!orderId) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: "Order ID is required"
      });
    }

    // Check if user has enough coins
    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    if (user.loyaltyCoins < coinsToUse) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: "Insufficient loyalty coins"
      });
    }

    // Check if order exists and belongs to user
    const order = await Order.findOne({ 
      orderId: orderId,
      userId: userId 
    }).session(session);

    if (!order) {
      await session.abortTransaction();
      return res.status(404).json({
        success: false,
        message: "Order not found"
      });
    }

    // Check if coins have already been used for this order
    if (order.referralCoinsUsed > 0) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: "Coins have already been used for this order"
      });
    }

    // Calculate discount (10 coins = ₹1)
    const coinsDiscount = coinsToUse / 10;

    // Update order with used coins
    order.referralCoinsUsed = coinsToUse;
    order.discount = (order.discount || 0) + coinsDiscount;
    order.total = Math.max(0, order.total - coinsDiscount);
    await order.save({ session });

    // Deduct coins from user
    user.loyaltyCoins -= coinsToUse;
    await user.save({ session });

    await session.commitTransaction();

    res.json({
      success: true,
      message: `Successfully used ${coinsToUse} coins for order ${orderId}`,
      coinsUsed: coinsToUse,
      discountApplied: coinsDiscount,
      remainingCoins: user.loyaltyCoins,
      newOrderTotal: order.total
    });

  } catch (error) {
    await session.abortTransaction();
    console.error("Use coins error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to use referral coins",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  } finally {
    await session.endSession();
  }
});
// ==================== DASHBOARD ROUTES ====================

app.get('/api/dashboard/stats', async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    // Today's revenue
    const todayOrders = await Order.find({
      createdAt: { $gte: today, $lt: tomorrow },
      paymentStatus: 'paid'
    });
    const todayRevenue = todayOrders.reduce((sum, order) => sum + order.totalAmount, 0);

    // New orders count
    const newOrdersCount = await Order.countDocuments({ orderStatus: 'new' });

    // Average Order Value
    const allPaidOrders = await Order.find({ paymentStatus: 'paid' });
    const aov = allPaidOrders.length > 0 
      ? allPaidOrders.reduce((sum, order) => sum + order.totalAmount, 0) / allPaidOrders.length 
      : 0;

    // Low stock alerts
    const lowStockCount = await Product.countDocuments({ stockQuantity: { $lt: 10 } });

    // Sales trend (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    const salesTrend = await Order.aggregate([
      {
        $match: {
          createdAt: { $gte: thirtyDaysAgo },
          paymentStatus: 'paid'
        }
      },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
          revenue: { $sum: '$totalAmount' },
          orders: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    // Order status distribution
    const orderStatusData = await Order.aggregate([
      {
        $group: {
          _id: '$orderStatus',
          count: { $sum: 1 }
        }
      }
    ]);

    // Low stock products
    const lowStockProducts = await Product.find({ stockQuantity: { $lt: 10 } })
      .limit(5)
      .select('title stockQuantity image');

    res.json({
      kpi: {
        revenue: todayRevenue,
        newOrders: newOrdersCount,
        aov: Math.round(aov),
        lowStock: lowStockCount
      },
      salesTrend,
      orderStatus: orderStatusData,
      lowStockProducts
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== ADMIN ORDER ROUTES ====================

app.get('/api/admin/orders', async (req, res) => {
  try {
    const { page = 1, limit = 10, orderStatus, paymentStatus } = req.query;
    
    let query = {};
    
    if (orderStatus) {
      query.orderStatus = orderStatus;
    }
    
    if (paymentStatus) {
      query.paymentStatus = paymentStatus;
    }

    const orders = await Order.find(query)
      .populate('userId', 'name email')
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .sort({ createdAt: -1 });

    const total = await Order.countDocuments(query);

    res.json({
      orders,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== ORDER DETAILS ROUTES ====================

// GET single order details
app.get('/api/orders/:id', async (req, res) => {
  try {
    const orderId = req.params.id;
    const userId = req.user._id;

    // Check if user is admin or the order belongs to the user
    const order = await Order.findById(orderId)
      .populate('userId', 'name email')
      .populate('items.productId', 'title subtitle image price')
      .populate('address');

    if (!order) {
      return res.status(404).json({ 
        success: false, 
        message: 'Order not found' 
      });
    }

    // Check if user owns the order or is admin
    if (order.userId._id.toString() !== userId.toString()) {
      // For simplicity, we'll allow any authenticated user to view orders
      // In production, you might want to implement proper admin checks
      console.log(`User ${userId} viewing order ${orderId} belonging to ${order.userId._id}`);
    }

    // Format the response
    const orderResponse = {
      _id: order._id,
      orderId: order.orderId,
      userId: {
        _id: order.userId._id,
        name: order.userId.name,
        email: order.userId.email
      },
      items: order.items.map(item => ({
        productId: item.productId ? {
          _id: item.productId._id,
          title: item.productId.title,
          subtitle: item.productId.subtitle,
          image: item.productId.image,
          price: item.productId.price
        } : null,
        title: item.title,
        image: item.image,
        quantity: item.quantity,
        price: item.price
      })),
      address: order.address || {},
      paymentMethod: order.paymentMethod,
      deliverySlot: order.deliverySlot,
      coupon: order.coupon,
      referralCoinsUsed: order.referralCoinsUsed,
      subtotal: order.subtotal,
      discount: order.discount,
      deliveryFee: order.deliveryFee,
      total: order.total,
      totalAmount: order.totalAmount,
      coinsEarned: order.coinsEarned,
      status: order.status,
      paymentStatus: order.paymentStatus,
      orderStatus: order.orderStatus,
      createdAt: order.createdAt,
      updatedAt: order.updatedAt
    };

    res.json({
      success: true,
      order: orderResponse
    });

  } catch (error) {
    console.error('Error fetching order details:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching order details',
      error: error.message 
    });
  }
});

// GET order details for admin (without user validation)
app.get('/api/admin/orders/:id', async (req, res) => {
  try {
    const orderId = req.params.id;

    const order = await Order.findById(orderId)
      .populate('userId', 'name email')
      .populate('items.productId', 'title subtitle image price')
      .populate('address');

    if (!order) {
      return res.status(404).json({ 
        success: false, 
        message: 'Order not found' 
      });
    }

    // Format the response
    const orderResponse = {
      _id: order._id,
      orderId: order.orderId,
      userId: {
        _id: order.userId._id,
        name: order.userId.name,
        email: order.userId.email
      },
      items: order.items.map(item => ({
        productId: item.productId ? {
          _id: item.productId._id,
          title: item.productId.title,
          subtitle: item.productId.subtitle,
          image: item.productId.image,
          price: item.productId.price
        } : null,
        title: item.title,
        image: item.image,
        quantity: item.quantity,
        price: item.price
      })),
      address: order.address || {},
      paymentMethod: order.paymentMethod,
      deliverySlot: order.deliverySlot,
      coupon: order.coupon,
      referralCoinsUsed: order.referralCoinsUsed,
      subtotal: order.subtotal,
      discount: order.discount,
      deliveryFee: order.deliveryFee,
      total: order.total,
      totalAmount: order.totalAmount,
      coinsEarned: order.coinsEarned,
      status: order.status,
      paymentStatus: order.paymentStatus,
      orderStatus: order.orderStatus,
      createdAt: order.createdAt,
      updatedAt: order.updatedAt
    };

    res.json({
      success: true,
      order: orderResponse
    });

  } catch (error) {
    console.error('Error fetching order details for admin:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching order details',
      error: error.message 
    });
  }
});

// ==================== ORDER STATUS UPDATE ROUTES ====================

// PUT update order status (Admin only)
app.put('/api/admin/orders/:id/status', async (req, res) => {
  try {
    const orderId = req.params.id;
    const { status } = req.body;

    // Validate status
    const validStatuses = ['new', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid order status. Valid statuses are: ' + validStatuses.join(', ')
      });
    }

    const order = await Order.findById(orderId);
    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    // Update order status
    const previousStatus = order.orderStatus;
    order.orderStatus = status;
    order.status = status; // Also update the legacy status field
    order.updatedAt = new Date();

    await order.save();

    // Log the status change
    console.log(`Order ${order.orderId} status updated from ${previousStatus} to ${status}`);

    // Populate the updated order for response
    const updatedOrder = await Order.findById(orderId)
      .populate('userId', 'name email')
      .populate('items.productId', 'title subtitle image price')
      .populate('address');

    res.json({
      success: true,
      message: `Order status updated to ${status}`,
      order: updatedOrder
    });

  } catch (error) {
    console.error('Error updating order status:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating order status',
      error: error.message
    });
  }
});

// PUT update order status (User specific)
app.put('/api/orders/:id/status', authMiddleware, async (req, res) => {
  try {
    const orderId = req.params.id;
    const userId = req.user._id;
    const { status } = req.body;

    // Users can only cancel their own orders
    if (status !== 'cancelled') {
      return res.status(403).json({
        success: false,
        message: 'You can only cancel your own orders'
      });
    }

    const order = await Order.findOne({ _id: orderId, userId });
    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found or you do not have permission to modify this order'
      });
    }

    // Check if order can be cancelled (only pending/confirmed orders)
    if (!['new', 'confirmed', 'pending'].includes(order.orderStatus)) {
      return res.status(400).json({
        success: false,
        message: 'Order cannot be cancelled at this stage'
      });
    }

    // Update order status
    order.orderStatus = 'cancelled';
    order.status = 'cancelled';
    order.updatedAt = new Date();

    await order.save();

    res.json({
      success: true,
      message: 'Order cancelled successfully',
      order
    });

  } catch (error) {
    console.error('Error cancelling order:', error);
    res.status(500).json({
      success: false,
      message: 'Error cancelling order',
      error: error.message
    });
  }
});

// ==================== BULK ORDER OPERATIONS ====================

// GET orders for specific user
app.get('/api/user/orders', authMiddleware, async (req, res) => {
  try {
    const userId = req.user._id;
    const { page = 1, limit = 10, status } = req.query;

    let query = { userId };
    if (status) {
      query.orderStatus = status;
    }

    const orders = await Order.find(query)
      .populate('userId', 'name email')
      .populate('items.productId', 'title image price')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Order.countDocuments(query);

    res.json({
      success: true,
      orders,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });

  } catch (error) {
    console.error('Error fetching user orders:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching orders',
      error: error.message
    });
  }
});

// GET order status history
app.get('/api/orders/:id/status-history', authMiddleware, async (req, res) => {
  try {
    const orderId = req.params.id;
    
    // In a real application, you might have a separate status history collection
    // For now, we'll return the current status and timestamps
    const order = await Order.findById(orderId).select('orderStatus status createdAt updatedAt');
    
    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    const statusHistory = [
      {
        status: order.orderStatus,
        timestamp: order.updatedAt,
        description: `Order ${order.orderStatus}`
      }
    ];

    res.json({
      success: true,
      statusHistory
    });

  } catch (error) {
    console.error('Error fetching order status history:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching status history',
      error: error.message
    });
  }
});

app.put('/api/admin/orders/:id/status', async (req, res) => {
  try {
    const { status } = req.body;
    const order = await Order.findByIdAndUpdate(
      req.params.id,
      { orderStatus: status, updatedAt: new Date() },
      { new: true }
    );
    
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    res.json(order);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ==================== ZONE ROUTES ====================

app.get('/api/zones', async (req, res) => {
  try {
    const zones = await Zone.find().sort({ createdAt: -1 });
    res.json(zones);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/zones', async (req, res) => {
  try {
    const zone = new Zone(req.body);
    await zone.save();
    res.status(201).json(zone);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ==================== DELIVERY STAFF ROUTES ====================

app.get('/api/delivery-staff', async (req, res) => {
  try {
    const staff = await DeliveryStaff.find().sort({ createdAt: -1 });
    res.json(staff);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/delivery-staff', async (req, res) => {
  try {
    const staff = new DeliveryStaff(req.body);
    await staff.save();
    res.status(201).json(staff);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ==================== REPORTS ROUTES ====================

app.get('/api/reports/sales', async (req, res) => {
  try {
    const { startDate, endDate, category } = req.query;
    
    let matchQuery = {};
    
    if (startDate && endDate) {
      matchQuery.createdAt = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }
    
    if (category) {
      matchQuery['items.productId'] = category;
    }

    const salesReport = await Order.aggregate([
      { $match: matchQuery },
      { $match: { paymentStatus: 'paid' } },
      {
        $group: {
          _id: null,
          totalRevenue: { $sum: '$totalAmount' },
          totalOrders: { $sum: 1 },
          averageOrderValue: { $avg: '$totalAmount' }
        }
      }
    ]);

    const dailySales = await Order.aggregate([
      { $match: matchQuery },
      { $match: { paymentStatus: 'paid' } },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
          revenue: { $sum: '$totalAmount' },
          orders: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    res.json({
      summary: salesReport[0] || { totalRevenue: 0, totalOrders: 0, averageOrderValue: 0 },
      dailySales
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== GET ORDERS BY USER ID ====================

// GET orders for specific user by user ID (Admin or the user themselves)
app.get('/api/user/order/:userid', async (req, res) => {
  try {
    const userId = req.params.userid;
    const { page = 1, limit = 10, status } = req.query;

    // Validate user ID
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid user ID format'
      });
    }

    // Build query object
    let query = { userId };
    
    // Filter by status if provided
    if (status) {
      query.$or = [
        { orderStatus: status },
        { status: status }
      ];
    }

    // Calculate pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Fetch orders with pagination and population
    const orders = await Order.find(query)
      .populate('userId', 'name email')
      .populate('items.productId', 'title subtitle image price')
      .populate('address')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);

    // Get total count for pagination
    const total = await Order.countDocuments(query);

    // Format the response
    const formattedOrders = orders.map(order => ({
      _id: order._id,
      orderId: order.orderId,
      userId: {
        _id: order.userId._id,
        name: order.userId.name,
        email: order.userId.email
      },
      items: order.items.map(item => ({
        productId: item.productId ? {
          _id: item.productId._id,
          title: item.productId.title,
          subtitle: item.productId.subtitle,
          image: item.productId.image,
          price: item.productId.price
        } : null,
        title: item.title || (item.productId ? item.productId.title : 'Unknown Product'),
        image: item.image || (item.productId ? item.productId.image : ''),
        quantity: item.quantity,
        price: item.price
      })),
      address: order.address ? {
        _id: order.address._id,
        fullName: order.address.fullName,
        mobile: order.address.mobile,
        address: order.address.address,
        locality: order.address.locality,
        city: order.address.city,
        state: order.address.state,
        pincode: order.address.pincode,
        landmark: order.address.landmark
      } : null,
      paymentMethod: order.paymentMethod,
      deliverySlot: order.deliverySlot,
      coupon: order.coupon,
      referralCoinsUsed: order.referralCoinsUsed,
      subtotal: order.subtotal,
      discount: order.discount,
      deliveryFee: order.deliveryFee,
      total: order.total,
      totalAmount: order.totalAmount,
      coinsEarned: order.coinsEarned,
      status: order.status,
      paymentStatus: order.paymentStatus,
      orderStatus: order.orderStatus,
      createdAt: order.createdAt,
      updatedAt: order.updatedAt
    }));

    res.json({
      success: true,
      orders: formattedOrders,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });

  } catch (error) {
    console.error('Error fetching user orders by ID:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching orders',
      error: error.message
    });
  }
});

// GET user order statistics by user ID
app.get('/api/user/order/:userid/stats', async (req, res) => {
  try {
    const userId = req.params.userid;

    // Validate user ID
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid user ID format'
      });
    }

    const stats = await Order.aggregate([
      { $match: { userId: mongoose.Types.ObjectId(userId) } },
      {
        $group: {
          _id: null,
          totalOrders: { $sum: 1 },
          totalSpent: { $sum: '$totalAmount' },
          deliveredOrders: {
            $sum: {
              $cond: [{ $in: ['$orderStatus', ['delivered']] }, 1, 0]
            }
          },
          pendingOrders: {
            $sum: {
              $cond: [{ $in: ['$orderStatus', ['new', 'confirmed', 'processing', 'shipped']] }, 1, 0]
            }
          },
          cancelledOrders: {
            $sum: {
              $cond: [{ $eq: ['$orderStatus', 'cancelled'] }, 1, 0]
            }
          }
        }
      }
    ]);

    const orderStatusCounts = await Order.aggregate([
      { $match: { userId: mongoose.Types.ObjectId(userId) } },
      {
        $group: {
          _id: '$orderStatus',
          count: { $sum: 1 }
        }
      }
    ]);

    const defaultStats = {
      totalOrders: 0,
      totalSpent: 0,
      deliveredOrders: 0,
      pendingOrders: 0,
      cancelledOrders: 0
    };

    res.json({
      success: true,
      stats: stats.length > 0 ? stats[0] : defaultStats,
      statusCounts: orderStatusCounts
    });

  } catch (error) {
    console.error('Error fetching user order stats by ID:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching order statistics',
      error: error.message
    });
  }
});

// GET recent orders for specific user by user ID
app.get('/api/user/order/:userid/recent', async (req, res) => {
  try {
    const userId = req.params.userid;

    // Validate user ID
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid user ID format'
      });
    }

    const recentOrders = await Order.find({ userId })
      .populate('items.productId', 'title image')
      .sort({ createdAt: -1 })
      .limit(5)
      .select('orderId totalAmount orderStatus createdAt items');

    const formattedOrders = recentOrders.map(order => ({
      _id: order._id,
      orderId: order.orderId,
      totalAmount: order.totalAmount,
      orderStatus: order.orderStatus,
      createdAt: order.createdAt,
      itemCount: order.items.length,
      firstItem: order.items[0] ? {
        title: order.items[0].title || order.items[0].productId?.title,
        image: order.items[0].image || order.items[0].productId?.image
      } : null
    }));

    res.json({
      success: true,
      orders: formattedOrders
    });

  } catch (error) {
    console.error('Error fetching recent orders by user ID:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching recent orders',
      error: error.message
    });
  }
});

// GET all orders with user details (Admin only)
app.get('/api/user/orders/all', async (req, res) => {
  try {
    const { page = 1, limit = 10, status, userId } = req.query;

    // Build query object
    let query = {};
    
    // Filter by status if provided
    if (status) {
      query.$or = [
        { orderStatus: status },
        { status: status }
      ];
    }

    // Filter by user ID if provided
    if (userId && mongoose.Types.ObjectId.isValid(userId)) {
      query.userId = userId;
    }

    // Calculate pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Fetch orders with pagination and population
    const orders = await Order.find(query)
      .populate('userId', 'name email phone')
      .populate('items.productId', 'title subtitle image price')
      .populate('address')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip);

    // Get total count for pagination
    const total = await Order.countDocuments(query);

    res.json({
      success: true,
      orders,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });

  } catch (error) {
    console.error('Error fetching all orders:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching orders',
      error: error.message
    });
  }
});
// ==================== ENHANCED ORDER ROUTES ====================

// Get orders with advanced filtering (Admin)
app.get('/api/admin/orders', async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 10, 
      orderStatus, 
      paymentStatus,
      search,
      startDate,
      endDate 
    } = req.query;
    
    let query = {};
    
    // Status filters
    if (orderStatus) {
      query.orderStatus = orderStatus;
    }
    
    if (paymentStatus) {
      query.paymentStatus = paymentStatus;
    }

    // Date range filter
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }

    // Search filter (order ID or customer name/email)
    if (search) {
      const searchRegex = new RegExp(search, 'i');
      query.$or = [
        { orderId: searchRegex },
        { 'userId.name': searchRegex },
        { 'userId.email': searchRegex }
      ];
    }

    const orders = await Order.find(query)
      .populate('userId', 'name email')
      .populate('items.productId', 'title image price')
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .sort({ createdAt: -1 });

    const total = await Order.countDocuments(query);

    res.json({
      success: true,
      orders,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      total
    });
  } catch (error) {
    console.error('Admin orders fetch error:', error);
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
});

// Get single order details (Admin)
app.get('/api/admin/orders/:id', async (req, res) => {
  try {
    const order = await Order.findById(req.params.id)
      .populate('userId', 'name email phone')
      .populate('items.productId', 'title subtitle image price category')
      .populate('address');

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    res.json({
      success: true,
      order
    });
  } catch (error) {
    console.error('Order fetch error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Update order status (Admin)
app.put('/api/admin/orders/:id/status', async (req, res) => {
  try {
    const { status, notes } = req.body;
    const orderId = req.params.id;

    // Validate status
    const validStatuses = ['new', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid order status'
      });
    }

    const order = await Order.findById(orderId);
    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Order not found'
      });
    }

    // Update order status
    const previousStatus = order.orderStatus;
    order.orderStatus = status;
    order.status = status; // Update legacy field
    order.updatedAt = new Date();

    // Add status history
    if (!order.statusHistory) {
      order.statusHistory = [];
    }
    
    order.statusHistory.push({
      status: status,
      timestamp: new Date(),
      notes: notes || `Status changed from ${previousStatus} to ${status}`
    });

    await order.save();

    // Populate the updated order for response
    const updatedOrder = await Order.findById(orderId)
      .populate('userId', 'name email')
      .populate('items.productId', 'title image price');

    res.json({
      success: true,
      message: `Order status updated to ${status}`,
      order: updatedOrder
    });

  } catch (error) {
    console.error('Order status update error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Bulk status update
app.put('/api/admin/orders/bulk/status', async (req, res) => {
  try {
    const { orderIds, status, notes } = req.body;

    if (!orderIds || !orderIds.length || !status) {
      return res.status(400).json({
        success: false,
        message: 'Order IDs and status are required'
      });
    }

    const result = await Order.updateMany(
      { _id: { $in: orderIds } },
      { 
        $set: { 
          orderStatus: status,
          status: status,
          updatedAt: new Date()
        },
        $push: {
          statusHistory: {
            status: status,
            timestamp: new Date(),
            notes: notes || `Bulk status update to ${status}`
          }
        }
      }
    );

    res.json({
      success: true,
      message: `Updated ${result.modifiedCount} orders to ${status}`,
      modifiedCount: result.modifiedCount
    });

  } catch (error) {
    console.error('Bulk status update error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Get order statistics
app.get('/api/admin/orders/stats/overview', async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    // Today's orders and revenue
    const todayStats = await Order.aggregate([
      {
        $match: {
          createdAt: { $gte: today, $lt: tomorrow }
        }
      },
      {
        $group: {
          _id: null,
          count: { $sum: 1 },
          revenue: { $sum: '$totalAmount' }
        }
      }
    ]);

    // Order status counts
    const statusCounts = await Order.aggregate([
      {
        $group: {
          _id: '$orderStatus',
          count: { $sum: 1 }
        }
      }
    ]);

    // Payment status counts
    const paymentCounts = await Order.aggregate([
      {
        $group: {
          _id: '$paymentStatus',
          count: { $sum: 1 }
        }
      }
    ]);

    // Recent orders (last 7 days)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    const recentOrders = await Order.countDocuments({
      createdAt: { $gte: sevenDaysAgo }
    });

    res.json({
      success: true,
      stats: {
        today: {
          orders: todayStats[0]?.count || 0,
          revenue: todayStats[0]?.revenue || 0
        },
        statusCounts: statusCounts.reduce((acc, curr) => {
          acc[curr._id] = curr.count;
          return acc;
        }, {}),
        paymentCounts: paymentCounts.reduce((acc, curr) => {
          acc[curr._id] = curr.count;
          return acc;
        }, {}),
        recentOrders
      }
    });

  } catch (error) {
    console.error('Order stats error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ==================== ADMIN LOYALTY COINS MANAGEMENT ====================

app.post('/api/admin/users/:userId/loyalty-coins', async (req, res) => {
  try {
    const { userId } = req.params;
    const { coins, reason, orderId } = req.body;

    const coinValue = parseInt(coins);
    if (isNaN(coinValue) || coinValue <= 0) {
      return res.status(400).json({ success: false, message: 'Valid coins amount is required' });
    }

    if (!reason) {
      return res.status(400).json({ success: false, message: 'Reason for adding coins is required' });
    }

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const previousBalance = user.loyaltyCoins;
    user.loyaltyCoins += coinValue;
    await user.save();

    const loyaltyTransaction = new LoyaltyTransaction({
      userId: userId,
      type: 'admin_added',
      coins: coinValue,
      previousBalance,
      newBalance: user.loyaltyCoins,
      reason,
      orderId: orderId || null,
      adminId: userId,
      status: 'completed'
    });

    await loyaltyTransaction.save();

    res.json({
      success: true,
      message: `Successfully added ${coinValue} loyalty coins to user`,
      user: {
        _id: userId,
        name: user.name,
        email: user.email,
        loyaltyCoins: user.loyaltyCoins
      },
      transaction: {
        id: loyaltyTransaction._id,
        coins: coinValue,
        reason,
        timestamp: loyaltyTransaction.createdAt
      }
    });

  } catch (error) {
    console.error('Add loyalty coins error:', error.stack);
    res.status(500).json({
      success: false,
      message: 'Failed to add loyalty coins',
      error: error.message
    });
  }
});

// Remove loyalty coins from user
app.post('/api/admin/users/:userId/loyalty-coins/deduct', async (req, res) => {
  try {
    const { userId } = req.params;
    const { coins, reason } = req.body;

    // Validate input
    if (!coins || coins <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Valid coins amount is required'
      });
    }

    if (!reason) {
      return res.status(400).json({
        success: false,
        message: 'Reason for deducting coins is required'
      });
    }

    // Check if user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Check if user has sufficient coins
    if (user.loyaltyCoins < coins) {
      return res.status(400).json({
        success: false,
        message: `User has insufficient coins. Current balance: ${user.loyaltyCoins}`
      });
    }

    // Update user's loyalty coins
    const previousBalance = user.loyaltyCoins;
    user.loyaltyCoins -= parseInt(coins);
    await user.save();

    // Create loyalty coins transaction record
    const loyaltyTransaction = new LoyaltyTransaction({
      userId: userId,
      type: 'admin_deducted',
      coins: parseInt(coins),
      previousBalance,
      newBalance: user.loyaltyCoins,
      reason: reason,
      adminId: userId,
      status: 'completed'
    });

    await loyaltyTransaction.save();

    res.json({
      success: true,
      message: `Successfully deducted ${coins} loyalty coins from user`,
      user: {
        _id: userId,
        name: user.name,
        email: user.email,
        loyaltyCoins: user.loyaltyCoins
      },
      transaction: {
        id: loyaltyTransaction._id,
        coins: coins,
        reason: reason,
        timestamp: loyaltyTransaction.createdAt
      }
    });

  } catch (error) {
    console.error('Deduct loyalty coins error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to deduct loyalty coins',
      error: error.message
    });
  }
});

// Get user loyalty coins transactions
app.get('/api/admin/users/:userId/loyalty-transactions', authMiddleware, async (req, res) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 10, type } = req.query;

    let query = { userId };
    if (type) {
      query.type = type;
    }

    const transactions = await LoyaltyTransaction.find(query)
      .populate('adminId', 'name email')
      .populate('orderId', 'orderId totalAmount')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await LoyaltyTransaction.countDocuments(query);

    res.json({
      success: true,
      transactions,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      total
    });

  } catch (error) {
    console.error('Get loyalty transactions error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch loyalty transactions',
      error: error.message
    });
  }
});

// Get user loyalty coins summary
app.get('/api/admin/users/:userId/loyalty-summary', authMiddleware, async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId).select('name email loyaltyCoins referralCode createdAt');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Get transaction statistics
    const stats = await LoyaltyTransaction.aggregate([
      { $match: { userId: user._id } },
      {
        $group: {
          _id: '$type',
          totalCoins: { $sum: '$coins' },
          count: { $sum: 1 }
        }
      }
    ]);

    // Get recent orders with coins earned
    const recentOrders = await Order.find({ userId: user._id })
      .select('orderId totalAmount coinsEarned createdAt')
      .sort({ createdAt: -1 })
      .limit(5);

    const summary = {
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        loyaltyCoins: user.loyaltyCoins,
        referralCode: user.referralCode,
        memberSince: user.createdAt
      },
      statistics: stats.reduce((acc, curr) => {
        acc[curr._id] = {
          totalCoins: curr.totalCoins,
          transactionCount: curr.count
        };
        return acc;
      }, {}),
      recentOrders
    };

    res.json({
      success: true,
      summary
    });

  } catch (error) {
    console.error('Get loyalty summary error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch loyalty summary',
      error: error.message
    });
  }
});
app.get("/api/zones", async (req, res) => {
  const zones = await Zone.find();
  res.json(zones);
});

// CREATE zone
app.post("/api/zones", async (req, res) => {
  const zone = await Zone.create(req.body);
  res.json(zone);
});

// UPDATE zone
app.put("/api/zones/:id", async (req, res) => {
  const updated = await Zone.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
  });
  res.json(updated);
});

// DELETE zone
app.delete("/api/zones/:id", async (req, res) => {
  await Zone.findByIdAndDelete(req.params.id);
  res.json({ success: true });
});

app.post('/api/offers/categories', async (req, res) => {
  try {
    const category = new OfferCategory(req.body);
    await category.save();
    res.status(201).json(category);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/offers/categories', async (req, res) => {
  try {
    const categories = await OfferCategory.find({ isActive: true }).sort({ displayOrder: 1 });
    res.json(categories);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/offers/categories/:id', async (req, res) => {
  try {
    const category = await OfferCategory.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    res.json(category);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete('/api/offers/categories/:id', async (req, res) => {
  try {
    await OfferCategory.findByIdAndUpdate(req.params.id, { isActive: false });
    res.json({ message: 'Category deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// SubCategory Routes
app.post('/api/offers/subcategories', async (req, res) => {
  try {
    const subcategory = new OfferSubCategory(req.body);
    await subcategory.save();
    await subcategory.populate('category');
    res.status(201).json(subcategory);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/offers/subcategories/:categoryId', async (req, res) => {
  try {
    const subcategories = await OfferSubCategory.find({
      category: req.params.categoryId,
      isActive: true
    }).populate('category');
    res.json(subcategories);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/offers/subcategories/:id', async (req, res) => {
  try {
    const subcategory = await OfferSubCategory.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    ).populate('category');
    res.json(subcategory);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete('/api/offers/subcategories/:id', async (req, res) => {
  try {
    await OfferSubCategory.findByIdAndUpdate(req.params.id, { isActive: false });
    res.json({ message: 'Subcategory deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Offer Routes
app.post('/api/offers', async (req, res) => {
  try {
    const offer = new Offer(req.body);
    await offer.save();
    await offer.populate('category');
    await offer.populate('subcategory');
    res.status(201).json(offer);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/offers', async (req, res) => {
  try {
    const { category, subcategory, active } = req.query;
    let filter = { isActive: true };
    
    if (category) filter.category = category;
    if (subcategory) filter.subcategory = subcategory;
    if (active !== undefined) filter.isActive = active === 'true';
    
    const offers = await Offer.find(filter)
      .populate('category')
      .populate('subcategory')
      .sort({ createdAt: -1 });
    
    res.json(offers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/offers/:id', async (req, res) => {
  try {
    const offer = await Offer.findById(req.params.id)
      .populate('category')
      .populate('subcategory');
    res.json(offer);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/offers/:id', async (req, res) => {
  try {
    const offer = await Offer.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    )
      .populate('category')
      .populate('subcategory');
    res.json(offer);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete('/api/offers/:id', async (req, res) => {
  try {
    await Offer.findByIdAndUpdate(req.params.id, { isActive: false });
    res.json({ message: 'Offer deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Dashboard Stats
app.get('/api/offers/stats', async (req, res) => {
  try {
    const totalOffers = await Offer.countDocuments({ isActive: true });
    const totalCategories = await OfferCategory.countDocuments({ isActive: true });
    const totalSubCategories = await OfferSubCategory.countDocuments({ isActive: true });
    const activeOffers = await Offer.countDocuments({ 
      isActive: true,
      endDate: { $gte: new Date() }
    });
    
    res.json({
      totalOffers,
      totalCategories,
      totalSubCategories,
      activeOffers
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
app.get('/api/check-pincode/:pincode', async (req, res) => {
    try {
        const { pincode } = req.params;

        // Validate 6-digit Indian PIN
        if (!/^\d{6}$/.test(pincode)) {
            return res.status(400).json({
                deliverable: false,
                message: 'Invalid pincode format. Enter a valid 6-digit pincode.'
            });
        }

        // Find zone where this pincode exists in the pincodes array
        const zone = await Zone.findOne({ pincodes: pincode });

        if (!zone) {
            return res.json({
                deliverable: false,
                message: `Delivery not available for pincode ${pincode}.`,
                zone: null
            });
        }

        // Deliverable
        return res.json({
            deliverable: true,
            message: `Delivery available in ${zone.name}.`,
            zone: {
                name: zone.name,
                deliveryFee: zone.deliveryFee,
                minimumOrderValue: zone.minimumOrderValue,
                deliveryTime: zone.deliveryTime || "30–60 mins"   // <-- NEW FIELD
            }
        });

    } catch (error) {
        console.error("Pincode check error:", error);

        return res.status(500).json({
            deliverable: false,
            message: "Server error. Could not check pincode.",
            zone: null
        });
    }
});

app.post('/api/coupon/validate', authMiddleware, async (req, res) => {
    try {
        const userId = req.user._id;
        const { couponCode, subtotal } = req.body;

        if (!couponCode || subtotal === undefined) {
            return res.status(400).json({ valid: false, message: 'Coupon code and subtotal are required.' });
        }
        
        const code = couponCode.trim().toUpperCase();

        // 1. Handle special 'FIRST1' coupon logic
        if (code === 'FIRST1') {
            const firstOrder = await Order.findOne({ userId });
            
            if (firstOrder) {
                return res.json({ valid: false, message: 'FIRST1 is only applicable for your first order.' });
            }

            const discount = Math.max(0, subtotal - 1);
            return res.json({
                valid: true,
                discount: Math.round(discount),
                description: "Your first order for just ₹1"
            });
        }
        
        // 2. Look up generic coupon in Offer model
        const offer = await Offer.findOne({ code, isActive: true });

        if (!offer) {
            return res.json({ valid: false, message: 'Invalid or expired coupon code.' });
        }

        // 3. Check minimum order value
        if (subtotal < offer.minOrderValue) {
            return res.json({
                valid: false,
                message: `Minimum order value of ₹${offer.minOrderValue} required.`
            });
        }
        
        // 4. Calculate discount
        let discount = 0;
        const discountValue = parseFloat(offer.discount.replace(/[^0-9.]/g, ''));
        
        if (offer.discount.includes('%')) {
            // Percentage discount
            discount = subtotal * (discountValue / 100);
            if (offer.maxDiscount) {
                discount = Math.min(discount, offer.maxDiscount);
            }
        } else {
            // Fixed amount discount
            discount = discountValue;
        }

        res.json({
            valid: true,
            discount: Math.round(discount),
            description: offer.title || `Applied ${offer.discount} discount.`
        });

    } catch (error) {
        console.error('Coupon validation error:', error);
        res.status(500).json({ valid: false, message: 'Failed to validate coupon.' });
    }
});
app.post("/api/notification", async (req, res) => {
  try {
    const { message } = req.body;

    const notification = await Notification.create({ message });

    res.json({
      success: true,
      notification,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});
app.get("/api/notifications/latest", async (req, res) => {
  try {
    const notifications = await Notification.find().sort({ createdAt: -1 });
    return res.status(200).json({ success: true, notifications });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to fetch notifications" });
  }
});

// Mark single notification as READ
app.patch("/api/notifications/:id/read", async (req, res) => {
  try {
    await Notification.findByIdAndUpdate(req.params.id, { read: true });
    return res.status(200).json({ success: true, message: "Notification marked as read" });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to update" });
  }
});

// Mark ALL notifications as read
app.patch("/api/notifications/mark-all-read", async (req, res) => {
  try {
    await Notification.updateMany({}, { read: true });
    return res.status(200).json({ success: true, message: "All notifications marked as read" });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to update" });
  }
});
app.delete("/api/notifications/:id", async (req, res) => {
  await Notification.findByIdAndDelete(req.params.id);
  res.json({ success: true });
});
app.delete("/api/notifications", async (req, res) => {
  await Notification.deleteMany({});
  res.json({ success: true });
});

// Get all referrals with user details populated
app.get("/api/referrals", async (req, res) => {
  try {
    const referrals = await Referral.find()
      .populate("referrerId", "name email phone")   // fields you want to show
      .populate("referredUserId", "name email phone")
      .sort({ createdAt: -1 });

    res.json({ success: true, referrals });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.get("/api/referrals/user/:id", async (req, res) => {
  try {
    const referrals = await Referral.find({ referrerId: req.params.id })
      .populate("referrerId", "name email phone")
      .populate("referredUserId", "name email phone");

    res.json({ success: true, referrals });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// Update coins
app.patch("/api/referrals/:id/update-coins", async (req, res) => {
  try {
    const referral = await Referral.findByIdAndUpdate(
      req.params.id,
      { rewardCoins: req.body.rewardCoins },
      { new: true }
    );
    res.json({ success: true, referral });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update status
app.patch("/api/referrals/:id/update-status", async (req, res) => {
  try {
    const referral = await Referral.findByIdAndUpdate(
      req.params.id,
      { status: req.body.status },
      { new: true }
    );
    res.json({ success: true, referral });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    database: db.readyState === 1 ? 'Connected' : 'Disconnected',
    cloudinary: cloudinary.config().cloud_name ? 'Configured' : 'Not Configured'
  });
});
app.use((error, req, res, next) => {
  console.error(error.stack);
  
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 5MB.' });
    }
  }
  
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// ==================== START SERVER ====================

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Health check: http://localhost:${PORT}/api/health`);
  console.log(`☁️  Cloudinary: ${cloudinary.config().cloud_name ? 'Configured' : 'Not Configured'}`);
});