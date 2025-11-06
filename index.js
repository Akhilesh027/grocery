const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

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

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'category-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Only image files are allowed!'), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

// Database Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://akhileshreddy811_db_user:KSco7zl1NdnbuwJi@cluster0.8qws5ov.mongodb.net/?appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// ==================== SCHEMAS ====================

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
  title: { type: String, required: true },
  subtitle: String,
  price: { type: Number, required: true },
  mrp: { type: Number, required: true },
  discount: Number,
  image: String,
  inStock: { type: Boolean, default: true },
  stockQuantity: { type: Number, default: 0 },
  deliveryTime: String,
  rating: { type: Number, default: 0 },
  category: {
    mainCategory: String,
    subCategory: String
  },
  brand: String,
  isTopSelling: { type: Boolean, default: false },
  isTodaysDeal: { type: Boolean, default: false },
  isHotDeal: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
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
  bannerImage: String,
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
  coinsEarned: Number,
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
  totalAmount: Number
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

// Zone Schema
const ZoneSchema = new mongoose.Schema({
  name: { type: String, required: true },
  pincodes: [String],
  deliveryFee: { type: Number, default: 0 },
  minimumOrderValue: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const Zone = mongoose.model('Zone', ZoneSchema);

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

// ==================== UTILITY FUNCTIONS ====================

function generateReferralCode(name) {
  const random = Math.floor(1000 + Math.random() * 9000);
  const prefix = name ? name.slice(0, 3).toUpperCase() : "USR";
  return prefix + random;
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

// Create category
app.post('/api/categories', upload.single('bannerImage'), async (req, res) => {
  try {
    const { name, type, parentCategory, icon } = req.body;

    let bannerImageUrl = '';

    if (req.file) {
      bannerImageUrl = '/uploads/' + req.file.filename;
    }

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

    const category = new Category({
      name,
      type,
      parentCategory: type === 'sub' ? parentCategory : null,
      icon,
      bannerImage: bannerImageUrl,
    });

    await category.save();
    res.status(201).json(category);
  } catch (error) {
    console.error('Error creating category:', error);
    res.status(500).json({ message: error.message });
  }
});

// Update category
app.put('/api/categories/:id', upload.single('bannerImage'), async (req, res) => {
  try {
    const { name, type, parentCategory, icon } = req.body;
    const categoryId = req.params.id;

    const existingCategory = await Category.findById(categoryId);
    if (!existingCategory) {
      return res.status(404).json({ message: 'Category not found' });
    }

    let bannerImageUrl = existingCategory.bannerImage;

    if (req.file) {
      if (existingCategory.bannerImage) {
        const oldImagePath = path.join(__dirname, existingCategory.bannerImage);
        if (fs.existsSync(oldImagePath)) {
          fs.unlinkSync(oldImagePath);
        }
      }
      bannerImageUrl = '/uploads/' + req.file.filename;
    }

    const updateData = {
      name,
      type,
      icon,
      parentCategory: type === 'sub' ? parentCategory : null,
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

// Delete category
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

    if (category.bannerImage) {
      const imagePath = path.join(__dirname, category.bannerImage);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
    }

    await Category.findByIdAndDelete(req.params.id);
    res.json({ message: 'Category deleted successfully' });
  } catch (error) {
    console.error('Error deleting category:', error);
    res.status(500).json({ message: error.message });
  }
});

// ==================== PRODUCT ROUTES ====================

// Get all products
app.get('/api/products', async (req, res) => {
  try {
    const { page = 1, limit = 10, search, category, stockStatus } = req.query;
    
    let query = {};
    
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { 'category.mainCategory': { $regex: search, $options: 'i' } }
      ];
    }
    
    if (category) {
      query['category.mainCategory'] = category;
    }
    
    if (stockStatus === 'in_stock') {
      query.inStock = true;
    } else if (stockStatus === 'out_of_stock') {
      query.inStock = false;
    }

    const products = await Product.find(query)
      .limit(limit * 1)
      .skip((page - 1) * limit)
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

// Create product
app.post('/api/products', async (req, res) => {
  try {
    const productData = {
      ...req.body,
      discount: Math.round(((req.body.mrp - req.body.price) / req.body.mrp) * 100)
    };
    
    const product = new Product(productData);
    await product.save();
    res.status(201).json(product);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Update product
app.put('/api/products/:id', async (req, res) => {
  try {
    const productData = {
      ...req.body,
      discount: Math.round(((req.body.mrp - req.body.price) / req.body.mrp) * 100),
      updatedAt: new Date()
    };
    
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      productData,
      { new: true, runValidators: true }
    );
    
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    res.json(product);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Delete product
app.delete('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    res.json({ message: 'Product deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
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
app.get('/api/check-pincode/:pincode', async (req, res) => {
  try {
    const { pincode } = req.params;
    const deliverablePincodes = ['560001', '560002', '560003', '560004', '560005', '560006', '560007', '560008'];
    const isAvailable = deliverablePincodes.includes(pincode);
    
    res.json({ deliverable: isAvailable });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});
app.post('/api/order', authMiddleware, async (req, res) => {
  const session = await mongoose.startSession();

  try {
    await session.startTransaction();

    const userId = req.user._id;
    const {
      items,
      address,
      paymentMethod,
      deliverySlot,
      coupon,
      subtotal,
      discount,
      deliveryFee,
      total,
      coinsEarned = Math.round(total * 0.05), // 5% of total as coins
    } = req.body;

    if (!total || !address || !items || items.length === 0) {
      await session.abortTransaction();
      return res.status(400).json({ 
        success: false, 
        message: "Order data is incomplete" 
      });
    }

    // ✅ Generate unique orderId
    const orderId = "ORD-" + uuidv4().split("-")[0].toUpperCase();

    const order = new Order({
      orderId, // ✅ include this line
      userId,
      items,
      address,
      paymentMethod,
      deliverySlot,
      coupon,
      subtotal,
      discount,
      deliveryFee,
      total,
      coinsEarned,
      totalAmount: total,
      status: "confirmed",
      paymentStatus: paymentMethod === 'cod' ? 'pending' : 'paid',
      orderStatus: "new"
    });

    const savedOrder = await order.save({ session });

    // ✅ Update user loyalty coins
    await User.findByIdAndUpdate(
      userId,
      { $inc: { loyaltyCoins: savedOrder.coinsEarned } },
      { session }
    );

    // ✅ Referral completion logic
    const user = await User.findById(userId).session(session);
    if (user?.referredBy) {
      const referral = await Referral.findOne({
        referredUserId: userId,
        status: "pending",
      }).session(session);

      if (referral) {
        await referral.completeReferral(savedOrder.orderId);

        await User.findByIdAndUpdate(
          referral.referrerId,
          { $inc: { loyaltyCoins: 50 } },
          { session }
        );

        await User.findByIdAndUpdate(
          userId,
          { $inc: { loyaltyCoins: 50 } },
          { session }
        );
      }
    }

    // ✅ Clear user's cart
    await Cart.deleteMany({ userId }).session(session);

    await session.commitTransaction();

    res.status(201).json({
      success: true,
      message: "Order placed successfully.",
      orderId: savedOrder.orderId,
      total: savedOrder.total,
      coinsEarned: savedOrder.coinsEarned,
      order: savedOrder
    });
  } catch (error) {
    await session.abortTransaction();
    console.error("Order placement error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error during order processing.",
    });
  } finally {
    await session.endSession();
  }
});

// Get user orders
app.get('/api/orders', authMiddleware, async (req, res) => {
  try {
    const userId = req.user._id;
    const orders = await Order.find({ userId }).sort({ createdAt: -1 });
    res.json({ success: true, orders });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
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

// Use loyalty coins
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
        message: 'Invalid coins amount'
      });
    }

    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (user.loyaltyCoins < coinsToUse) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: 'Insufficient coins balance'
      });
    }

    user.loyaltyCoins -= coinsToUse;
    await user.save({ session });

    const referralUsage = new ReferralUsage({
      userId: user._id,
      coinsUsed: coinsToUse,
      discountAmount: coinsToUse / 10,
      orderId: orderId || null,
      previousBalance: user.loyaltyCoins + coinsToUse,
      newBalance: user.loyaltyCoins
    });

    await referralUsage.save({ session });
    await session.commitTransaction();

    res.json({
      success: true,
      message: `Successfully used ${coinsToUse} coins`,
      newBalance: user.loyaltyCoins,
      discountAmount: coinsToUse / 10,
      usageRecord: {
        id: referralUsage._id,
        coinsUsed: coinsToUse,
        discountAmount: coinsToUse / 10
      }
    });

  } catch (error) {
    await session.abortTransaction();
    console.error('Use coins error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to use coins'
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
// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    database: db.readyState === 1 ? 'Connected' : 'Disconnected'
  });
});

// ==================== ERROR HANDLING ====================

app.use((error, req, res, next) => {
  console.error(error.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 Handler

// ==================== START SERVER ====================

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Health check: http://localhost:${PORT}/api/health`);
});