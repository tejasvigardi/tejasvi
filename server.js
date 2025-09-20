const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");

const app = express();
// During development allow cross-origin requests and custom headers like x-user-id
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// Connect to MongoDB
mongoose
  .connect("mongodb://127.0.0.1:27017/blood_donation", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  role: { type: String, required: true },
  name: String,
  email: { type: String, unique: true, required: true },
  phone: String,
  aadhaar: String,
  city: String,
  password: { type: String, required: true },
  birthdate: String,
  age: Number,
  gender: String,
  blood_group: String,
  hospital_name: String,
  address: String,
});

// Feedback Schema
const feedbackSchema = new mongoose.Schema({
  user_name: { type: String, required: true },
  role: { type: String, required: true },
  rating: { type: Number, required: true },
  comments: { type: String, required: true },
  city: String,
  created_at: { type: Date, default: Date.now },
});

// Blood Request Schema
const bloodRequestSchema = new mongoose.Schema({
  receiver_id: { type: String, required: true },
  // donor_id is optional because requests can target either a donor or a blood bank
  donor_id: { type: String },
  donor_name: { type: String }, // Store donor's name when available
  // allow generic target so we can support blood_bank targets too
  target_type: { type: String, enum: ["donor", "blood_bank"] },
  target_id: { type: String },
  recipient: { type: String, required: true },
  blood_group: { type: String, required: true },
  message: String,
  status: { type: String, default: "Pending" }, // Standardized to capitalized 'Pending'
  created_at: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const Feedback = mongoose.model("Feedback", feedbackSchema);
const BloodRequest = mongoose.model("BloodRequest", bloodRequestSchema);

// Inventory Schema for Blood Banks
const inventorySchema = new mongoose.Schema({
  blood_bank_id: { type: String, required: true },
  blood_group: { type: String, required: true },
  units: { type: Number, default: 0 },
  last_updated: { type: Date, default: Date.now },
});

const Inventory = mongoose.model('Inventory', inventorySchema);

// Registration Route
app.post("/register", async (req, res) => {
  try {
    const { role, email, password } = req.body;
    if (!role || !email || !password) {
      return res.status(400).json({ message: "Role, email, and password are required" });
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already registered" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ ...req.body, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully!", userId: newUser._id });
  } catch (err) {
    console.error("❌ Registration Error:", err);
    res.status(500).json({ message: "Error registering user" });
  }
});

// Login Route
app.post("/login", async (req, res) => {
  try {
    console.log("Login request received:", req.body);
    const { email, password, role } = req.body;
    if (!email || !password || !role) {
      return res.status(400).json({ message: "Email, password, and role are required" });
    }
    const user = await User.findOne({ email, role });
    console.log("User found:", user);
    if (!user) return res.status(400).json({ message: "User not found or wrong role" });
    const isMatch = await bcrypt.compare(password, user.password);
    console.log("Password match:", isMatch);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });
    const redirectPage = getRedirectPage(user.role);
    res.json({ message: "Login successful", role: user.role, userId: user._id, redirect: redirectPage });
  } catch (err) {
    console.error("❌ Login Error:", err.stack);
    res.status(500).json({ message: "Server error during login" });
  }
});

// Feedback Route
app.post("/feedback", async (req, res) => {
  try {
    const { user_name, role, rating, comments, city } = req.body;
    if (!user_name || !role || !rating || !comments) {
      return res.status(400).json({ message: "Please fill all required fields" });
    }
    const newFeedback = new Feedback({ user_name, role, rating, comments, city });
    await newFeedback.save();
    res.status(201).json({ message: "Feedback submitted successfully!" });
  } catch (err) {
    console.error("❌ Feedback Error:", err);
    res.status(500).json({ message: "Error saving feedback" });
  }
});

// Fetch Blood Banks Route
app.get("/api/blood_banks", async (req, res) => {
  try {
    console.log("Received blood banks request:", req.query);
    const { city, bloodGroup } = req.query;
    
    if (!city || !bloodGroup) {
      console.log("Missing required parameters");
      return res.status(400).json({ error: "City and blood group are required" });
    }

    console.log("Searching for blood banks in city:", city);
    const bloodBanks = await User.find({
      role: "blood_bank",
      city: { $regex: new RegExp(city, "i") }
    }).select("_id name city phone");
    
    console.log("Found blood banks:", bloodBanks);
    const formattedBanks = bloodBanks.map((bank) => ({
      id: bank._id.toString(),
      name: bank.name || "Unknown",
      city: bank.city,
      contact: bank.phone || "N/A",
    }));
    console.log("Sending formatted response:", formattedBanks);
    res.json(formattedBanks);
  } catch (err) {
    console.error("❌ Error fetching blood banks:", err);
    res.status(500).json({ error: "Error fetching blood banks" });
  }
});

// Fetch Donors Route
app.get("/api/donors", async (req, res) => {
  try {
    const { city, bloodGroup } = req.query;
    if (!city || !bloodGroup) {
      return res.status(400).json({ error: "City and blood group are required" });
    }
    const donors = await User.find({
      role: "donor",
      city: { $regex: city, $options: "i" },
      blood_group: bloodGroup,
    }).select("_id name city blood_group phone");
    const formattedDonors = donors.map((donor) => ({
      id: donor._id.toString(), // Ensure ID is a string
      name: donor.name || "Unknown",
      city: donor.city,
      bloodGroup: donor.blood_group, // Match frontend expectation
      contact: donor.phone || "N/A",
    }));
    res.json(formattedDonors);
  } catch (err) {
    console.error("❌ Error fetching donors:", err);
    res.status(500).json({ error: "Error fetching donors" });
  }
});

// Send Blood Request Route
app.post("/api/blood-requests", async (req, res) => {
  try {
    const { receiver_id, donor_id, target_type, target_id, recipient, blood_group, message } = req.body;

    // Validate required common fields
    if (!receiver_id || !recipient || !blood_group) {
      return res.status(400).json({ error: "receiver_id, recipient and blood_group are required" });
    }

    // Determine target: donor or blood_bank
    let finalDonorId = donor_id || null;
    let finalTargetType = target_type || null;
    let finalTargetId = target_id || null;

    // If donor_id not provided, frontend may send target_type/target_id
    if (!finalDonorId) {
      if (!finalTargetType || !finalTargetId) {
        return res.status(400).json({ error: "Either donor_id or both target_type and target_id must be provided" });
      }
      if (finalTargetType === 'donor') {
        finalDonorId = finalTargetId;
      }
    }

    // If targeting a donor, ensure donor exists and capture donor_name
    let donorName = null;
    if (finalDonorId) {
      const donor = await User.findById(finalDonorId).select("name role").lean();
      if (!donor || donor.role !== 'donor') {
        return res.status(404).json({ error: "Donor not found" });
      }
      donorName = donor.name || 'Unknown';
    }

    // Create new blood request; include target fields to support blood_bank requests
    const bloodRequest = new BloodRequest({
      receiver_id,
      donor_id: finalDonorId || undefined,
      donor_name: donorName || undefined,
      target_type: finalTargetType || (finalDonorId ? 'donor' : undefined),
      target_id: finalTargetId || (finalDonorId ? finalDonorId : undefined),
      recipient,
      blood_group,
      message,
      status: "Pending",
    });

    await bloodRequest.save();
    res.status(201).json({ message: "Blood request created successfully", request: bloodRequest });
  } catch (err) {
    console.error("❌ Error creating blood request:", err);
    res.status(500).json({ error: "Error creating blood request" });
  }
});

// Inventory endpoints
app.post('/api/inventory', async (req, res) => {
  try {
    const { blood_bank_id, blood_group, units, last_updated } = req.body;
    if (!blood_bank_id || !blood_group || typeof units === 'undefined') {
      return res.status(400).json({ error: 'blood_bank_id, blood_group and units are required' });
    }

    const requesterId = req.headers['x-user-id'] || req.headers['x_user_id'] || req.headers['x-userid'];
    if (!requesterId || requesterId !== blood_bank_id) {
      return res.status(403).json({ error: 'Forbidden - requester does not match blood bank id' });
    }

    const existing = await Inventory.findOne({ blood_bank_id, blood_group });
    if (existing) {
      existing.units = Number(units);
      existing.last_updated = last_updated ? new Date(last_updated) : new Date();
      await existing.save();
      return res.json({ message: 'Inventory updated', inventory: existing });
    }

    const inv = new Inventory({ blood_bank_id, blood_group, units: Number(units), last_updated: last_updated ? new Date(last_updated) : new Date() });
    await inv.save();
    res.status(201).json({ message: 'Inventory created', inventory: inv });
  } catch (err) {
    console.error('❌ Error in inventory POST:', err);
    res.status(500).json({ error: 'Error updating inventory' });
  }
});

app.get('/api/inventory', async (req, res) => {
  try {
    const { blood_bank_id } = req.query;
    if (!blood_bank_id) return res.status(400).json({ error: 'blood_bank_id required' });

    const requesterId = req.headers['x-user-id'] || req.headers['x_user_id'] || req.headers['x-userid'];
    if (!requesterId || requesterId !== blood_bank_id) {
      return res.status(403).json({ error: 'Forbidden - requester does not match blood bank id' });
    }

    const items = await Inventory.find({ blood_bank_id }).lean();
    res.json(items.map(i => ({ blood_group: i.blood_group, units: i.units, last_updated: i.last_updated })));
  } catch (err) {
    console.error('❌ Error in inventory GET:', err);
    res.status(500).json({ error: 'Error fetching inventory' });
  }
});

// Get Requests for a Donor
app.get("/api/blood-requests", async (req, res) => {
  try {
    const { donor_id, target_type, target_id } = req.query;

    // Optional protection: verify requester identity via x-user-id header when present
    const requesterId = req.headers['x-user-id'] || req.headers['x_user_id'] || req.headers['x-userid'];

    // If donor_id is provided and requesterId is present, ensure they match
    if (donor_id && requesterId && requesterId !== donor_id) {
      return res.status(403).json({ error: 'Forbidden - requester does not match donor_id' });
    }

    // Allow querying by donor_id OR by target_type & target_id (for blood_bank)
    let filter = {};
    if (donor_id) {
      filter.donor_id = donor_id;
    } else if (target_type && target_id) {
      // If requesting by target and requesterId provided, ensure match
      if (requesterId && requesterId !== target_id) {
        return res.status(403).json({ error: 'Forbidden - requester does not match target_id' });
      }
      filter.target_type = target_type;
      filter.target_id = target_id;
    } else {
      return res.status(400).json({ error: "donor_id or (target_type and target_id) is required" });
    }

    const requests = await BloodRequest.find(filter).lean();
    const formattedRequests = await Promise.all(
      requests.map(async (request) => {
        // select fields that could represent the receiver's display name
        const receiver = await User.findById(request.receiver_id).select("name hospital_name email").lean();
        const receiverName = receiver?.name || receiver?.hospital_name || receiver?.email || "Unknown";
        return {
          id: request._id.toString(),
          receiver: receiverName,
          recipient: request.recipient,
          bloodGroup: request.blood_group, // Match frontend expectation
          message: request.message || "No message provided",
          status: request.status,
          created_at: request.created_at,
        };
      })
    );
    res.json(formattedRequests);
  } catch (err) {
    console.error("❌ Error fetching blood requests:", err);
    res.status(500).json({ error: "Error fetching blood requests" });
  }
});

// Get Requests for a Receiver
app.get("/api/receiver-requests", async (req, res) => {
  try {
    const { receiver_id } = req.query;
    if (!receiver_id) {
      return res.status(400).json({ error: "Receiver ID is required" });
    }

    // Optional simple session validation: check x-user-id header matches the requested receiver_id
    const requesterId = req.headers['x-user-id'] || req.headers['x_user_id'] || req.headers['x-userid'];
    // Enforce that a requester must present the header and it must match the requested receiver_id
    if (!requesterId) {
      return res.status(401).json({ error: 'Unauthorized - missing x-user-id header' });
    }
    if (requesterId !== receiver_id) {
      return res.status(403).json({ error: 'Forbidden - requester does not match receiver_id' });
    }
    const requests = await BloodRequest.find({ receiver_id }).lean();

    const formattedRequests = await Promise.all(requests.map(async (request) => {
      // Determine display target name: prefer stored donor_name, else resolve from DB
      let targetName = request.donor_name || null;

      // If donor_id present but donor_name missing, try to fetch donor
      if (!targetName && request.donor_id) {
        try {
          const donor = await User.findById(request.donor_id).select('name role').lean();
          if (donor && donor.role === 'donor') targetName = donor.name || 'Unknown';
        } catch (e) {
          console.error('Error resolving donor for request', request._id, e);
        }
      }

      // If still no name and this request targets a blood_bank, resolve blood bank name
      if (!targetName && request.target_type === 'blood_bank' && request.target_id) {
        try {
          const bank = await User.findById(request.target_id).select('name role').lean();
          if (bank && bank.role === 'blood_bank') targetName = bank.name || 'Unknown';
        } catch (e) {
          console.error('Error resolving blood bank for request', request._id, e);
        }
      }

      // Fallback
      if (!targetName) targetName = 'Unknown';

      return {
        id: request._id.toString(),
        target: targetName,
        recipient: request.recipient,
        bloodGroup: request.blood_group, // Match frontend expectation
        message: request.message || 'No message provided',
        status: request.status,
        created_at: request.created_at,
      };
    }));

    res.json(formattedRequests);
  } catch (err) {
    console.error("❌ Error fetching receiver requests:", err);
    res.status(500).json({ error: "Error fetching receiver requests" });
  }
});

// Update Request Status
app.patch("/api/blood-requests/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    if (!status || !["Accepted", "Rejected"].includes(status)) {
      return res.status(400).json({ error: "Valid status (Accepted or Rejected) is required" });
    }
    const request = await BloodRequest.findById(id);
    if (!request) {
      return res.status(404).json({ error: "Blood request not found" });
    }
    const requesterId = req.headers['x-user-id'] || req.headers['x_user_id'] || req.headers['x-userid'];
    if (!requesterId) return res.status(401).json({ error: 'Unauthorized - missing x-user-id header' });

    // Allow admin users to act on any request. Otherwise enforce target-based authorization.
    const requester = await User.findById(requesterId).select('role').lean();
    const isAdmin = requester && requester.role === 'admin';
    if (!isAdmin) {
      // If this request targets a blood bank ensure the requester matches
      if (request.target_type === 'blood_bank') {
        if (request.target_id !== requesterId) return res.status(403).json({ error: 'Forbidden - only target blood bank can update this request' });
      } else if (request.donor_id) {
        if (request.donor_id !== requesterId) return res.status(403).json({ error: 'Forbidden - only target donor can update this request' });
      } else {
        return res.status(403).json({ error: 'Forbidden - you are not authorized to update this request' });
      }
    }

    // If accepting a blood bank-targeted request, decrement inventory
    if (status === 'Accepted' && request.target_type === 'blood_bank') {
      const inv = await Inventory.findOne({ blood_bank_id: requesterId, blood_group: request.blood_group });
      if (!inv || inv.units <= 0) {
        return res.status(400).json({ error: 'Insufficient inventory to accept request' });
      }
      inv.units = inv.units - 1;
      inv.last_updated = new Date();
      await inv.save();
    }

    request.status = status;
    await request.save();
    res.json({ message: `Blood request ${status} successfully` });
  } catch (err) {
    console.error("❌ Error updating blood request:", err);
    res.status(500).json({ error: "Error updating blood request" });
  }
});

app.get("/api/users", async (req, res) => {
  try {
    const users = await User.find({}).select("name email role blood_group city").lean();
    res.json(users.map(user => ({
      _id: user._id.toString(),
      name: user.name || "N/A",
      email: user.email,
      role: user.role,
      blood_group: user.blood_group || "N/A",
      city: user.city || "N/A",
    })));
  } catch (err) {
    console.error("❌ Error fetching users:", err);
    res.status(500).json({ error: "Error fetching users" });
  }
});

// Fetch All Blood Requests (for Admin) - Updated to include receiver_name and donor_name
app.get("/api/all-requests", async (req, res) => {
  try {
    const requests = await BloodRequest.find({}).lean();
    const formattedRequests = await Promise.all(
      requests.map(async (request) => {
        const receiver = await User.findById(request.receiver_id).select("name hospital_name email").lean();
        const receiverName = receiver?.name || receiver?.hospital_name || receiver?.email || "Unknown";
        return {
          id: request._id.toString(),
          recipient: request.recipient,
          blood_group: request.blood_group,
          message: request.message || "No message",
          status: request.status,
          donor_name: request.donor_name || "Unknown",
          receiver_name: receiverName,
          created_at: request.created_at,
        };
      })
    );
    res.json(formattedRequests);
  } catch (err) {
    console.error("❌ Error fetching requests:", err);
    res.status(500).json({ error: "Error fetching requests" });
  }
});

// Get Single Blood Request (for modal)
app.get("/api/blood-requests/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const request = await BloodRequest.findById(id).lean();
    if (!request) {
      return res.status(404).json({ error: "Request not found" });
    }
    const receiver = await User.findById(request.receiver_id).select("name hospital_name email").lean();
    const receiverName = receiver?.name || receiver?.hospital_name || receiver?.email || "Unknown";
    const formatted = {
      ...request,
      _id: request._id.toString(),
      receiver_name: receiverName,
      donor_name: request.donor_name || "Unknown",
      created_at: request.created_at,
    };
    res.json(formatted);
  } catch (err) {
    console.error("❌ Error fetching request:", err);
    res.status(500).json({ error: "Error fetching request" });
  }
});

// Fetch All Feedback (for Admin) - Updated to include created_at
app.get("/api/feedback", async (req, res) => {
  try {
    const feedback = await Feedback.find({}).sort({ created_at: -1 }).lean();
    res.json(feedback.map(item => ({
      _id: item._id.toString(),
      user_name: item.user_name,
      role: item.role,
      rating: item.rating,
      comments: item.comments,
      city: item.city || "N/A",
      created_at: item.created_at,
    })));
  } catch (err) {
    console.error("❌ Error fetching feedback:", err);
    res.status(500).json({ error: "Error fetching feedback" });
  }
});

// Get Single Feedback (for modal)
app.get("/api/feedback/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const feedback = await Feedback.findById(id).lean();
    if (!feedback) {
      return res.status(404).json({ error: "Feedback not found" });
    }
    res.json({
      _id: feedback._id.toString(),
      user_name: feedback.user_name,
      role: feedback.role,
      rating: feedback.rating,
      comments: feedback.comments,
      city: feedback.city || "N/A",
      created_at: feedback.created_at,
    });
  } catch (err) {
    console.error("❌ Error fetching feedback:", err);
    res.status(500).json({ error: "Error fetching feedback" });
  }
});

// Export Users to CSV
app.get("/api/export/users", async (req, res) => {
  try {
    const users = await User.find({}).select("name email role blood_group city").lean();
    let csv = "Name,Email,Role,Blood Group,City\n";
    users.forEach(user => {
      csv += `"${user.name || 'N/A'}","${user.email}","${user.role}","${user.blood_group || 'N/A'}","${user.city || 'N/A'}"\n`;
    });
    res.header("Content-Type", "text/csv");
    res.attachment("users-report.csv");
    res.send(csv);
  } catch (err) {
    console.error("❌ Error exporting users:", err);
    res.status(500).json({ error: "Error exporting users" });
  }
});

// Export Requests to CSV
app.get("/api/export/requests", async (req, res) => {
  try {
    const requests = await BloodRequest.find({}).lean();
    let csv = "Recipient,Blood Group,Message,Status\n";
    requests.forEach(request => {
      csv += `"${request.recipient}","${request.blood_group}","${request.message || 'No message'}","${request.status}"\n`;
    });
    res.header("Content-Type", "text/csv");
    res.attachment("requests-report.csv");
    res.send(csv);
  } catch (err) {
    console.error("❌ Error exporting requests:", err);
    res.status(500).json({ error: "Error exporting requests" });
  }
});

// Helper function for role-based redirect
function getRedirectPage(role) {
  switch (role) {
    case "admin":
      return "dashboard-admin.html";
    case "hospital":
      return "dashboard-hospital.html";
    case "blood_bank":
      return "dashboard-bloodbank.html";
    case "receiver":
      return "dashboard-receiver.html";
    case "donor":
      return "dashboard-donor.html";
    default:
      return "login.html";
  }
}

// Start server
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});

// Admin-only: Delete a user
app.delete('/api/users/:id', async (req, res) => {
  try {
    const requesterId = req.headers['x-user-id'] || req.headers['x_user_id'] || req.headers['x-userid'];
    console.log('DELETE /api/users/:id called by', requesterId, 'target', req.params.id);
    if (!requesterId) return res.status(401).json({ error: 'Unauthorized - missing x-user-id header' });
    const requester = await User.findById(requesterId).select('role').lean();
    console.log('Requester role:', requester && requester.role);
    if (!requester || requester.role !== 'admin') return res.status(403).json({ error: 'Forbidden - admin only' });

    const { id } = req.params;
    await User.findByIdAndDelete(id);
    // Also remove related requests and feedback optionally
    await BloodRequest.deleteMany({ $or: [ { receiver_id: id }, { donor_id: id }, { target_id: id } ] });
    await Feedback.deleteMany({ user_name: id }); // best-effort (feedback stores user_name instead of id)
    res.json({ message: 'User and related data deleted' });
  } catch (err) {
    console.error('❌ Error deleting user:', err);
    res.status(500).json({ error: 'Error deleting user' });
  }
});

// Admin-only: Delete a blood request
app.delete('/api/blood-requests/:id', async (req, res) => {
  try {
    const requesterId = req.headers['x-user-id'] || req.headers['x_user_id'] || req.headers['x-userid'];
    console.log('DELETE /api/blood-requests/:id called by', requesterId, 'target', req.params.id);
    if (!requesterId) return res.status(401).json({ error: 'Unauthorized - missing x-user-id header' });
    const requester = await User.findById(requesterId).select('role').lean();
    console.log('Requester role:', requester && requester.role);
    if (!requester || requester.role !== 'admin') return res.status(403).json({ error: 'Forbidden - admin only' });

    const { id } = req.params;
    await BloodRequest.findByIdAndDelete(id);
    res.json({ message: 'Request deleted' });
  } catch (err) {
    console.error('❌ Error deleting request:', err);
    res.status(500).json({ error: 'Error deleting request' });
  }
});

// Admin-only: Delete feedback
app.delete('/api/feedback/:id', async (req, res) => {
  try {
    const requesterId = req.headers['x-user-id'] || req.headers['x_user_id'] || req.headers['x-userid'];
    console.log('DELETE /api/feedback/:id called by', requesterId, 'target', req.params.id);
    if (!requesterId) return res.status(401).json({ error: 'Unauthorized - missing x-user-id header' });
    const requester = await User.findById(requesterId).select('role').lean();
    console.log('Requester role:', requester && requester.role);
    if (!requester || requester.role !== 'admin') return res.status(403).json({ error: 'Forbidden - admin only' });

    const { id } = req.params;
    await Feedback.findByIdAndDelete(id);
    res.json({ message: 'Feedback deleted' });
  } catch (err) {
    console.error('❌ Error deleting feedback:', err);
    res.status(500).json({ error: 'Error deleting feedback' });
  }
});