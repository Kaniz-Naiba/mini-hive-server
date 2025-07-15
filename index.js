require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const admin = require('firebase-admin');
const stripe = require('stripe')(process.env.PAYMENT_GATEWAY_KEY);

const app = express();
const port = process.env.PORT || 5000;



app.use(cors());
app.use(express.json());

const serviceAccount = require('./firebase-admin-key.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const uri = 'mongodb+srv://mini_hive_user:K0oECfCnu954GDWX@freelance.uly90ar.mongodb.net/?retryWrites=true&w=majority&appName=Freelance';
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});


// Declare collections variables here to be initialized after DB connection
let usersCollection;
let tasksCollection;
let submissionsCollection;
let paymentsCollection;
let notificationsCollection;
let withdrawalsCollection;




async function addNotification({ message, toEmail, actionRoute = "/" }) {
  if (!message || !toEmail) {
    console.warn("⚠️ Missing required fields for notification", { message, toEmail });
    return;
  }

  try {
    await client.connect();
    const db = client.db('mini_hive_user');
    const notificationsCollection = db.collection('notifications');

    const notificationDoc = {
      message,
      toEmail,
      actionRoute,
      time: new Date(),
    };

    const result = await notificationsCollection.insertOne(notificationDoc);
    console.log("✅ Notification saved:", notificationDoc, "InsertedId:", result.insertedId);
  } catch (error) {
    console.error("❌ Failed to save notification:", error);
  } finally {
    await client.close(); // Close the DB connection after use
  }
}


const verifyRole = (allowedRoles = []) => {
  return async (req, res, next) => {
    try {
      if (!usersCollection) {
        return res.status(500).json({ message: 'Server not ready: database not connected' });
      }
      const email = req.decoded.email;
      const user = await usersCollection.findOne({ email });
      if (!user || !allowedRoles.includes(user.role)) {
        return res.status(403).json({ message: 'Access denied: insufficient permissions' });
      }
      // Attach user to request if you want
      req.user = user;
      next();
    } catch (error) {
      console.error('Role verification error:', error);
      res.status(500).json({ message: 'Server error during role verification' });
    }
  };
};


// Middleware to verify Firebase token and attach decoded info
const verifyFBToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send({ message: 'Unauthorized access: missing or invalid Authorization header' });
  }

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).send({ message: 'Unauthorized access: missing token' });

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.decoded = decoded;
    next();
  } catch (error) {
    console.error('Firebase token verification error:', error);
    return res.status(403).send({ message: 'Forbidden access: invalid token' });
  }
};



// Middleware to verify Admin role
const verifyAdmin = async (req, res, next) => {
  try {
    if (!usersCollection) {
      return res.status(500).send({ message: 'Server not ready: database not connected' });
    }
    const user = await usersCollection.findOne({ email: req.decoded.email });
    if (!user || user.role !== 'admin') {
      return res.status(403).send({ message: 'Admin access required' });
    }
    next();
  } catch (error) {
    console.error('Admin verification error:', error);
    res.status(500).send({ message: 'Server error' });
  }
};


app.patch('/api/submissions/:id', verifyFBToken, verifyRole(['buyer']), async (req, res) => {
  const submissionId = req.params.id;
  const { status } = req.body;

  try {
    const submission = await submissionsCollection.findOne({ _id: new ObjectId(submissionId) });
    if (!submission) return res.status(404).json({ message: 'Submission not found' });

    
    await submissionsCollection.updateOne(
      { _id: new ObjectId(submissionId) },
      { $set: { status } }
    );

    // Send notification to worker
    const buyer = await usersCollection.findOne({ email: req.decoded.email });
    const task = await tasksCollection.findOne({ _id: new ObjectId(submission.taskId) });

    if (status === 'approved' || status === 'rejected') {
      const msg = status === 'approved'
        ? `You have earned ${submission.payable_amount} from ${buyer.name} for completing ${task.title}`
        : `${buyer.name} rejected your submission for ${task.title}`;

      await addNotification({
        message: msg,
        toEmail: submission.worker_email,
        actionRoute: '/dashboard/worker-home',
      });
    }

    res.json({ message: `Submission ${status}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal error' });
  }
});


app.patch('/api/withdrawals/:id', verifyFBToken, verifyAdmin, async (req, res) => {
  const id = req.params.id;

  try {
    const withdrawal = await withdrawalsCollection.findOne({ _id: new ObjectId(id) });
    if (!withdrawal) return res.status(404).json({ message: 'Withdrawal not found' });

    await withdrawalsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { status: 'approved' } }
    );

    // Notify worker
    await addNotification({
      message: `Your withdrawal of $${withdrawal.withdrawal_amount} has been approved.`,
      toEmail: withdrawal.worker_email,
      actionRoute: '/dashboard/worker-home',
    });

    res.json({ message: 'Withdrawal approved' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Approval failed' });
  }
});



app.post('/api/submissions', verifyFBToken, verifyRole(['worker']), async (req, res) => {
  const data = req.body;

  try {
    const result = await submissionsCollection.insertOne(data);

    // Notify buyer
    const task = await tasksCollection.findOne({ _id: new ObjectId(data.taskId) });
    const buyer = await usersCollection.findOne({ email: task.buyer_email });

    await addNotification({
      message: `${data.worker_name} has submitted a task: ${task.title}`,
      toEmail: buyer.email,
      actionRoute: '/dashboard/buyer-submissions',
    });

    res.status(201).json({ message: 'Submission sent', id: result.insertedId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to submit' });
  }
});





// Get notifications for logged-in user
app.get('/api/notifications', verifyFBToken, async (req, res) => {
  try {
    const userEmail = req.decoded.email;
    const notifications = await notificationsCollection
      .find({ toEmail: userEmail })
      .sort({ time: -1 })
      .toArray();
    res.json(notifications);
  } catch (error) {
    console.error('Failed to fetch notifications:', error);
    res.status(500).json({ message: 'Failed to fetch notifications' });
  }
});

// Delete a notification by ID
app.delete('/api/notifications/:id', verifyFBToken, async (req, res) => {
  try {
    const userEmail = req.decoded.email;
    const id = req.params.id;

    const notif = await notificationsCollection.findOne({ _id: new ObjectId(id) });
    if (!notif) return res.status(404).json({ message: 'Notification not found' });
    if (notif.toEmail !== userEmail) return res.status(403).json({ message: 'Not authorized to delete this notification' });

    await notificationsCollection.deleteOne({ _id: new ObjectId(id) });
    res.json({ message: 'Notification deleted' });
  } catch (error) {
    console.error('Failed to delete notification:', error);
    res.status(500).json({ message: 'Failed to delete notification' });
  }
});


// Stripe create payment intent route - moved outside any other handler
app.post("/create-payment-intent", verifyFBToken, async (req, res) => {
  const { amount_usd } = req.body;
  if (!amount_usd || typeof amount_usd !== 'number' || amount_usd <= 0) {
    return res.status(400).send({ message: "Invalid amount" });
  }
  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(amount_usd * 100), // Stripe uses cents
      currency: "usd",
      payment_method_types: ["card"],
    });
    res.send({ clientSecret: paymentIntent.client_secret });
  } catch (error) {
    console.error("Payment intent error:", error);
    res.status(500).send({ message: "Stripe payment failed" });
  }
});

async function run() {
  try {
    //  await client.connect();
    const db = client.db('microtaskDB');

    // Initialize collections once
    usersCollection = db.collection('users');
    tasksCollection = db.collection('tasks');
    submissionsCollection = db.collection('submissions');
    paymentsCollection = db.collection('payments');
    notificationsCollection = db.collection('notifications');
    withdrawalsCollection = db.collection('withdrawals');


    app.post("/api/payments/record", verifyFBToken, async (req, res) => {
  const { amount_usd, coins, payment_method } = req.body;
  const buyer_email = req.decoded.email;

  if (!amount_usd || !coins) {
    return res.status(400).json({ message: "Missing amount or coins" });
  }

  try {
    const paymentDoc = {
      buyer_email,
      amount_usd,
      coins,
      payment_method: payment_method || "Stripe",
      payment_date: new Date(),
      status: "completed"
    };

    await paymentsCollection.insertOne(paymentDoc);

    await usersCollection.updateOne(
      { email: buyer_email },
      { $inc: { coins: coins } }
    );

    res.json({ message: "Payment recorded and coins updated" });
  } catch (error) {
    console.error("Payment record error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});


   app.get('/api/worker/home', verifyFBToken, async (req, res) => {
  const email = req.query.email;
  if (!email || email !== req.decoded.email) {
    return res.status(403).json({ message: 'Forbidden: Invalid email' });
  }

  try {
    // Get all submissions by this worker
    const submissions = await submissionsCollection.find({ worker_email: email }).toArray();

    const totalSubmission = submissions.length;
    const totalPendingSubmission = submissions.filter(s => s.status === 'pending').length;
    const approvedSubmissions = submissions.filter(s => s.status === 'approved');

    // Sum payable amounts from approved submissions
    const totalEarning = approvedSubmissions.reduce(
      (sum, sub) => sum + (sub.payable_amount || 0),
      0
    );

    // Fetch user to get current coins
    const user = await usersCollection.findOne({ email });
    const coins = user?.coins || 0;

    // Enrich approved submissions with task info
    const enrichedApproved = await Promise.all(
      approvedSubmissions.map(async (sub) => {
        const task = await tasksCollection.findOne({ _id: new ObjectId(sub.task_id) });
        return {
          task_title: task?.task_title || 'Unknown Task',
          payable_amount: sub.payable_amount || 0,
          buyer_name: task?.buyer_name || 'Unknown Buyer',
        };
      })
    );

    res.json({
      totalSubmission,
      totalPendingSubmission,
      totalEarning,
      coins,               // <-- Added coins here
      approvedSubmissions: enrichedApproved,
    });
  } catch (error) {
    console.error('Error in /api/worker/home:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});



    // User registration with role and coins assignment
    app.post('/users', async (req, res) => {
      try {
        const { name, email, photo, role } = req.body;

        console.log("👉 Received user registration data:", req.body);

        if (!name || !email || !role) {
          return res.status(400).json({ message: 'Missing required fields' });
        }

        // Check if user exists
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.status(409).json({ message: 'Email already exists' });
        }

        const coins = role === 'buyer' ? 50 : 10;

        const newUser = {
          name,
          email,
          photo: photo || '',
          role,
          coins,
          createdAt: new Date(),
        };

        const result = await usersCollection.insertOne(newUser);
        res.status(201).json({ message: 'User registered successfully', insertedId: result.insertedId });
      } catch (error) {
        console.error('❌ Error registering user:', error);
        res.status(500).json({ message: 'Server error while registering user' });
      }
    });   

    // Get user profile by email query param
    app.get('/users/profile', async (req, res) => {
      const email = req.query.email;
      if (!email) return res.status(400).json({ message: 'Email is required' });
      try {
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json(user);
      } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ message: 'Server error' });
      }
    });

    // Fetch all payments
  app.get("/payments", verifyFBToken, async (req, res) => {
  const email = req.query.email;
  if (!email || email !== req.decoded.email) {
    return res.status(403).json({ message: "Unauthorized" });
  }

  const payments = await paymentsCollection
    .find({ email })
    .sort({ payment_date: -1 })
    .toArray();

  res.json(payments);
});


    // Add a new task (only buyers allowed)
    app.post('/tasks', verifyFBToken, async (req, res) => {
      try {
        const {
          task_title,
          task_detail,
          required_workers,
          payable_amount,
          completion_date,
          submission_info,
          task_image_url,
        } = req.body;

        // Use email from verified token, not from client payload
        const buyer_email = req.decoded.email;

        if (
          !task_title ||
          !task_detail ||
          !required_workers ||
          !payable_amount ||
          !completion_date ||
          !submission_info
        ) {
          return res.status(400).json({ message: 'Missing required task fields' });
        }

        // Validate numeric fields
        const requiredWorkersInt = parseInt(required_workers, 10);
        const payableAmountFloat = parseFloat(payable_amount);
        if (isNaN(requiredWorkersInt) || isNaN(payableAmountFloat) || requiredWorkersInt <= 0 || payableAmountFloat <= 0) {
          return res.status(400).json({ message: 'Invalid required_workers or payable_amount' });
        }

        // Find user and validate role
        const user = await usersCollection.findOne({ email: buyer_email });
        if (!user || user.role !== 'buyer') {
          return res.status(403).json({ message: 'Only buyers can create tasks' });
        }

        const totalCost = requiredWorkersInt * payableAmountFloat;

        if (user.coins < totalCost) {
          return res.status(400).json({ message: 'Not enough coins. Please purchase coins.' });
        }

        // Deduct coins from user
        await usersCollection.updateOne(
          { email: buyer_email },
          { $inc: { coins: -totalCost } }
        );

        const taskData = {
          task_title,
          task_detail,
          required_workers: requiredWorkersInt,
          payable_amount: payableAmountFloat,
          completion_date,
          submission_info,
          task_image_url: task_image_url || '',
          buyer_email,
          buyer_name: user.name || '', // from DB
          createdAt: new Date(),
          status: 'open',
        };

        const result = await tasksCollection.insertOne(taskData);
        res.status(201).json({ message: 'Task added successfully', taskId: result.insertedId });
      } catch (error) {
        console.error('Error adding task:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    });

    app.get('/buyer/home', verifyFBToken, async (req, res) => {
  const buyerEmail = req.decoded.email;
  try {
    // 1. Get user info
    const user = await usersCollection.findOne({ email: buyerEmail });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // 2. Get tasks by buyer
    const tasks = await tasksCollection.find({ buyer_email: buyerEmail }).toArray();
    const taskIds = tasks.map(t => t._id.toString());

    // 3. Get submissions for buyer's tasks
    const submissions = await submissionsCollection.find({ task_id: { $in: taskIds } }).toArray();

    // Count submissions
    const totalSubmissions = submissions.length;
    const pendingSubmissions = submissions.filter(s => s.status === 'pending').length;
    const approvedSubmissions = submissions.filter(s => s.status === 'approved').length;

    // Sum of payments made by buyer (from paymentsCollection)
    const paymentsAgg = await paymentsCollection.aggregate([
      { $match: { email: buyerEmail } },
      { $group: { _id: null, totalPaid: { $sum: '$amount_usd' } } }
    ]).toArray();
    const totalPaid = paymentsAgg[0]?.totalPaid || 0;

    res.json({
      user: {
        name: user.name,
        email: user.email,
        coins: user.coins,
        role: user.role,
      },
      stats: {
        totalTasks: tasks.length,
        totalSubmissions,
        pendingSubmissions,
        approvedSubmissions,
        totalPaid,
      },
      tasks,
      submissions,
    });
  } catch (error) {
    console.error('Error in /buyer/home:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});



app.get("/api/buyer/stats", verifyFBToken, async (req, res) => {
  try {
    const buyerEmail = req.query.email;
    if (!buyerEmail) return res.status(400).send({ message: "Email required" });

    // ✅ Count total tasks (not deleted)
    const totalTasks = await tasksCollection.countDocuments({ 
      buyer_email: buyerEmail, 
      status: { $ne: "deleted" } 
    });

    // ✅ Sum of required_workers from buyer's tasks
    const tasks = await tasksCollection.find({ 
      buyer_email: buyerEmail, 
      status: { $ne: "deleted" } 
    }).toArray();
    const pendingWorkers = tasks.reduce((sum, task) => sum + (task.required_workers || 0), 0);

    // ✅ Sum of all approved submission payments
    const approvedSubs = await submissionsCollection.find({
      buyer_email: buyerEmail,
       status: { $in: ["approve", "approved"] }
    }).toArray();

    const totalPayments = approvedSubs.reduce((sum, sub) => sum + (sub.payable_amount || 0), 0);

    res.send({
      totalTasks,
      pendingWorkers,
      totalPayments,
    });

  } catch (error) {
    console.error("Buyer stats error:", error);
    res.status(500).send({ message: "Server error" });
  }
});


    app.get('/buyer-tasks', verifyFBToken, async (req, res) => {
      const email = req.query.email;

      // Optional: Make sure the email in query matches the email from verified token
      if (!email || email !== req.decoded.email) {
        return res.status(403).json({ message: 'Forbidden: invalid email' });
      }

      try {
        const tasks = await tasksCollection.find({ buyer_email: email }).toArray();
        res.json(tasks);
      } catch (error) {
        console.error('Failed to fetch buyer tasks:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    });


    app.patch('/tasks/:id', verifyFBToken, async (req, res) => {
  const taskId = req.params.id;
  const userEmail = req.decoded.email;
  const { task_title, task_detail, submission_info } = req.body;

  if (!task_title || !task_detail || !submission_info) {
    return res.status(400).json({ message: 'Missing required fields for update' });
  }

  try {
    // Find the task and verify ownership
    const task = await tasksCollection.findOne({ _id: new ObjectId(taskId) });
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }

    if (task.buyer_email !== userEmail) {
      return res.status(403).json({ message: 'Forbidden: You cannot update this task' });
    }

    // Update the allowed fields
    await tasksCollection.updateOne(
      { _id: new ObjectId(taskId) },
      { $set: { task_title, task_detail, submission_info, updatedAt: new Date() } }
    );

    res.json({ message: 'Task updated successfully' });
  } catch (error) {
    console.error('Error updating task:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


    app.delete('/tasks/:id', verifyFBToken, async (req, res) => {
      const taskId = req.params.id;
      const userEmail = req.decoded.email;

      try {
        // Find the task to verify ownership or permissions
        const task = await tasksCollection.findOne({ _id: new ObjectId(taskId) });
        if (!task) {
          return res.status(404).json({ message: 'Task not found' });
        }

        // Only allow the buyer who created the task to delete it
        if (task.buyer_email !== userEmail) {
          return res.status(403).json({ message: 'Forbidden: You cannot delete this task' });
        }

        await tasksCollection.deleteOne({ _id: new ObjectId(taskId) });
        res.json({ message: 'Task deleted successfully' });
      } catch (error) {
        console.error('Error deleting task:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    });

    app.patch('/refund-coins', verifyFBToken, async (req, res) => {
      const { email, coins } = req.body;

      if (!email || typeof coins !== 'number') {
        return res.status(400).json({ message: 'Email and coins are required' });
      }

      // Only allow refund for the authenticated user or admin (optional)
      if (email !== req.decoded.email) {
        return res.status(403).json({ message: 'Forbidden: cannot refund coins for another user' });
      }

      try {
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).json({ message: 'User not found' });

        await usersCollection.updateOne(
          { email },
          { $inc: { coins: coins } }
        );

        res.json({ message: 'Coins refunded successfully' });
      } catch (error) {
        console.error('Error refunding coins:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    });

    // purchase-coin route with Stripe integration & payment record
    
   app.post("/purchase-coin", verifyFBToken, async (req, res) => {
  try {
    const { coins, amount } = req.body;
    const email = req.decoded.email;

    if (!coins || !amount) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    const user = await usersCollection.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // 1. Update user's coins
    await usersCollection.updateOne(
      { email },
      { $inc: { coins: parseInt(coins) } }
    );

    // 2. Save to payments collection ✅
    const paymentRecord = {
      email,
      name: user.name,
      coins: parseInt(coins),
      amount_usd: parseFloat(amount),
      payment_method: "Stripe",
      payment_date: new Date(),
    };

    await paymentsCollection.insertOne(paymentRecord);

    res.json({ message: `Successfully purchased ${coins} coins` });
  } catch (error) {
    console.error("purchase-coin error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});


app.get('/buyer/submissions', verifyFBToken, async (req, res) => {
  const buyerEmail = req.decoded.email;

  try {
    // Get tasks created by this buyer
    const buyerTasks = await tasksCollection.find({ buyer_email: buyerEmail }).toArray();
    const taskIds = buyerTasks.map(task => task._id.toString());

    // Find all submissions for these tasks
    const submissions = await submissionsCollection.find({ task_id: { $in: taskIds } }).toArray();

    res.json(submissions);
  } catch (error) {
    console.error('Error fetching buyer submissions:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});




app.patch('/buyer/submissions/:id/approve', verifyFBToken, async (req, res) => {
  const submissionId = req.params.id;
  const buyerEmail = req.decoded.email;

  try {
    const submission = await submissionsCollection.findOne({ _id: new ObjectId(submissionId) });
    if (!submission) return res.status(404).json({ message: 'Submission not found' });

    // Verify ownership
    const task = await tasksCollection.findOne({ _id: new ObjectId(submission.task_id), buyer_email: buyerEmail });
    if (!task) return res.status(403).json({ message: 'Not authorized to approve this submission' });

    if (submission.status === 'approved') {
      return res.status(400).json({ message: 'Submission already approved' });
    }

    // Count how many submissions are already approved for this task
    const approvedCount = await submissionsCollection.countDocuments({
      task_id: submission.task_id,
      status: 'approved'
    });

    if (approvedCount >= task.required_workers) {
      return res.status(400).json({ message: 'Required number of workers already fulfilled' });
    }

    console.log('Approving submission:', submissionId, 'Payable:', submission.payable_amount, 'Worker email:', submission.worker_email);

    // Update submission status to approved
    await submissionsCollection.updateOne(
      { _id: new ObjectId(submissionId) },
      { $set: { status: 'approved', approvedAt: new Date() } }
    );

    // Increase worker coins
    const updateResult = await usersCollection.updateOne(
      { email: submission.worker_email },
      { $inc: { coins: submission.payable_amount || 0 } }
    );

    if (updateResult.matchedCount === 0) {
      return res.status(404).json({ message: 'Worker not found' });
    }

    res.json({ message: 'Submission approved and coins added to worker' });

  } catch (error) {
    console.error('Error approving submission:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


// PATCH reject submission by buyer
app.patch('/buyer/submissions/:id/reject', verifyFBToken, async (req, res) => {
  const submissionId = req.params.id;
  const buyerEmail = req.decoded.email;

  try {
    const submission = await submissionsCollection.findOne({ _id: new ObjectId(submissionId) });
    if (!submission) return res.status(404).json({ message: 'Submission not found' });

    // Verify ownership: submission's task must belong to this buyer
    const task = await tasksCollection.findOne({ _id: new ObjectId(submission.task_id), buyer_email: buyerEmail });
    if (!task) return res.status(403).json({ message: 'Not authorized to reject this submission' });

    if (submission.status === 'rejected') {
      return res.status(400).json({ message: 'Submission already rejected' });
    }

    await submissionsCollection.updateOne(
      { _id: new ObjectId(submissionId) },
      { $set: { status: 'rejected', rejectedAt: new Date() } }
    );

    res.json({ message: 'Submission rejected' });
  } catch (error) {
    console.error('Error rejecting submission:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


app.put('/api/submissions/approve/:id', verifyFBToken, async (req, res) => {
  const submissionId = req.params.id;

  // your approval logic here, e.g.:
  try {
    const result = await submissionsCollection.updateOne(
      { _id: new ObjectId(submissionId) },
      { $set: { status: 'approved' } }
    );
    if (result.matchedCount === 0) {
      return res.status(404).json({ message: 'Submission not found' });
    }
    res.json({ message: 'Submission approved successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});




app.put('/api/submissions/reject/:id', verifyFBToken, async (req, res) => {
  const submissionId = req.params.id;

  try {
    const result = await submissionsCollection.updateOne(
      { _id: new ObjectId(submissionId) },
      { $set: { status: 'rejected' } }
    );
    if (result.matchedCount === 0) {
      return res.status(404).json({ message: 'Submission not found' });
    }
    res.json({ message: 'Submission rejected successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});



    app.post('/submissions', async (req, res) => {
  const submission = req.body;

  try {
    submission.submitted_at = new Date();  // Use submitted_at here
    const result = await submissionsCollection.insertOne(submission);
    res.status(201).json({ message: 'Submission saved', id: result.insertedId });
  } catch (err) {
    console.error('Submission error:', err);
    res.status(500).json({ error: 'Failed to save submission' });
  }
});


    // GET /buyer/pending-submissions?email=buyer@example.com
   
app.get('/api/buyer/pending-submissions', verifyFBToken, async (req, res) => {
  const buyerEmail = req.query.email;
  if (!buyerEmail || buyerEmail !== req.decoded.email) {
    return res.status(403).json({ message: "Forbidden" });
  }

  try {
    const tasks = await tasksCollection.find({ buyer_email: buyerEmail }).toArray();
    const taskIds = tasks.map(t => t._id.toString()); // string IDs

    const submissions = await submissionsCollection.find({
      task_id: { $in: taskIds },
      status: "pending"
    }).toArray();

    res.json(submissions);
  } catch (err) {
    console.error('Error fetching pending submissions:', err);
    res.status(500).json({ message: "Server error" });
  }
});



    app.post('/purchase-coin', verifyFBToken, async (req, res) => {
  try {
    const { coins, amount } = req.body;
    const email = req.decoded.email;

    if (!coins || !amount) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Increase coins
    await usersCollection.updateOne(
      { email },
      { $inc: { coins: parseInt(coins, 10) } }
    );

    // Save payment info
    const paymentRecord = {
      email,
      name: user.name,
      coins: parseInt(coins),
      amount_usd: parseFloat(amount),
      payment_method: 'Stripe',
      payment_date: new Date(),
    };
    await paymentsCollection.insertOne(paymentRecord);

    res.json({ message: `Successfully purchased ${coins} coins` });
  } catch (error) {
    console.error('Error in purchase-coin:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


    app.get('/submissions', verifyFBToken, async (req, res) => {
      const email = req.query.email;
      if (!email) return res.status(400).json({ message: 'Email is required' });

      try {
        const submissions = await submissionsCollection
          .find({ worker_email: email })
          .sort({ current_date: -1 }) // Optional: newest first
          .toArray();
        res.json(submissions);
      } catch (err) {
        console.error('Fetch submissions error:', err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    app.get('/tasks/:id', async (req, res) => {
      const { id } = req.params;
      try {
        const task = await tasksCollection.findOne({ _id: new ObjectId(id) });
        if (!task) {
          return res.status(404).json({ message: 'Task not found' });
        }
        res.json(task);
      } catch (err) {
        console.error('Error fetching task:', err);
        res.status(500).json({ message: 'Server error' });
      }
    });



    // Route: GET /worker/tasks - fetch all open tasks for workers
app.get('/worker/tasks', verifyFBToken, async (req, res) => {
  try {
    const tasks = await tasksCollection.find({ status: 'open' }).sort({ createdAt: -1 }).toArray();
    res.json(tasks);
  } catch (error) {
    console.error('Error fetching tasks for worker:', error);
    res.status(500).json({ message: 'Server error' });
  }
});



app.post('/withdrawals', verifyFBToken, async (req, res) => {
  try {
    const {
      worker_email,
      worker_name,
      withdrawal_coin,
      withdrawal_amount,
      payment_system,
      account_number,
    } = req.body;

    // Basic validation
    if (!worker_email || !worker_name || !withdrawal_coin || !withdrawal_amount || !payment_system || !account_number) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    if (withdrawal_coin < 200) {
      return res.status(400).json({ message: 'Minimum withdrawal is 200 coins' });
    }

    // Check if user has enough coins
    const user = await usersCollection.findOne({ email: worker_email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (user.coins < withdrawal_coin) {
      return res.status(400).json({ message: 'Insufficient coins' });
    }

    // Insert withdrawal request with status pending
    const newWithdrawal = {
      worker_email,
      worker_name,
      withdrawal_coin,
      withdrawal_amount,
      payment_system,
      account_number,
      withdraw_date: new Date(),
      status: 'pending',
    };

    await withdrawalsCollection.insertOne(newWithdrawal);

    res.status(201).json({ message: 'Withdrawal request submitted successfully' });
  } catch (error) {
    console.error('Withdrawal request error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});



    // Admin routes

    app.get('/admin/withdrawals', verifyFBToken, verifyAdmin, async (req, res) => {
      const { status } = req.query;
      try {
        const query = status ? { status } : {};
        const result = await withdrawalsCollection.find(query).toArray();
        res.json(result);
      } catch (error) {
        console.error('Failed to get withdrawals:', error);
        res.status(500).json({ message: 'Failed to get withdrawals' });
      }
    });

    // GET /admin/users - get all users (admin only)
    app.get('/admin/users', verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const users = await usersCollection
          .find({}, { projection: { name: 1, email: 1, photo: 1, role: 1, coins: 1 } })
          .toArray();
        res.json(users);
      } catch (error) {
        console.error('Failed to fetch users:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
      }
    });

    // DELETE /admin/users/:email - delete user by email (admin only)
    app.delete('/admin/users/:email', verifyFBToken, verifyAdmin, async (req, res) => {
      const email = req.params.email;
      try {
        const result = await usersCollection.deleteOne({ email });
        if (result.deletedCount === 0) {
          return res.status(404).json({ error: 'User not found' });
        }
        res.json({ message: `User ${email} deleted successfully` });
      } catch (error) {
        console.error('Failed to delete user:', error);
        res.status(500).json({ error: 'Failed to delete user' });
      }
    });

    // PATCH /admin/users/:email/role - update user role (admin only)
    
app.patch('/admin/users/:email/role',  verifyFBToken,verifyAdmin, async (req, res) => {
  const { email } = req.params;
  const { role } = req.body;

  const validRoles = ['admin', 'buyer', 'worker'];
  if (!validRoles.includes(role)) {
    return res.status(400).json({ message: "Invalid role" });
  }

  try {
    const result = await usersCollection.updateOne({ email }, { $set: { role } });

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: "User not found or role unchanged" });
    }

    res.json({ message: `User role updated to ${role}` });
  } catch (error) {
    console.error('Error updating user role:', error);
    res.status(500).json({ message: "Internal server error" });
  }
});



    app.get('/admin/tasks', async (req, res) => {
  try {
    const tasks = await db.collection('tasks').find({}).toArray();
    res.json(tasks);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch tasks' });
  }
});

app.delete('/api/admin/tasks/:id',verifyFBToken, verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ message: 'Invalid task ID' });
    }

    const result = await db.collection('tasks').deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: 'Task not found' });
    }

    res.json({ message: 'Task deleted' });
  } catch (err) {
    console.error('Delete task error:', err);
    res.status(500).json({ message: 'Failed to delete task' });
  }
});




// GET /admin/home - Admin dashboard data (stats + pending withdrawals)
app.get('/admin/home', verifyFBToken, verifyAdmin, async (req, res) => {
  try {
    // 1. Aggregate counts
    const totalWorkers = await usersCollection.countDocuments({ role: 'worker' });
    const totalBuyers = await usersCollection.countDocuments({ role: 'buyer' });

    // 2. Sum total coins across all users
    const coinsAgg = await usersCollection.aggregate([
      { $group: { _id: null, totalCoins: { $sum: '$coins' } } }
    ]).toArray();
    const totalCoins = coinsAgg[0]?.totalCoins || 0;

    // 3. Sum total payments made by buyers
    const paymentsAgg = await paymentsCollection.aggregate([
      { $group: { _id: null, totalPayments: { $sum: '$amount_usd' } } }
    ]).toArray();
    const totalPayments = paymentsAgg[0]?.totalPayments || 0;

    // 4. Fetch pending withdrawal requests
    const pendingWithdrawals = await withdrawalsCollection.find({ status: 'pending' }).toArray();

    // 5. Send aggregated data
    res.json({
      totalWorkers,
      totalBuyers,
      totalCoins,
      totalPayments,
      pendingWithdrawals,
    });
  } catch (error) {
    console.error('Error fetching admin home data:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


// GET top 6 workers by coin count
app.get('/top-workers', async (req, res) => {
  try {
    const topWorkers = await usersCollection.aggregate([
      { $match: { role: 'worker' } },
      { $sort: { coins: -1 } },
      { $limit: 6 },
      {
        $project: {
          name: 1,
          coins: 1,
          img: '$photo'  // Rename photo to img for frontend consistency
        }
      }
    ]).toArray();

    res.status(200).json(topWorkers);
  } catch (error) {
    console.error('Error fetching top workers:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});



app.get('/users/profile', async (req, res) => {
  const email = req.query.email;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const user = await usersCollection.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (err) {
    console.error('Failed to get user profile:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});



app.post('/withdrawals', verifyFBToken, async (req, res) => {
  try {
    const {
      worker_email,
      worker_name,
      withdrawal_coin,
      withdrawal_amount,
      payment_system,
      account_number,
    } = req.body;

    // Basic validation
    if (!worker_email || !worker_name || !withdrawal_coin || !withdrawal_amount || !payment_system || !account_number) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    if (withdrawal_coin < 200) {
      return res.status(400).json({ message: 'Minimum withdrawal is 200 coins' });
    }

    // Check if user has enough coins
    const user = await usersCollection.findOne({ email: worker_email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (user.coins < withdrawal_coin) {
      return res.status(400).json({ message: 'Insufficient coins' });
    }

    // Insert withdrawal request with status pending
    const newWithdrawal = {
      worker_email,
      worker_name,
      withdrawal_coin,
      withdrawal_amount,
      payment_system,
      account_number,
      withdraw_date: new Date(),
      status: 'pending',
    };

    await withdrawalsCollection.insertOne(newWithdrawal);

    res.status(201).json({ message: 'Withdrawal request submitted successfully' });
  } catch (error) {
    console.error('Withdrawal request error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});



    // POST /admin/withdrawals/:id/approve - approve a withdrawal (admin only)
  app.post('/admin/withdrawals/:id/approve', verifyFBToken, verifyAdmin, async (req, res) => {
  const withdrawalId = req.params.id;

  try {
    const withdrawal = await withdrawalsCollection.findOne({ _id: new ObjectId(withdrawalId) });
    if (!withdrawal) return res.status(404).json({ message: 'Withdrawal not found' });

    if (withdrawal.status === 'approved') {
      return res.status(400).json({ message: 'Withdrawal already approved' });
    }

    const user = await usersCollection.findOne({ email: withdrawal.worker_email });
    if (!user) return res.status(404).json({ message: 'Worker not found' });

    if (user.coins < withdrawal.withdrawal_coin) {
      return res.status(400).json({ message: 'Worker has insufficient coins' });
    }

    // Deduct coins from user
    await usersCollection.updateOne(
      { email: withdrawal.worker_email },
      { $inc: { coins: -withdrawal.withdrawal_coin } }
    );

    // Update withdrawal status to approved
    await withdrawalsCollection.updateOne(
      { _id: new ObjectId(withdrawalId) },
      { $set: { status: 'approved', approvedAt: new Date() } }
    );

    res.json({ message: 'Withdrawal approved and coins deducted' });
  } catch (error) {
    console.error('Error approving withdrawal:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


    // GET /admin/stats - get admin dashboard stats (admin only)
    app.get('/admin/stats', verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const totalWorkers = await usersCollection.countDocuments({ role: 'worker' });
        const totalBuyers = await usersCollection.countDocuments({ role: 'buyer' });

        const coinsAgg = await usersCollection.aggregate([
          { $group: { _id: null, totalCoins: { $sum: '$coins' } } }
        ]).toArray();

        const paymentsAgg = await paymentsCollection.aggregate([
          { $group: { _id: null, totalPayments: { $sum: '$amount_usd' } } }
        ]).toArray();

        res.json({
          totalWorkers,
          totalBuyers,
          totalCoins: coinsAgg[0]?.totalCoins || 0,
          totalPayments: paymentsAgg[0]?.totalPayments || 0,
        });
      } catch (error) {
        console.error('Failed to fetch admin stats:', error);
        res.status(500).json({ message: 'Failed to fetch stats' });
      }
    });

    // await client.db('admin').command({ ping: 1 });
    console.log("🟢 Successfully connected to MongoDB and pinged.");

  } catch (err) {
    console.error('Failed to connect to MongoDB:', err);
  }
}
run();

app.get('/', (req, res) => {
  res.send('Micro Tasking and Earning Platform API is running');
});

app.listen(port, () => {
  console.log(`⚡ Server is running on port ${port}`);
});


