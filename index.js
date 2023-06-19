const express = require('express');
const mongoose = require('mongoose');
const { Snowflake } = require('@theinternetfolks/snowflake');
// const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Connect to MongoDB using Mongoose
mongoose.connect('mongodb+srv://onlinejudge:12345678lokesh@cluster0.c0rnqdi.mongodb.net/?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.error('Error connecting to MongoDB:', error);
  });

// Define the models

function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
  
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
  
    jwt.verify(token, 'your_secret_key', (err, user) => {
      if (err) {
        return res.status(403).json({ error: 'Invalid token' });
      }
  
      req.user = user;
      next();
    });
  }

const User = mongoose.model('User', new mongoose.Schema({
  id: {
    type: String,
    default: Snowflake.generate(),
  },
  name: {
    type: String,
    required: true,
    maxlength: 64,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    maxlength: 128,
  },
  password: {
    type: String,
    required: true,
    maxlength: 64,
  },
  created_at: {
    type: Date,
    default: Date.now,
  },
}));

const Community = mongoose.model('Community', new mongoose.Schema({
  id: {
    type: String,
    default: Snowflake.generate(),
  },
  name: {
    type: String,
    required: true,
    maxlength: 128,
  },
  slug: {
    type: String,
    unique: true,
    maxlength: 255,
  },
  owner: {
    type: String,
    ref: 'User',
    required: true,
  },
  created_at: {
    type: Date,
    default: Date.now,
  },
  updated_at: {
    type: Date,
    default: Date.now,
  },
}));

const Role = mongoose.model('Role', new mongoose.Schema({
  id: {
    type: String,
    default: Snowflake.generate(),
  },
  name: {
    type: String,
    required: true,
    unique: true,
    maxlength: 64,
  },
  created_at: {
    type: Date,
    default: Date.now,
  },
  updated_at: {
    type: Date,
    default: Date.now,
  },
}));

const Member = mongoose.model('Member', new mongoose.Schema({
  id: {
    type: String,
    default: Snowflake.generate(),
  },
  community: {
    type: String,
    ref: 'Community',
    required: true,
  },
  user: {
    type: String,
    ref: 'User',
    required: true,
  },
  role: {
    type: String,
    ref: 'Role',
    required: true,
  },
  created_at: {
    type: Date,
    default: Date.now,
  },
}));

// Routes


app.post('/v1/role', (req, res) => {
    const { name } = req.body;
  
    // Validate the 'name' field
    if (!name || name.length < 2) {
      return res.status(400).json({ error: 'Invalid role name' });
    }
  
    // Create the role
    Role.create({ name })
      .then((role) => {
        res.json({ role });
      })
      .catch((error) => {
        res.status(500).json({ error: 'Failed to create role' });
      });
  });
  

  app.get('/v1/role', (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
  
    // Fetch the total count of roles
    Role.countDocuments()
      .then((total) => {
        // Calculate the total number of pages
        const pages = Math.ceil(total / limit);
  
        // Calculate the starting index for the current page
        const startIndex = (page - 1) * limit;
  
        // Fetch the roles for the current page
        Role.find()
          .skip(startIndex)
          .limit(limit)
          .then((roles) => {
            res.json({
              status: true,
              content: {
                meta: {
                  total,
                  pages,
                  page,
                },
                data: roles,
              },
            });
          })
          .catch((error) => {
            res.status(500).json({ error: 'Failed to fetch roles' });
          });
      })
      .catch((error) => {
        res.status(500).json({ error: 'Failed to count roles' });
      });
  });
  

  
  
  app.post('/v1/auth/signup', (req, res) => {
    const { name, email, password } = req.body;
  
    // Validate input fields
    if (!name || name.length < 2 || !email || !password || password.length < 6) {
      return res.status(400).json({ error: 'Invalid input fields' });
    }
  
    // Check if the user with the same email already exists
    User.findOne({ email })
      .then((existingUser) => {
        if (existingUser) {
          return res.status(409).json({ error: 'Email is already registered' });
        }
  
        // Hash the password
        bcrypt.hash(password, 10, (err, hashedPassword) => {
          if (err) {
            return res.status(500).json({ error: 'Error hashing password' });
          }
  
          // Create a new user
          const user = new User({
            name,
            email,
            password: hashedPassword,
          });
  
          // Save the user to the database
          user.save()
            .then(() => {
              // Generate an access token
              const token = jwt.sign({ id: user.id }, 'your-secret-key', { expiresIn: '1h' });
  
              // Return the response with the user data and access token
              res.json({
                status: true,
                content: {
                  data: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    created_at: user.created_at,
                  },
                  meta: {
                    access_token: token,
                  },
                },
              });
            })
            .catch((error) => {
              res.status(500).json({ error: 'Error creating user' });
            });
        });
      })
      .catch((error) => {
        res.status(500).json({ error: 'Error checking existing user' });
      });
  });
  

  app.post('/v1/auth/signin', (req, res) => {
    const { email, password } = req.body;
  
    // Validate input fields
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
  
    // Find the user by email
    User.findOne({ email })
      .then((user) => {
        if (!user) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }
  
        // Compare the provided password with the hashed password
        bcrypt.compare(password, user.password, (err, result) => {
          if (err || !result) {
            return res.status(401).json({ error: 'Invalid credentials' });
          }
  
          // Generate an access token
          const token = jwt.sign({user :user}, 'your-secret-key', { expiresIn: '1h' });
  
          // Return the response with the user data (excluding the password) and the access token
          res.json({
            status: true,
            content: {
              data: {
                id: user.id,
                name: user.name,
                email: user.email,
                created_at: user.created_at,
              },
              meta: {
                access_token: token,
              },
            },
          });
        });
      })
      .catch((error) => {
        res.status(500).json({ error: 'Error signing in' });
      });
  });
  

  app.get('/v1/auth/me', (req, res) => {
    // const {  name, email, created_at } = req.user;
    let token = req.header("Authorization").replace("Bearer ", "");
    const decoded = jwt.verify(
      token,
      'your-secret-key',
      (err, decoded) => {
        return decoded;
      }
    );
    console.log(decoded);
    // res.send(200);
  
    // Return the response with the user data (excluding the password)
    res.json({
        status: true,
        content: {
          data: {
            name: decoded.user.name,
            email: decoded.user.email,
            created_at: decoded.user.created_at,
          },
        },
      });
      
  });


  app.post('/v1/community', (req, res) => {
    let token = req.header("Authorization").replace("Bearer ", "");
    const decoded = jwt.verify(
      token,
      'your-secret-key',
      (err, decoded) => {
        return decoded;
      }
    );
    console.log(decoded);
    const { name } = decoded.user.name;
    const { id } =  decoded.user.id;
  
    // Generate the slug from the name (replace spaces with dashes)
    const slug = name;
  
    // Create the community and set the owner
    const community = new Community({
      name,
      slug,
      id,
    });
    console.log("i am here");
    console.log("community",community);
  
    // Save the community to the database
    community.save()
      .then((savedCommunity) => {
        // Create a member for the owner with the role "Community Admin"
        
        const member = new Member({
          community: savedCommunity._id,
          user: owner,
          role: 'Community Admin',
        });

  
        // Save the member to the database
        return member.save();
      })
      .then(() => {
        // Return the response with the created community data
        res.json({
          status: true,
          content: {
            data: {
              id: community._id,
              name: community.name,
              slug: community.slug,
              owner: community.owner,
              created_at: community.created_at,
              updated_at: community.updated_at,
            },
          },
        });
      })
      .catch((error) => {
        // Handle any errors that occur during the creation process
        res.status(500).json({ error: 'Error creating the community' });
      });
  });
  

  app.get('/v1/community', (req, res) => {
    const perPage = 10; // Number of communities per page
    const page = req.query.page || 1; // Current page number (default: 1)
  
    // Count the total number of communities
    Community.countDocuments()
      .then((total) => {
        // Calculate the total number of pages
        const totalPages = Math.ceil(total / perPage);
  
        // Find the communities with pagination and populate the owner field with limited fields
        Community.find()
          .select('name slug owner created_at updated_at')
          .populate('owner', 'id name')
          .skip((page - 1) * perPage)
          .limit(perPage)
          .then((communities) => {
            // Return the response with the community data and pagination metadata
            res.json({
              status: true,
              content: {
                meta: {
                  total,
                  pages: totalPages,
                  page: parseInt(page),
                },
                data: communities,
              },
            });
          })
          .catch((error) => {
            // Handle any errors that occur during the retrieval process
            res.status(500).json({ error: 'Error retrieving the communities' });
          });
      })
      .catch((error) => {
        // Handle any errors that occur during the count process
        res.status(500).json({ error: 'Error counting the communities' });
      });
  });
  

  app.get('/v1/community/:id/members', (req, res) => {
    const perPage = 10; // Number of members per page
    const page = req.query.page || 1; // Current page number (default: 1)
  
    // Count the total number of members in the community
    Member.countDocuments({ community: req.params.id })
      .then((total) => {
        // Calculate the total number of pages
        const totalPages = Math.ceil(total / perPage);
  
        // Find the members with pagination and populate the user and role fields with limited fields
        Member.find({ community: req.params.id })
          .select('community user role created_at')
          .populate('user', 'id name')
          .populate('role', 'id name')
          .skip((page - 1) * perPage)
          .limit(perPage)
          .then((members) => {
            // Return the response with the member data and pagination metadata
            res.json({
              status: true,
              content: {
                meta: {
                  total,
                  pages: totalPages,
                  page: parseInt(page),
                },
                data: members,
              },
            });
          })
          .catch((error) => {
            // Handle any errors that occur during the retrieval process
            res.status(500).json({ error: 'Error retrieving the members' });
          });
      })
      .catch((error) => {
        // Handle any errors that occur during the count process
        res.status(500).json({ error: 'Error counting the members' });
      });
  });
  

  app.get('/v1/community/me/owner', authenticateToken, (req, res) => {
    const perPage = 10; // Number of communities per page
    const page = req.query.page || 1; // Current page number (default: 1)
  
    // Count the total number of communities owned by the user
    Community.countDocuments({ owner: req.user.id })
      .then((total) => {
        // Calculate the total number of pages
        const totalPages = Math.ceil(total / perPage);
  
        // Find the communities owned by the user with pagination
        Community.find({ owner: req.user.id })
          .skip((page - 1) * perPage)
          .limit(perPage)
          .then((communities) => {
            // Return the response with the community data and pagination metadata
            res.json({
              status: true,
              content: {
                meta: {
                  total,
                  pages: totalPages,
                  page: parseInt(page),
                },
                data: communities,
              },
            });
          })
          .catch((error) => {
            // Handle any errors that occur during the retrieval process
            res.status(500).json({ error: 'Error retrieving the communities' });
          });
      })
      .catch((error) => {
        // Handle any errors that occur during the count process
        res.status(500).json({ error: 'Error counting the communities' });
      });
  });
  

  app.get('/v1/community/me/member', authenticateToken, (req, res) => {
    const perPage = 10; // Number of communities per page
    const page = req.query.page || 1; // Current page number (default: 1)
  
    // Count the total number of communities the user has joined
    CommunityMember.countDocuments({ user: req.user.id })
      .then((total) => {
        // Calculate the total number of pages
        const totalPages = Math.ceil(total / perPage);
  
        // Find the communities the user has joined with pagination
        CommunityMember.find({ user: req.user.id })
          .skip((page - 1) * perPage)
          .limit(perPage)
          .populate('community', 'id name slug owner')
          .populate('role', 'id name')
          .then((communityMembers) => {
            // Return the response with the community data and pagination metadata
            res.json({
              status: true,
              content: {
                meta: {
                  total,
                  pages: totalPages,
                  page: parseInt(page),
                },
                data: communityMembers,
              },
            });
          })
          .catch((error) => {
            // Handle any errors that occur during the retrieval process
            res.status(500).json({ error: 'Error retrieving the community members' });
          });
      })
      .catch((error) => {
        // Handle any errors that occur during the count process
        res.status(500).json({ error: 'Error counting the community members' });
      });
  });
  

  app.post('/v1/member', authenticateToken, (req, res) => {
    const { community, user, role } = req.body;
  
    // Check if the authenticated user is a Community Admin
    if (req.user.role !== 'Community Admin') {
      return res.status(403).json({ error: 'NOT_ALLOWED_ACCESS' });
    }
  
    // Create a new member using the provided data
    const member = new CommunityMember({
      community,
      user,
      role,
      created_at: new Date(),
    });
  
    // Save the member to the database
    member.save()
      .then((savedMember) => {
        // Return the response with the added member data
        res.json({
          status: true,
          content: {
            data: savedMember,
          },
        });
      })
      .catch((error) => {
        // Handle any errors that occur during the saving process
        res.status(500).json({ error: 'Error adding the member' });
      });
  });
  
  

  app.delete('/v1/member/:id', authenticateToken, (req, res) => {
    const memberId = req.params.id;
  
    // Find the member in the database by ID
    CommunityMember.findById(memberId)
      .then((member) => {
        // Check if the member exists
        if (!member) {
          return res.status(404).json({ error: 'Member not found' });
        }
  
        // Check if the authenticated user is a Community Admin or Community Moderator
        const isAdmin = req.user.role === 'Community Admin';
        const isModerator = req.user.role === 'Community Moderator';
  
        if (!isAdmin && !isModerator) {
          return res.status(403).json({ error: 'NOT_ALLOWED_ACCESS' });
        }
  
        // Remove the member from the database
        member.remove()
          .then(() => {
            res.json({ status: true });
          })
          .catch((error) => {
            res.status(500).json({ error: 'Error removing the member' });
          });
      })
      .catch((error) => {
        res.status(500).json({ error: 'Error finding the member' });
      });
  });
  

// Start the server
const port = 2500;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});