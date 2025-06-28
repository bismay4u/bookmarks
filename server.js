const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const cheerio = require('cheerio');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { JSDOM } = require('jsdom');
const { Readability } = require('@mozilla/readability');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const IP_WHITELIST = process.env.IP_WHITELIST.split(",") || [];
const AUTH_TOKENS = process.env.API_AUTHTOKEN.split(",") || [];

app.set('trust proxy', 1); /* number of proxies between user and server */

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false // Disable for development
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

app.use(function(req, res, next) {
  //console.log("REQUEST_URL", req.method, req.url, req.headers, req.body, req.query, req.params);
  const REQ_URI = req.url.split("?")[0];
  const MY_IP = req.headers['x-forwarded-for']?req.headers['x-forwarded-for']:(req.headers['x-real-ip']?req.headers['x-real-ip']:"-");
  
  if(req.headers.authorization==null && req.headers['apikey']!=null) {
    req.headers.authorization = `Bearer ${req.headers['apikey']}`;
  }

  //ByPass
  if(["/cron"].indexOf(REQ_URI)>=0) {
    return next();
  }

  //Header Authorization
  if(["/addURL"].indexOf(REQ_URI)>=0) {
    if(req.headers.authorization==null || req.headers.authorization.length<=0) {
      res.status(403).send("Unauthorised");
      return;
    }

    var authToken = req.headers.authorization.split(" ");
    if(authToken[1]==null) authToken[1] = "";

    if(AUTH_TOKENS.indexOf(authToken[1])>=0) {
      return next();
    }

    res.status(403).send("Unauthorised");
    return;
  }

  if(IP_WHITELIST.length>0 && IP_WHITELIST[0].length>0) {
    if(IP_WHITELIST.indexOf(MY_IP)<0) {
      console.error("IP WHITELIST FAILURE", MY_IP, req.headers);

      res.status(403).send("Unauthorised");
      return;
    }
  }
  
  return next();
});

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'bookmark_manager',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

let pool;

// Initialize database connection
async function initDatabase() {
  try {
    pool = mysql.createPool(dbConfig);
    console.log('Database connected successfully');
    
    // Create tables if they don't exist
    await createTables();
  } catch (error) {
    console.error('Database connection failed:', error);
    process.exit(1);
  }
}

async function createTables() {
  const createCategoriesTable = `
    CREATE TABLE IF NOT EXISTS categories (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(255) NOT NULL UNIQUE,
      icon VARCHAR(100) DEFAULT 'folder',
      color VARCHAR(7) DEFAULT '#007bff',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  const createBookmarksTable = `
    CREATE TABLE IF NOT EXISTS bookmarks (
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(500) NOT NULL,
      url TEXT NOT NULL,
      description TEXT,
      favicon_url TEXT,
      image_url TEXT,
      category_id INT,
      tags VARCHAR(500),
      is_read BOOLEAN DEFAULT FALSE,
      is_favorite BOOLEAN DEFAULT FALSE,
      is_archived BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL,
      INDEX idx_category (category_id),
      INDEX idx_read (is_read),
      INDEX idx_favorite (is_favorite),
      INDEX idx_archived (is_archived)
    )
  `;

  try {
    await pool.execute(createCategoriesTable);
    await pool.execute(createBookmarksTable);
    
    // Insert default categories
    const defaultCategories = [
      ['All', 'list', '#6c757d'],
      ['Unread', 'eye-slash', '#007bff'],
      ['Archive', 'archive', '#6c757d'],
      ['Favorites', 'heart', '#dc3545'],
      ['Articles', 'file-text', '#28a745'],
      ['Videos', 'play-circle', '#fd7e14'],
      ['Pictures', 'image', '#e83e8c']
    ];

    for (const [name, icon, color] of defaultCategories) {
      await pool.execute(
        'INSERT IGNORE INTO categories (name, icon, color) VALUES (?, ?, ?)',
        [name, icon, color]
      );
    }
    
    console.log('Database tables created successfully');
  } catch (error) {
    console.error('Error creating tables:', error);
  }
}

//Sanitize Input String
function sanitizeString(input) {
    // Replace all non-alphanumeric characters with _
    let result = input.replace(/[^a-zA-Z0-9]/g, '_');
    
    // Replace multiple consecutive underscores with a single underscore
    result = result.replace(/_+/g, '_');
    
    // (Optional) Trim leading and trailing underscores
    result = result.replace(/^_+|_+$/g, '');

    return result;
}

// URL metadata fetcher
async function fetchUrlMetadata(url) {
  try {
    const response = await axios.get(url, {
      timeout: 10000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });
    
    const $ = cheerio.load(response.data);
    
    const title = $('title').text() || 
                  $('meta[property="og:title"]').attr('content') || 
                  $('meta[name="twitter:title"]').attr('content') || 
                  'Untitled';
    
    const description = $('meta[name="description"]').attr('content') ||
                       $('meta[property="og:description"]').attr('content') ||
                       $('meta[name="twitter:description"]').attr('content') || '';
    
    const image = $('meta[property="og:image"]').attr('content') ||
                  $('meta[name="twitter:image"]').attr('content') || '';
    
    const favicon = $('link[rel="icon"]').attr('href') ||
                   $('link[rel="shortcut icon"]').attr('href') ||
                   `${new URL(url).origin}/favicon.ico`;
    
    return {
      title: title.trim().substring(0, 500),
      description: description.trim().substring(0, 1000),
      image_url: image,
      favicon_url: favicon.startsWith('http') ? favicon : new URL(favicon, url).href
    };
  } catch (error) {
    console.error('Error fetching metadata:', error);
    return {
      title: new URL(url).hostname,
      description: '',
      image_url: '',
      favicon_url: `${new URL(url).origin}/favicon.ico`
    };
  }
}

// API Routes

// Get all categories
app.post('/api/categories', async (req, res) => {
  try {
    const { author } = req.body;

    const [rows] = await pool.execute('SELECT * FROM categories ORDER BY name');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get bookmarks with filters
app.post('/api/bookmarks', async (req, res) => {
  try {
    const { category, search, filter, page = 1, limit = 20 } = req.query;
    const { author } = req.body;

    const offset = (page - 1) * limit;
    
    let query = `
      SELECT b.*, c.name as category_name, c.icon as category_icon, c.color as category_color
      FROM bookmarks b
      LEFT JOIN categories c ON b.category_id = c.id
      WHERE 1=1 AND author=? AND b.blocked = 'false'
    `;
    const params = [author];
    
    // Apply filters
    if (category && category !== 'All') {
      if (category === 'Unread') {
        query += ' AND b.is_read = FALSE AND b.is_archived = FALSE';
      } else if (category === 'Archive') {
        query += ' AND b.is_archived = TRUE';
      } else if (category === 'Favorites') {
        query += ' AND b.is_favorite = TRUE AND b.is_archived = FALSE';
      } else {
        query += ' AND c.name = ?';
        params.push(category);
      }
    }
    
    if (search) {
      query += ' AND (b.title LIKE ? OR b.description LIKE ? OR b.url LIKE ?)';
      const searchParam = `%${search}%`;
      params.push(searchParam, searchParam, searchParam);
    }
    
    // Add ordering
    query += ' ORDER BY b.created_at DESC LIMIT ? OFFSET ?';
    params.push(""+(limit), ""+(offset));
    
    const [rows] = await pool.execute(query, params);
    
    // Get total count for pagination
    let countQuery = `
      SELECT COUNT(*) as total
      FROM bookmarks b
      LEFT JOIN categories c ON b.category_id = c.id
      WHERE 1=1
    `;
    const countParams = params.slice(0, -2); // Remove limit and offset
    
    if (category && category !== 'All') {
      if (category === 'Unread') {
        countQuery += ' AND b.is_read = FALSE AND b.is_archived = FALSE';
      } else if (category === 'Archive') {
        countQuery += ' AND b.is_archived = TRUE';
      } else if (category === 'Favorites') {
        countQuery += ' AND b.is_favorite = TRUE AND b.is_archived = FALSE';
      } else {
        countQuery += ' AND c.name = ?';
      }
    }
    
    if (search) {
      countQuery += ' AND (b.title LIKE ? OR b.description LIKE ? OR b.url LIKE ?)';
    }
    
    const [countResult] = await pool.execute(countQuery, countParams);
    const total = countResult[0].total;
    
    res.json({
      bookmarks: rows,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {console.log(error);
    res.status(500).json({ error: error.message });
  }
});

// Add new bookmark
app.post('/api/bookmarks/create', async (req, res) => {
  try {
    const { url, category_id, tags, author } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }
    
    // Fetch metadata
    const metadata = await fetchUrlMetadata(url);
    
    const [result] = await pool.execute(
      `INSERT INTO bookmarks (title, url, description, favicon_url, image_url, category_id, author, tags)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        metadata.title,
        url,
        metadata.description,
        metadata.favicon_url,
        metadata.image_url,
        category_id || null,
        author,
        tags//JSON.stringify(tags || [])
      ]
    );
    
    // Get the created bookmark with category info
    const [bookmark] = await pool.execute(
      `SELECT b.*, c.name as category_name, c.icon as category_icon, c.color as category_color
       FROM bookmarks b
       LEFT JOIN categories c ON b.category_id = c.id
       WHERE b.id = ?`,
      [result.insertId]
    );
    
    res.status(201).json(bookmark[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update bookmark
app.put('/api/bookmarks/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    
    const allowedFields = ['title', 'description', 'is_read', 'is_favorite', 'is_archived', 'category_id', 'tags'];
    const setClause = [];
    const params = [];
    
    for (const [key, value] of Object.entries(updates)) {
      if (allowedFields.includes(key)) {
        setClause.push(`${key} = ?`);
        //params.push(key === 'tags' ? JSON.stringify(value) : value);
        params.push(key === 'tags' ? value : value);
      }
    }
    
    if (setClause.length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }
    
    params.push(id);
    
    await pool.execute(
      `UPDATE bookmarks SET ${setClause.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
      params
    );
    
    // Get updated bookmark
    const [bookmark] = await pool.execute(
      `SELECT b.*, c.name as category_name, c.icon as category_icon, c.color as category_color
       FROM bookmarks b
       LEFT JOIN categories c ON b.category_id = c.id
       WHERE b.id = ?`,
      [id]
    );
    
    res.json(bookmark[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete bookmark
app.delete('/api/bookmarks/:id', async (req, res) => {
  try {
    const { id } = req.params;
    //await pool.execute('DELETE FROM bookmarks WHERE id = ?', [id]);
    await pool.execute('UPDATE bookmarks SET blocked="true", updated_at = CURRENT_TIMESTAMP WHERE id = ?', [id]);
    res.json({ message: 'Bookmark deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get bookmark counts for categories
app.post('/api/stats', async (req, res) => {
  try {
    var { author } = req.body;
    author = sanitizeString(author);
    
    const [stats] = await pool.execute(`
      SELECT 
        (SELECT COUNT(*) FROM bookmarks WHERE blocked="false" AND author='${author}' AND is_archived = FALSE) as all_count,
        (SELECT COUNT(*) FROM bookmarks WHERE blocked="false" AND author='${author}' AND is_read = FALSE AND is_archived = FALSE) as unread_count,
        (SELECT COUNT(*) FROM bookmarks WHERE blocked="false" AND author='${author}' AND is_archived = TRUE) as archive_count,
        (SELECT COUNT(*) FROM bookmarks WHERE blocked="false" AND author='${author}' AND is_favorite = TRUE AND is_archived = FALSE) as favorites_count,
        (SELECT COUNT(*) FROM bookmarks b JOIN categories c ON b.category_id = c.id WHERE c.name = 'Articles' AND b.blocked="false" AND b.is_archived = FALSE AND b.author='${author}') as articles_count,
        (SELECT COUNT(*) FROM bookmarks b JOIN categories c ON b.category_id = c.id WHERE c.name = 'Videos' AND b.blocked="false" AND b.is_archived = FALSE AND b.author='${author}') as videos_count,
        (SELECT COUNT(*) FROM bookmarks b JOIN categories c ON b.category_id = c.id WHERE c.name = 'Pictures' AND b.blocked="false" AND b.is_archived = FALSE AND b.author='${author}') as pictures_count,
        (SELECT COUNT(*) FROM bookmarks WHERE blocked="false" AND author='${author}' AND is_processed=0) as unprocessed,
        (SELECT COUNT(*) FROM bookmarks WHERE blocked="false" AND author='${author}' AND is_processed=1) as processed
    `);
    
    res.json(stats[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

//Cron Job to process unprocessed Bookmarks
app.get('/cron', async (req, res) => {
  let query = `
      SELECT *
      FROM bookmarks
      WHERE blocked = 'false' AND is_processed=0
      ORDER BY created_at DESC LIMIT 10
    `;
  //favicon_url

  const [rows] = await pool.execute(query, []);

  if(!rows) {
    res.send("okay");
    return next();
  }

  rows.forEach(async function(row, k) {
    // console.log("#ID", row.id);
    if(row.url.length<=1) {
      await pool.execute('UPDATE bookmarks SET blocked="true", updated_at = CURRENT_TIMESTAMP, tags = concat(tags,",INVALID") WHERE id = ?', [row.id]);
    } else if(row.description.length>0) {
      await pool.execute('UPDATE bookmarks SET is_processed=1, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [row.id]);
    } else {
      try {
        const metadata = await fetchUrlMetadata(row.url);

        const setClause = [];
        const dataParams = [];
        
        if(metadata.title.length>0) {
          dataParams.push(metadata.title);
          setClause.push(`title = ?`);
        }
        if(metadata.description.length>0) {
          dataParams.push(metadata.description);
          setClause.push(`description = ?`);
        }
        if(metadata.favicon_url.length>0) {
          dataParams.push(metadata.favicon_url);
          setClause.push(`favicon_url = ?`);
        }
        if(metadata.image_url.length>0) {
          dataParams.push(metadata.image_url);  
          setClause.push(`image_url = ?`);
        }

        dataParams.push(row.id);

        await pool.execute(`UPDATE bookmarks SET ${setClause.join(', ')}, updated_at = CURRENT_TIMESTAMP, is_processed=1 WHERE id = ?`, dataParams);
        //console.log("CRON_META", row.id, metadata);
      } catch(error) {
        console.error("CRON_META_ERROR", row.id, error);
        await pool.execute('UPDATE bookmarks SET updated_at = CURRENT_TIMESTAMP, tags = concat(tags,",ERROR") WHERE id = ?', [row.id]);
      }
    }
  });

  res.send("okay");
});

// Add URL via various remote methods
app.get('/addURL', async (req, res) => {
  console.log("ADD_URL", req.query);

  if(req.query.url!=null && req.query.url.length>5) {

    try {
      new URL(req.query.url)
    } catch(e) {
      res.send(e.message);
      return;
    }

    var category_id = 5;
    var tags = "";

    await pool.execute(
      `INSERT INTO bookmarks (title, url, description, favicon_url, image_url, category_id, author, tags)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.query.title?req.query.title:"",
        req.query.url,
        req.query.description?req.query.description:"",
        req.query.favicon_url?req.query.favicon_url:"",
        req.query.image_url?req.query.image_url:"",
        category_id || 5,
        req.query.author?req.query.author:"",
        tags
      ]
    );
    res.send("Added");
  } else {
    res.send("Error finding URL");
  }
});

app.post('/addURL', async (req, res) => {
  console.log("ADD_URL", req.body);

  if(req.body.url!=null && req.body.url.length>5) {
    
    try {
      new URL(req.body.url)
    } catch(e) {
      res.send(e.message);
      return;
    }

    var category_id = 5;
    var tags = "";

    await pool.execute(
      `INSERT INTO bookmarks (title, url, description, favicon_url, image_url, category_id, author, tags)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.body.title?req.body.title:"",
        req.body.url,
        req.body.description?req.body.description:"",
        req.body.favicon_url?req.body.favicon_url:"",
        req.body.image_url?req.body.image_url:"",
        category_id || 5,
        req.body.author?req.body.author:"",
        tags
      ]
    );
    res.send("Added");
  } else {
    res.send("Error finding URL");
  }
});

// Serve the main HTML file
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Initialize database and start server
initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
});

module.exports = app;

