require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend files
app.use(express.static('./'));

const VT_API_KEY = process.env.VT_API_KEY;
const NEWS_API_KEY = process.env.NEWS_API_KEY;

// Base64 URL Safe helper for VirusTotal URL Identifiers
function toUrlSafeBase64(url) {
    const base64 = Buffer.from(url).toString('base64');
    return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

// ==========================================
// 1. VIRUSTOTAL v3 URL SCAN ENDPOINTS
// ==========================================

// Endpoint A: Instant Lookup by Base64 URL ID
app.get('/api/scan-url/lookup', async (req, res) => {
    try {
        const targetUrl = req.query.url;
        if (!targetUrl) return res.status(400).json({ error: 'URL query parameter is required' });

        const urlId = toUrlSafeBase64(targetUrl);
        const vtUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;

        const response = await fetch(vtUrl, {
            method: 'GET',
            headers: {
                'x-apikey': VT_API_KEY,
                'Accept': 'application/json'
            }
        });

        const data = await response.json();
        return res.status(response.status).json(data);
    } catch (err) {
        return res.status(500).json({ error: 'Internal server proxy error during VirusTotal lookup', details: err.message });
    }
});

// Endpoint B: Submit New URL for VirusTotal Scanning
app.post('/api/scan-url/submit', async (req, res) => {
    try {
        const { url } = req.body;
        if (!url) return res.status(400).json({ error: 'URL is required in body' });

        const formBody = new URLSearchParams();
        formBody.append('url', url);

        const response = await fetch('https://www.virustotal.com/api/v3/urls', {
            method: 'POST',
            headers: {
                'x-apikey': VT_API_KEY,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: formBody.toString()
        });

        const data = await response.json();
        return res.status(response.status).json(data);
    } catch (err) {
        return res.status(500).json({ error: 'Internal server proxy error during VirusTotal submission', details: err.message });
    }
});

// Endpoint C: Poll VirusTotal Analysis ID Status
app.get('/api/scan-url/analysis/:id', async (req, res) => {
    try {
        const analysisId = req.params.id;
        const vtUrl = `https://www.virustotal.com/api/v3/analyses/${analysisId}`;

        const response = await fetch(vtUrl, {
            method: 'GET',
            headers: {
                'x-apikey': VT_API_KEY,
                'Accept': 'application/json'
            }
        });

        const data = await response.json();
        return res.status(response.status).json(data);
    } catch (err) {
        return res.status(500).json({ error: 'Internal server proxy error during VirusTotal polling', details: err.message });
    }
});

// ==========================================
// 2. LIVE CYBER NEWS ENDPOINT
// ==========================================
app.get('/api/news', async (req, res) => {
    try {
        const category = req.query.category || 'ALL';
        let queryTerm = 'cybersecurity OR ransomware OR "data breach" OR "malware"';

        if (category !== 'ALL') {
            queryTerm = `cybersecurity AND "${category.toLowerCase()}"`;
        }

        const newsUrl = `https://gnews.io/api/v4/search?q=${encodeURIComponent(queryTerm)}&lang=en&max=9&sortby=publishedAt&apikey=${NEWS_API_KEY}`;

        const response = await fetch(newsUrl);
        const data = await response.json();

        if (!response.ok) {
            return res.status(response.status).json({
                error: data.errors ? data.articles : 'Failed to fetch from News Provider',
                status: response.status
            });
        }

        // Normalize response output structure
        const articles = (data.articles || []).map(a => ({
            title: a.title,
            description: a.description,
            url: a.url,
            source: a.source ? a.source.name : 'Cyber Intel',
            publishedAt: a.publishedAt,
            image: a.image,
            category: category === 'ALL' ? 'SECURITY' : category
        }));

        return res.json({ articles });
    } catch (err) {
        return res.status(500).json({ error: 'Failed to retrieve live cybersecurity news', details: err.message });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`=======================================================`);
    console.log(` CYBERGUARD AI Backend API active on port ${PORT}`);
    console.log(` VirusTotal & News API endpoints operational`);
    console.log(`=======================================================`);
});
