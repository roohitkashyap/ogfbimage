# FB Anti-Ban Link System v4 — Complete Documentation

## 🎯 Concept Kya Hai?

Facebook pe jab tu kisi website ka link share karta hai, toh FB us link ko scan karta hai. Agar FB ko lagta hai link spammy hai ya banned domain hai, toh wo link ki reach kill kar deta hai ya post block kar deta hai.

**Solution:** Apna ek middleman script banao jo:
1. FB crawler ko proper OG image + title + description dikhaye (tera server se)
2. Real visitor ko instantly original article pe redirect kare
3. Visitor ko pata bhi na chale ki beech mein koi script thi

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────┐
│                    ADMIN PANEL                       │
│  (terisite.com/go.php?admin=1)                      │
│                                                     │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │ Article URL  │  │ Upload Image │  │ Title/Desc│  │
│  └──────┬──────┘  └──────┬───────┘  └─────┬─────┘  │
│         └────────────────┼─────────────────┘        │
│                          ▼                           │
│              ┌───────────────────┐                   │
│              │  CREATE FB LINK   │                   │
│              └─────────┬─────────┘                   │
│                        ▼                             │
│         terisite.com/go.php?id=abc123                │
└─────────────────────────────────────────────────────┘

                         │
                         ▼

┌─────────────────────────────────────────────────────┐
│              FB PE LINK SHARE KARO                   │
│                                                     │
│  FB Crawler aata hai → User-Agent detect hota hai   │
│         │                          │                │
│    [CRAWLER]                  [REAL VISITOR]         │
│         │                          │                │
│         ▼                          ▼                │
│  OG Tags dikhao:            Instant Redirect:       │
│  - og:image (JPG)           - JS redirect           │
│  - og:title                 - Meta refresh           │
│  - og:description           - Fallback <a> link     │
│  - og:site_name                    │                │
│         │                          │                │
│         ▼                          ▼                │
│  FB Preview Card             Original Article       │
│  with YOUR image             (newshoxs.com/...)     │
└─────────────────────────────────────────────────────┘
```

---

## 📁 File Structure

```
cocolinks.in/
├── go.php              ← Main script (single file, sab kuch isme hai)
├── fb_images/          ← Auto-created folder, uploaded images JPG mein store hoti hain
│   ├── a1b2c3d4.jpg
│   ├── e5f6g7h8.jpg
│   └── ...
└── fb_data/            ← Auto-created folder, links ka JSON data
    └── links.json      ← Saare links ka database (JSON file)
```

---

## 📄 go.php — Single File Breakdown

### 1. CONFIG Section
```
ADMIN_PASSWORD  → Admin panel ka password (change karna zaroori hai)
DATA_DIR        → fb_data/ folder path (auto create hota hai)
IMAGE_DIR       → fb_images/ folder path (auto create hota hai)
LINKS_FILE      → fb_data/links.json path
MAX_IMAGE_SIZE  → 5MB max image upload limit
```

### 2. ROUTING — URL ke basis pe decide hota hai kya karna hai

| URL Pattern | Kya Hota Hai |
|---|---|
| `go.php?id=abc123` | Redirect handler — Crawler ko OG tags, visitor ko redirect |
| `go.php?img=abc123` | Image serve karta hai — JPG file directly |
| `go.php?admin=1` | Admin panel dikhata hai (login required) |
| `go.php?api=create` | New link create karta hai (POST request) |
| `go.php?api=delete` | Link delete karta hai |
| `go.php?api=list` | Saare links ki list return karta hai (JSON) |
| `go.php` (blank) | Admin pe redirect kar deta hai |

### 3. REDIRECT HANDLER — Core Logic

```
Step 1: URL se ID nikalo (go.php?id=abc123 → id = abc123)
Step 2: links.json se is ID ka data load karo
Step 3: Click count increment karo
Step 4: User-Agent check karo

IF User-Agent = Facebook Bot / Crawler:
    → HTML page return karo with OG meta tags
    → og:image = tere server ki JPG image
    → og:title = saved title
    → og:description = saved description
    → NO redirect (crawler ko page dikhana hai)

IF User-Agent = Real Visitor (normal browser):
    → Instant redirect via 3 methods:
       1. JavaScript: window.location.replace("original-url")
       2. Meta refresh: <meta http-equiv="refresh" content="0;url=...">
       3. Fallback: <a href="...">Click here</a>
    → Visitor seedha original article pe pahunch jaata hai
```

### 4. IMAGE SERVER

```
Step 1: URL se ID nikalo (go.php?img=abc123)
Step 2: fb_images/abc123.jpg file check karo
Step 3: Cache headers set karo (7 days cache)
Step 4: ETag based 304 Not Modified support
Step 5: JPG file serve karo

FB crawler jab og:image URL hit karta hai → ye JPG milti hai
```

### 5. API — Admin Panel ke liye

#### CREATE (POST go.php?api=create)
```
Input:
  - url (required) → Article ka original URL
  - image (required) → Image file upload
  - title (optional) → Custom title, empty = auto-fetch from URL
  - desc (optional) → Custom description
  - site_name (optional) → Site name

Process:
  1. URL validate karo
  2. Image upload check karo (max 5MB, valid image type)
  3. Unique 8-char ID generate karo (random hex)
  4. Image ko JPG mein convert karo (GD library se)
     - WebP → JPG ✅
     - PNG → JPG ✅
     - GIF → JPG ✅
     - Transparency → White background
     - Width > 1200px → Resize to 1200px
  5. JPG save karo: fb_images/{id}.jpg
  6. Agar title/desc empty hai → URL se OG tags fetch karo
  7. links.json mein data save karo
  8. Generated link return karo

Output:
  - go_url: go.php?id=abc123
  - img_url: go.php?img=abc123
  - title, desc
```

#### DELETE (POST go.php?api=delete)
```
Input: id
Process: links.json se remove + JPG file delete
```

#### LIST (GET go.php?api=list)
```
Output: Saare links ka array with click counts
```

### 6. HELPER FUNCTIONS

| Function | Kya Karta Hai |
|---|---|
| `convertAndSave()` | Image ko JPG mein convert + resize + save |
| `fetchOGFromUrl()` | URL se OG title/description fetch karta hai |
| `fetchUrl()` | cURL ya file_get_contents se page download |
| `getMeta()` | HTML se meta tag content extract |
| `generateId()` | 8-char random hex ID |
| `sanitizeId()` | ID se special characters remove |
| `loadLinks()` | links.json read |
| `saveLinks()` | links.json write |
| `getBaseUrl()` | Current script ka full URL |

### 7. ADMIN PANEL UI

Login page → Password check → Session based auth

Admin panel features:
- URL input field
- Drag & drop image upload zone
- Title, Description, Site Name fields (optional)
- "Create FB Link" button
- Generated link with copy button
- All links list with:
  - Thumbnail preview
  - Link ID
  - Click count
  - Created date
  - Copy / Test / Delete buttons

---

## 🔧 Hosting Setup Guide

### Step 1: Upload
```
1. go.php file ko hosting pe upload karo
   - Root: cocolinks.in/go.php
   - Ya subfolder: cocolinks.in/fb/go.php
```

### Step 2: Password Change
```php
// go.php line 20 pe ye change karo:
define('ADMIN_PASSWORD', 'tera_strong_password');
```

### Step 3: Permissions
```
Script automatically 2 folders create karega:
- fb_data/    (links.json store hota hai)
- fb_images/  (JPG images store hoti hain)

Agar auto-create fail ho toh manually bana ke 755 permission do:
mkdir fb_data fb_images
chmod 755 fb_data fb_images
```

### Step 4: PHP Requirements
```
- PHP 7.4+ (8.x recommended)
- GD Library enabled (image conversion ke liye) — 99% hosts pe already hai
- cURL extension (OG data fetch ke liye) — 99% hosts pe already hai
- JSON extension (data storage ke liye) — PHP mein built-in hai
```

### Step 5: Test
```
1. Browser: cocolinks.in/go.php?admin=1
2. Login with password
3. Paste any URL + upload image
4. "Create FB Link" click karo
5. Generated link copy karo
6. FB pe paste karo → image dikhni chahiye
```

---

## 🔄 Complete User Flow

### Admin Side:
```
1. go.php?admin=1 open karo
2. Login karo
3. Article URL paste karo: https://newshoxs.com/us-oil-tanker-seizure/
4. Image upload karo (article ka screenshot ya thumbnail)
5. Title/Desc optional hai — blank chhodo toh auto-fetch hoga
6. "Create FB Link ⚡" click karo
7. Generated link copy karo: cocolinks.in/go.php?id=a1b2c3d4
```

### Facebook Side:
```
1. FB pe new post banao
2. Generated link paste karo
3. FB crawler hit karega → teri image + title dikhega preview mein
4. Post publish karo
```

### Visitor Side:
```
1. Visitor FB pe post dekhta hai → teri uploaded image dikhti hai
2. Image/link pe click karta hai
3. go.php?id=a1b2c3d4 open hota hai
4. Script detect karti hai — ye real visitor hai (bot nahi)
5. JavaScript se instant redirect hota hai
6. Visitor seedha newshoxs.com/us-oil-tanker-seizure/ pe pahunch jaata hai
7. Visitor ko pata bhi nahi chala ki beech mein koi script thi
8. Admin panel mein click count +1 ho jaata hai
```

---

## 🛡️ Anti-Ban Kaise Kaam Karta Hai

| Problem | Solution |
|---|---|
| FB blocks certain domains | Link tera domain hai (cocolinks.in) — FB ko trust hai |
| FB rejects WebP images | Script automatically JPG mein convert karti hai |
| FB OG fetch fails | Image tera server pe stored hai — always accessible |
| Link looks suspicious | Clean URL: `go.php?id=abc123` — nothing suspicious |
| FB throttles external images | Image cocolinks.in se serve hoti hai with proper cache headers |

---

## 📊 links.json Data Structure

```json
{
    "a1b2c3d4": {
        "id": "a1b2c3d4",
        "url": "https://newshoxs.com/us-oil-tanker-seizure/",
        "title": "US Oil Tanker Seized by Iran in Strait of Hormuz",
        "desc": "Iran's Revolutionary Guard seized a US-flagged oil tanker...",
        "site_name": "NewsHoxs",
        "created": "2026-02-24 15:30:00",
        "updated": 1740412200,
        "clicks": 47,
        "last_click": "2026-02-24 18:45:12"
    }
}
```

---

## 🐛 Troubleshooting

| Issue | Fix |
|---|---|
| Image upload fail | Check GD library: `php -m \| grep gd` |
| Folders not created | Manually create fb_data/ and fb_images/ with 755 |
| FB preview not showing | Use FB Sharing Debugger: developers.facebook.com/tools/debug/ |
| FB showing old image | Debugger pe "Scrape Again" click karo |
| 404 on image URL | Check fb_images/ folder has the .jpg file |
| Login not working | Clear browser cookies, check password in config |
| Redirect not working | Check URL format in links.json |
| Click count not updating | Check fb_data/ folder is writable |

---

## 🔗 FB Sharing Debugger

Link create karne ke baad, FB cache refresh karne ke liye:

```
1. https://developers.facebook.com/tools/debug/ open karo
2. Apna generated link paste karo: cocolinks.in/go.php?id=abc123
3. "Debug" click karo
4. "Scrape Again" click karo
5. Preview dikhega with teri image
6. Ab FB pe share karo — image aayegi
```

---

## ⚡ Quick Reference

```
Admin Panel:    cocolinks.in/go.php?admin=1
Generated Link: cocolinks.in/go.php?id={8-char-id}
Image URL:      cocolinks.in/go.php?img={8-char-id}
API Create:     POST go.php?api=create  (url + image file + title + desc + site_name)
API Delete:     POST go.php?api=delete  (id)
API List:       GET  go.php?api=list
```
