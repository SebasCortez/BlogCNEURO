// --- START OF FILE server.js ---
// -----------------------------------------------------------------------------
// server.js - Blog CNEURO Backend con Autenticación y CRUD (Artículos + Casos + Noticias + Revisiones)
// -----------------------------------------------------------------------------

const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Constantes de Rutas ---
const POSTS_FILE = path.join(__dirname, 'posts.json'); // Para Artículos
const CASES_FILE = path.join(__dirname, 'cases.json'); // Para Casos Clínicos
const NEWS_FILE = path.join(__dirname, 'news.json');   // Para Noticias
const REVISIONS_FILE = path.join(__dirname, 'revisiones.json'); // Para Revisiones Médicas
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const PUBLIC_DIR = path.join(__dirname, 'public');
const PRIVATE_DIR = path.join(__dirname, 'private');

// --- Configuración de Seguridad (¡IMPORTANTE!) ---
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
// Contraseña por defecto 'admin' (hash bcrypt). ¡CAMBIAR EN PRODUCCIÓN!
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '$2b$10$vvm.ZggYIhTkKsEXq2hWxeisHrG6l2sHZ5Deq9cKrjHdSEzFQZXb2';
const SESSION_SECRET = process.env.SESSION_SECRET || 'administradorcneuro'; // ¡CAMBIAR EN PRODUCCIÓN!

if (ADMIN_PASSWORD_HASH === '$2b$10$CAMBIAESTOXD') { // Ajusta si cambiaste el hash por defecto
    console.warn('\x1b[31m%s\x1b[0m', 'CRITICAL WARNING: Using default admin p  assword hash! Generate a new one with "npm run generate-hash" and set ADMIN_PASSWORD_HASH environment variable.');
}
if (SESSION_SECRET === 'adminCAMBIAESTOTAMBIENXD') { // Ajusta si cambiaste el secret por defecto
    console.warn('\x1b[33m%s\x1b[0m', 'WARNING: Using default session SECRET! Set SESSION_SECRET environment variable to a long random string.');
}

// --- Configuración de Multer ---
fs.mkdir(UPLOADS_DIR, { recursive: true }).catch(err => { if (err.code !== 'EEXIST') console.error("Error creating uploads dir:", err); });
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const fileFilter = (req, file, cb) => {
    // Permitir PDF o Imágenes JPG/PNG/GIF/WEBP dependiendo del campo
    if ((file.fieldname === 'pdfFile' && file.mimetype === 'application/pdf') ||
        (file.fieldname === 'imageFile' && ['image/jpeg', 'image/png', 'image/gif', 'image/webp'].includes(file.mimetype))) { // Ampliado tipos de imagen
        cb(null, true);
    } else {
        cb(new Error('Tipo de archivo no permitido (solo PDF para pdfFile, o JPG/PNG/GIF/WEBP para imageFile)'), false);
    }
};
const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: { fileSize: 15 * 1024 * 1024 } // Límite de 15MB
});

// Middleware Multer adaptado
const handleMulterUpload = (req, res, next) => {
    const uploader = upload.fields([{ name: 'pdfFile', maxCount: 1 }, { name: 'imageFile', maxCount: 1 }]);
    uploader(req, res, err => {
        if (err instanceof multer.MulterError) {
            // Ignorar error si el campo no existe (puede ser para noticias o revisiones sin imagen)
            if (err.code === 'LIMIT_UNEXPECTED_FILE') {
                 console.warn("Multer warning: Unexpected file field received, ignoring.");
                 next();
                 return;
            }
            console.error("Multer Error:", err);
            return res.status(400).json({ message: `Error de subida (${err.code}): ${err.message}` });
        }
        if (err) {
             console.error("File Processing Error:", err);
             // Devolver el mensaje específico del filtro de archivos
             if (err.message.includes('Tipo de archivo no permitido')) {
                 return res.status(400).json({ message: err.message });
             }
             return res.status(400).json({ message: err.message || 'Error procesando archivo.' });
        }
        next();
    });
};

// --- Middlewares Generales ---
app.use(express.static(PUBLIC_DIR)); // Servir archivos estáticos (HTML, CSS, JS del cliente)
app.use('/uploads', express.static(UPLOADS_DIR)); // Servir archivos subidos
app.use(express.urlencoded({ extended: true })); // Para parsear datos de formularios URL-encoded
app.use(express.json()); // Para parsear JSON en el body de las requests

// --- Configuración de Sesión ---
app.use(session({
    secret: SESSION_SECRET,
    resave: false, // No guardar la sesión si no se modificó
    saveUninitialized: false, // No crear sesión hasta que algo se guarde
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Usar cookies seguras (HTTPS) en producción
        httpOnly: true, // Prevenir acceso JS a la cookie
        maxAge: 1000 * 60 * 60 * 4 // Duración de la cookie: 4 horas
    }
}));

// --- Middleware de Autenticación ---
function isAuthenticated(req, res, next) {
    if (req.session && req.session.isAdmin) {
        return next(); // Usuario autenticado, continuar
    }
    // No autenticado
    console.warn('Access denied: Authentication required for', req.originalUrl);
    // Adaptar respuesta según si la petición es para API o página
    if (req.originalUrl.startsWith('/api/admin/')) {
        return res.status(401).json({ message: 'No autorizado. Se requiere acceso de administrador.' });
    }
    // Para otras rutas protegidas (como admin.html directo)
    res.redirect('/login.html');
}

// --- Funciones Auxiliares ---

// Funciones para Artículos (posts.json)
async function readPosts() {
    try {
        const data = await fs.readFile(POSTS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            console.log('posts.json not found, returning empty array.');
            return []; // Si no existe el archivo, empezar con array vacío
        }
        console.error("Error reading posts.json:", error);
        throw new Error('Error al leer datos de artículos.');
    }
}
async function writePosts(posts) {
    try {
        await fs.writeFile(POSTS_FILE, JSON.stringify(posts, null, 2), 'utf8');
        console.log('DEBUG: posts.json successfully written.');
    } catch (error) {
        console.error("Error writing posts.json:", error);
        throw new Error('Error al guardar datos de artículos.');
    }
}

// Funciones para Casos Clínicos (cases.json)
async function readCases() {
    try {
        const data = await fs.readFile(CASES_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            console.log('cases.json not found, returning empty array.');
            return [];
        }
        console.error("Error reading cases.json:", error);
        throw new Error('Error al leer datos de casos clínicos.');
    }
}
async function writeCases(cases) {
    try {
        await fs.writeFile(CASES_FILE, JSON.stringify(cases, null, 2), 'utf8');
        console.log('DEBUG: cases.json successfully written.');
    } catch (error) {
        console.error("Error writing cases.json:", error);
        throw new Error('Error al guardar datos de casos clínicos.');
    }
}

// Funciones para Noticias (news.json)
async function readNews() {
    try {
        const data = await fs.readFile(NEWS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            console.log('news.json not found, returning empty array.');
            return [];
        }
        console.error("Err reading news.json:", error);
        throw new Error('Error al leer datos de noticias.');
    }
}
async function writeNews(newsItems) {
    try {
        await fs.writeFile(NEWS_FILE, JSON.stringify(newsItems, null, 2), 'utf8');
        console.log('DEBUG: news.json successfully written.');
    } catch (error) {
        console.error("Err writing news.json:", error);
        throw new Error('Error al guardar datos de noticias.');
    }
}

// **** NUEVAS FUNCIONES PARA REVISIONES (revisiones.json) ****
async function readRevisions() {
    try {
        const data = await fs.readFile(REVISIONS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            console.log('revisiones.json not found, returning empty array.');
            return [];
        }
        console.error("Error reading revisiones.json:", error);
        throw new Error('Error al leer datos de revisiones médicas.');
    }
}
async function writeRevisions(revisions) {
    try {
        await fs.writeFile(REVISIONS_FILE, JSON.stringify(revisions, null, 2), 'utf8');
        console.log('DEBUG: revisiones.json successfully written.');
    } catch (error) {
        console.error("Error writing revisiones.json:", error);
        throw new Error('Error al guardar datos de revisiones médicas.');
    }
}
// *********************************************************


// Función genérica para borrar archivos subidos
async function deleteFileIfExists(filename) {
    if (!filename) return; // Si no hay nombre de archivo, no hacer nada

    // Medida de seguridad básica contra path traversal
    const safeFilename = path.basename(filename);
    if (safeFilename !== filename || safeFilename === '.' || safeFilename === '..') {
         console.warn(`Intento de borrado de archivo inválido bloqueado: ${filename}`);
         return;
    }

    const absolutePath = path.join(UPLOADS_DIR, safeFilename);
    try {
        await fs.access(absolutePath); // Verificar si existe primero
        await fs.unlink(absolutePath);
        console.log(`Archivo eliminado: ${safeFilename}`);
    } catch (err) {
        // No loguear error si el archivo simplemente no existe (ENOENT)
        if (err.code !== 'ENOENT') {
            console.error(`Error al intentar eliminar ${safeFilename}:`, err);
        } else {
             console.log(`Archivo ${safeFilename} no encontrado para eliminar (puede que ya se haya borrado).`);
        }
    }
}

// --- Rutas Públicas ---

// GET /api/articles (Lista pública de artículos)
app.get('/api/articles', async (req, res) => {
    try {
        const posts = await readPosts();
        posts.sort((a, b) => new Date(b.publish_date) - new Date(a.publish_date)); // Más recientes primero
        // Mapear solo los campos necesarios para la lista pública
        const publicList = posts.map(p => ({
            id: p.id,
            category: p.category,
            title: p.title,
            excerpt: p.excerpt,
            image_url: p.image_url,
            author: p.author,
            publish_date: p.publish_date
        }));
        res.json(publicList);
    } catch (e) {
        console.error("GET /api/articles Error:", e);
        res.status(500).json({ message: e.message || 'Error al obtener artículos' });
    }
});

// GET /api/articles/:id (Artículo específico)
app.get('/api/articles/:id', async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (isNaN(id)) {
            return res.status(400).json({ message: 'ID de artículo inválido' });
        }
        const posts = await readPosts();
        const post = posts.find(p => p.id === id);
        if (post) {
            res.json(post); // Devuelve el objeto completo del artículo
        } else {
            res.status(404).json({ message: 'Artículo no encontrado' });
        }
    } catch (e) {
        console.error(`GET /api/articles/${req.params.id} Error:`, e);
        res.status(500).json({ message: e.message || 'Error al obtener el artículo' });
    }
});

// GET /api/cases (Lista pública de casos clínicos)
app.get('/api/cases', async (req, res) => {
    try {
        const cases = await readCases();
        cases.sort((a, b) => new Date(b.publish_date) - new Date(a.publish_date)); // Más recientes primero
        // Mapear solo los campos necesarios para la lista pública
        const publicList = cases.map(c => ({
            id: c.id,
            category: c.category,
            title: c.title,
            excerpt: c.excerpt,
            image_url: c.image_url,
            author: c.author,
            publish_date: c.publish_date
        }));
        res.json(publicList);
    } catch (e) {
        console.error("GET /api/cases Error:", e);
        res.status(500).json({ message: e.message || 'Error al obtener casos clínicos' });
    }
});

// GET /api/cases/:id (Caso clínico específico)
app.get('/api/cases/:id', async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (isNaN(id)) {
            return res.status(400).json({ message: 'ID de caso clínico inválido' });
        }
        const cases = await readCases();
        const caseData = cases.find(c => c.id === id);
        if (caseData) {
            res.json(caseData); // Devuelve el objeto completo del caso
        } else {
            res.status(404).json({ message: 'Caso clínico no encontrado' });
        }
    } catch (e) {
        console.error(`GET /api/cases/${req.params.id} Error:`, e);
        res.status(500).json({ message: e.message || 'Error al obtener el caso clínico' });
    }
});

// GET /api/news (Lista pública de noticias para el sidebar)
app.get('/api/news', async (req, res) => {
    try {
        const newsItems = await readNews();
        // Ordenar por fecha de publicación, más recientes primero
        newsItems.sort((a, b) => new Date(b.publish_date) - new Date(a.publish_date));
        // Mapear para asegurar que solo enviamos los campos necesarios/públicos si fuera necesario
        const publicNews = newsItems.map(item => ({
            id: item.id,
            title: item.title,
            content: item.content,
            image_url: item.image_url,
            link: item.link,
            publish_date: item.publish_date
        }));
        res.json(publicNews);
    } catch (e) {
        console.error("GET /api/news Error:", e);
        res.status(500).json({ message: e.message || 'Error al obtener noticias' });
    }
});


// **** NUEVAS RUTAS PÚBLICAS PARA REVISIONES ****
// GET /api/revisions (Lista pública de revisiones)
app.get('/api/revisions', async (req, res) => {
    try {
        const revisions = await readRevisions();
        revisions.sort((a, b) => new Date(b.publish_date) - new Date(a.publish_date)); // Más recientes primero
        // Mapear solo los campos necesarios para la lista pública
        const publicList = revisions.map(r => ({
            id: r.id,
            category: r.category,
            title: r.title,
            excerpt: r.excerpt,
            image_url: r.image_url, // Puede ser null
            author: r.author,
            publish_date: r.publish_date
        }));
        res.json(publicList);
    } catch (e) {
        console.error("GET /api/revisions Error:", e);
        res.status(500).json({ message: e.message || 'Error al obtener revisiones médicas' });
    }
});

// GET /api/revisions/:id (Revisión específica)
app.get('/api/revisions/:id', async (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (isNaN(id)) {
            return res.status(400).json({ message: 'ID de revisión inválido' });
        }
        const revisions = await readRevisions();
        const revision = revisions.find(r => r.id === id);
        if (revision) {
            res.json(revision); // Devuelve el objeto completo
        } else {
            res.status(404).json({ message: 'Revisión médica no encontrada' });
        }
    } catch (e) {
        console.error(`GET /api/revisions/${req.params.id} Error:`, e);
        res.status(500).json({ message: e.message || 'Error al obtener la revisión médica' });
    }
});
// ************************************************


// --- Rutas de Autenticación ---
// GET /login.html (servido por express.static)

// POST /login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        console.log('Login attempt failed: Missing username or password.');
        return res.redirect('/login.html?error=1'); // Error 1: Campos vacíos o incorrectos
    }

    if (ADMIN_PASSWORD_HASH === '$2b$10CAMBIAESTOXD' && process.env.NODE_ENV !== 'development') { // Ajusta si cambiaste el hash
         console.error('CRITICAL SECURITY ISSUE: Default password hash is being used for login attempt in non-dev environment.');
         // Considera no permitir el login en este caso o mostrar un error más grave
         return res.redirect('/login.html?error=2'); // Error 2: Configuración insegura
    }

    try {
        // Comparar el hash de la contraseña enviada con el hash almacenado
        const isMatch = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);

        if (username === ADMIN_USERNAME && isMatch) {
            // Credenciales correctas: Iniciar sesión
            req.session.isAdmin = true;
            req.session.username = username;
            console.log(`Login successful for user: ${username}`);

            // Guardar la sesión antes de redirigir (previene race conditions)
            req.session.save(err => {
                if (err) {
                    console.error("Session save error during login:", err);
                    return res.redirect('/login.html?error=3'); // Error 3: Error del servidor
                }
                res.redirect('/admin.html'); // Redirigir al panel de admin
            });
        } else {
            // Credenciales incorrectas
            console.log(`Login failed for user: ${username} (Incorrect username or password)`);
            res.redirect('/login.html?error=1'); // Error 1: Campos vacíos o incorrectos
        }
    } catch (e) {
        console.error("Login error (bcrypt compare or other):", e);
        res.redirect('/login.html?error=3'); // Error 3: Error del servidor
    }
});

// POST /logout
app.post('/logout', (req, res) => {
    if (req.session) {
        const user = req.session.username || 'UNKNOWN_USER';
        req.session.destroy(err => {
            if (err) {
                console.error(`Logout error for user ${user}:`, err);
                // A pesar del error, intentamos redirigir
                 return res.status(500).send("Error al cerrar sesión."); // Podrías redirigir igual
            }
            console.log(`Logout successful for user: ${user}`);
            // Limpiar la cookie del lado del cliente
            res.clearCookie('connect.sid'); // Asegúrate que el nombre de la cookie sea el correcto
            res.redirect('/'); // Redirigir a la página principal
        });
    } else {
        // Si no hay sesión, simplemente redirigir
        res.redirect('/');
    }
});

// --- Rutas Protegidas (Admin) ---

// GET /admin.html (Página principal del admin)
// Usa el middleware isAuthenticated para proteger esta ruta
app.get('/admin.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(PRIVATE_DIR, 'admin.html'));
});

// --- CRUD para Artículos (posts.json) ---

// POST /api/admin/articles (Añadir Artículo)
app.post('/api/admin/articles', isAuthenticated, handleMulterUpload, async (req, res) => {
    const files = req.files || {};
    const data = req.body;
    let pdfFilePath = files.pdfFile?.[0]?.filename; // path relativo a /uploads
    let imgFilePath = files.imageFile?.[0]?.filename; // path relativo a /uploads

    try {
        console.log(`User ${req.session.username} ADD article. Body:`, data, "Files:", files);
        // Validación específica para artículos
        if (!data.title || !data.excerpt || !data.category || !data.author || !data.full_content || !data.publish_date) {
            throw new Error('Faltan datos requeridos para el artículo (título, extracto, categoría, autor, contenido, fecha).');
        }

        // Validación Fecha Publicación (no pasada)
        const publishDate = new Date(data.publish_date + 'T00:00:00.000Z'); // Asegura UTC mediodía
        const today = new Date();
        today.setUTCHours(0, 0, 0, 0); // Poner al inicio del día UTC para comparar

        if (isNaN(publishDate.getTime())) { throw new Error('Fecha de publicación inválida.'); }
        if (publishDate < today) { throw new Error('La fecha de publicación no puede ser anterior a hoy.'); }

        // Validación y determinación de URL de Imagen
        let finalImageUrl = null;
        if (imgFilePath) { // Prioridad 1: Archivo subido
            finalImageUrl = `/uploads/${imgFilePath}`;
        } else if (data.image_url && data.image_url.trim()) { // Prioridad 2: URL externa
            try {
                const parsedUrl = new URL(data.image_url.trim());
                 if (!['http:', 'https:'].includes(parsedUrl.protocol)) throw new Error(); // Solo http/https
                 finalImageUrl = parsedUrl.toString();
            } catch {
                throw new Error('La URL de la imagen externa no es válida.');
            }
        } else {
             // Si no hay archivo ni URL válida, es un error para artículos
             throw new Error('Se requiere una imagen (subir archivo o proporcionar URL válida).');
        }


        const posts = await readPosts();
        const newPost = {
            id: Date.now(), // ID único simple basado en timestamp
            title: data.title.trim(),
            category: data.category,
            excerpt: data.excerpt.trim(),
            full_content: data.full_content.trim(), // Asume que el frontend sanitiza si es necesario
            image_url: finalImageUrl,
            author: data.author.trim(),
            publish_date: publishDate.toISOString(), // Guardar como ISO string
            pdf_url: pdfFilePath ? `/uploads/${pdfFilePath}` : null, // Ruta relativa al PDF
            last_updated_date: new Date().toISOString() // Fecha de creación/actualización
        };

        posts.push(newPost);
        await writePosts(posts);
        console.log(`Article ${newPost.id} created successfully by ${req.session.username}.`);
        res.status(201).json(newPost); // 201 Created

    } catch (e) {
        console.error(`Error ADD article by ${req.session.username}:`, e);
        // Si falla, intentar borrar los archivos que se hayan subido
        if (pdfFilePath) await deleteFileIfExists(pdfFilePath);
        if (imgFilePath) await deleteFileIfExists(imgFilePath);
        res.status(400).json({ message: e.message || 'Error interno al crear el artículo.' }); // 400 Bad Request
    }
});

// PUT /api/admin/articles/:id (Editar Artículo)
app.put('/api/admin/articles/:id', isAuthenticated, handleMulterUpload, async (req, res) => {
    const postId = parseInt(req.params.id, 10);
    const files = req.files || {};
    const data = req.body;
    let newPdfFile = files.pdfFile?.[0]?.filename;
    let newImgFile = files.imageFile?.[0]?.filename;
    let oldPdfToDelete = null;
    let oldImgToDelete = null;
    const removeCurrentPdf = data.removeCurrentPdf === 'true';
    const removeCurrentImage = data.removeCurrentImage === 'true';

    try {
        console.log(`User ${req.session.username} UPDATE article ${postId}. Body:`, data, "Files:", files, "RemovePDF:", removeCurrentPdf, "RemoveIMG:", removeCurrentImage);
        if (isNaN(postId)) { throw new Error('ID de artículo inválido'); }
        // Validar campos obligatorios básicos
        if (!data.title || !data.excerpt || !data.category || !data.author || !data.full_content) {
            throw new Error('Faltan datos requeridos para el artículo (título, extracto, categoría, autor, contenido).');
        }

        const posts = await readPosts();
        const postIndex = posts.findIndex(p => p.id === postId);
        if (postIndex === -1) {
            res.status(404); // Not Found
            throw new Error('Artículo no encontrado');
        }
        const originalPost = posts[postIndex];

        // --- Lógica de Imagen ---
        let finalImageUrl = originalPost.image_url; // Empezar con la URL original

        if (newImgFile) { // 1. Si se subió un archivo nuevo
            finalImageUrl = `/uploads/${newImgFile}`;
            // Marcar el antiguo para borrar SI era una subida previa
            if (originalPost.image_url && originalPost.image_url.startsWith('/uploads/')) {
                oldImgToDelete = path.basename(originalPost.image_url);
                 console.log(`DEBUG IMG: Marked old uploaded file for deletion (replaced by new upload): ${oldImgToDelete}`);
            }
             console.log(`DEBUG IMG: Using new uploaded image: ${finalImageUrl}`);
        } else if (removeCurrentImage) { // 2. Si se marcó para eliminar Y no se subió nuevo archivo
             finalImageUrl = null;
             // Marcar el antiguo para borrar SI era una subida previa
             if (originalPost.image_url && originalPost.image_url.startsWith('/uploads/')) {
                 oldImgToDelete = path.basename(originalPost.image_url);
                 console.log(`DEBUG IMG: Marked old uploaded file for deletion (explicit removal): ${oldImgToDelete}`);
             }
             console.log(`DEBUG IMG: Image explicitly removed.`);
             // ¡Validación importante! No se puede quedar sin imagen
             if (!data.image_url?.trim()) {
                 throw new Error('Si eliminas la imagen actual, debes proporcionar una nueva URL externa.');
             }
             // Si se proporcionó URL externa junto con la eliminación, se usará en el siguiente paso.
        }

        // 3. Si no se subió archivo nuevo NI se marcó para eliminar, verificar si la URL externa cambió
        if (!newImgFile && !removeCurrentImage && data.image_url !== originalPost.image_url) {
             if (data.image_url && data.image_url.trim()) { // Si se proporcionó una nueva URL externa
                 try {
                     const parsedUrl = new URL(data.image_url.trim());
                     if (!['http:', 'https:'].includes(parsedUrl.protocol)) throw new Error();
                     finalImageUrl = parsedUrl.toString();
                     console.log(`DEBUG IMG: Using new external URL: ${finalImageUrl}`);
                     // Marcar el antiguo para borrar SI era una subida previa
                     if (originalPost.image_url && originalPost.image_url.startsWith('/uploads/')) {
                         oldImgToDelete = path.basename(originalPost.image_url);
                         console.log(`DEBUG IMG: Marked old uploaded file for deletion (replaced by new URL): ${oldImgToDelete}`);
                     }
                 } catch { throw new Error('La URL de la imagen externa proporcionada no es válida.'); }
             } else if (originalPost.image_url) { // Si la URL externa se borró (quedó vacía)
                 finalImageUrl = null;
                 console.log(`DEBUG IMG: External URL removed.`);
                 // Marcar el antiguo para borrar SI era una subida previa
                 if (originalPost.image_url && originalPost.image_url.startsWith('/uploads/')) {
                     oldImgToDelete = path.basename(originalPost.image_url);
                     console.log(`DEBUG IMG: Marked old uploaded file for deletion (external URL removed): ${oldImgToDelete}`);
                 }
                  // ¡Validación importante! No se puede quedar sin imagen
                  if (!finalImageUrl) { // Si al final no hay imagen
                       throw new Error('El artículo debe tener una imagen (URL o archivo subido).');
                  }
             }
        }
        // Si se marcó para eliminar pero se proporcionó una URL externa, usar esa URL
        if (removeCurrentImage && data.image_url?.trim() && !newImgFile) {
              try {
                  const parsedUrl = new URL(data.image_url.trim());
                  if (!['http:', 'https:'].includes(parsedUrl.protocol)) throw new Error();
                  finalImageUrl = parsedUrl.toString();
                  console.log(`DEBUG IMG: Using new external URL provided alongside removal flag: ${finalImageUrl}`);
              } catch { throw new Error('La URL de la imagen externa proporcionada no es válida.'); }
        }

        // Validación final: debe haber una imagen para artículos
        if (!finalImageUrl) {
             throw new Error('El artículo debe tener una imagen. Proporciona una URL o sube un archivo.');
        }
         console.log(`DEBUG IMG: Final Image URL determined: ${finalImageUrl}`);
        // --- FIN Lógica Imagen ---


        // --- Lógica PDF ---
        let finalPdfUrl = originalPost.pdf_url; // Empezar con el PDF original

        if (newPdfFile) { // 1. Si se subió un nuevo PDF
            finalPdfUrl = `/uploads/${newPdfFile}`;
            // Marcar el antiguo para borrar SI existía y era una subida previa
            if (originalPost.pdf_url && originalPost.pdf_url.startsWith('/uploads/')) {
                oldPdfToDelete = path.basename(originalPost.pdf_url);
            }
        } else if (removeCurrentPdf) { // 2. Si se marcó para eliminar Y no se subió nuevo PDF
            finalPdfUrl = null;
            // Marcar el antiguo para borrar SI existía y era una subida previa
            if (originalPost.pdf_url && originalPost.pdf_url.startsWith('/uploads/')) {
                oldPdfToDelete = path.basename(originalPost.pdf_url);
            }
        }
        // 3. Si no se subió nuevo ni se marcó para eliminar, se mantiene el original (finalPdfUrl ya lo tiene)
         console.log(`DEBUG PDF: Final PDF URL determined: ${finalPdfUrl}`);
        // --- FIN Lógica PDF ---

        // Crear objeto actualizado
        const updatedPost = {
            ...originalPost, // Mantener id, publish_date original
            title: data.title.trim(),
            category: data.category,
            excerpt: data.excerpt.trim(),
            full_content: data.full_content.trim(),
            image_url: finalImageUrl, // Usar la URL de imagen final determinada
            author: data.author.trim(),
            pdf_url: finalPdfUrl, // Usar la URL de PDF final determinada
            last_updated_date: new Date().toISOString() // Actualizar fecha de modificación
        };

        // Reemplazar el post en el array
        posts[postIndex] = updatedPost;

        // Guardar el array actualizado en el archivo JSON
        await writePosts(posts);

        // Borrar archivos antiguos SI es necesario y SI son diferentes a los nuevos
        if (oldImgToDelete && oldImgToDelete !== newImgFile) {
             await deleteFileIfExists(oldImgToDelete);
        }
        if (oldPdfToDelete && oldPdfToDelete !== newPdfFile) {
             await deleteFileIfExists(oldPdfToDelete);
        }

        console.log(`Article ${postId} updated successfully by ${req.session.username}.`);
        res.status(200).json(updatedPost); // 200 OK

    } catch (error) {
        console.error(`Error UPDATE article ${postId} by ${req.session.username}:`, error);
        // Limpiar archivos nuevos subidos si la actualización falla
        if (newPdfFile) await deleteFileIfExists(newPdfFile);
        if (newImgFile) await deleteFileIfExists(newImgFile);

        const status = res.statusCode >= 400 ? res.statusCode : 400; // Usar 400 o el status ya establecido (404)
        res.status(status).json({ message: error.message || 'Error interno al actualizar el artículo.' });
    }
});

// DELETE /api/admin/articles/:id (Eliminar Artículo)
app.delete('/api/admin/articles/:id', isAuthenticated, async (req, res) => {
    const postId = parseInt(req.params.id, 10);
    try {
        if (isNaN(postId)) {
            throw new Error('ID de artículo inválido');
        }
        console.log(`User ${req.session.username} attempts DELETE article ${postId}`);

        const posts = await readPosts();
        const postIndex = posts.findIndex(p => p.id === postId);

        if (postIndex === -1) {
            res.status(404); // Not Found
            throw new Error('Artículo no encontrado para eliminar');
        }

        const postToDelete = posts[postIndex]; // Guardar referencia para borrar archivos

        // Eliminar el post del array
        posts.splice(postIndex, 1);

        // Guardar los cambios en posts.json
        await writePosts(posts);

        // Intentar borrar archivos asociados SI existen y son subidas locales
        if (postToDelete.image_url && postToDelete.image_url.startsWith('/uploads/')) {
            await deleteFileIfExists(path.basename(postToDelete.image_url));
        }
        if (postToDelete.pdf_url && postToDelete.pdf_url.startsWith('/uploads/')) {
            await deleteFileIfExists(path.basename(postToDelete.pdf_url));
        }

        console.log(`Article ${postId} deleted successfully by ${req.session.username}.`);
        res.status(200).json({ message: 'Artículo eliminado correctamente' }); // 200 OK

    } catch (e) {
        console.error(`Error DELETE article ${postId} by ${req.session.username}:`, e);
        const status = res.statusCode >= 400 ? res.statusCode : 500; // Usar 500 o el status ya establecido (404)
        res.status(status).json({ message: e.message || 'Error interno al eliminar el artículo.' });
    }
});


// --- CRUD para Casos Clínicos (cases.json) ---

// POST /api/admin/cases (Añadir Caso Clínico)
app.post('/api/admin/cases', isAuthenticated, handleMulterUpload, async (req, res) => {
    const files = req.files || {};
    const data = req.body;
    let pdfFilePath = files.pdfFile?.[0]?.filename;
    let imgFilePath = files.imageFile?.[0]?.filename;

    try {
        console.log(`User ${req.session.username} ADD case. Body:`, data, "Files:", files);
        // Validación específica para casos
        if (!data.title || !data.excerpt || !data.category || !data.author || !data.full_content || !data.publish_date) {
            throw new Error('Faltan datos requeridos para el caso clínico (título, extracto, categoría, autor, contenido, fecha).');
        }

        // Validación Fecha Publicación
        const publishDate = new Date(data.publish_date + 'T00:00:00.000Z');
        const today = new Date(); today.setUTCHours(0, 0, 0, 0);
        if (isNaN(publishDate.getTime())) { throw new Error('Fecha de publicación inválida.'); }
        if (publishDate < today) { throw new Error('La fecha de publicación no puede ser anterior a hoy.'); }

        // Validación y determinación de URL de Imagen (obligatoria para casos)
        let finalImageUrl = null;
        if (imgFilePath) {
            finalImageUrl = `/uploads/${imgFilePath}`;
        } else if (data.image_url && data.image_url.trim()) {
            try {
                const parsedUrl = new URL(data.image_url.trim());
                if (!['http:', 'https:'].includes(parsedUrl.protocol)) throw new Error();
                finalImageUrl = parsedUrl.toString();
            } catch { throw new Error('La URL de la imagen externa no es válida.'); }
        } else { throw new Error('Se requiere una imagen para el caso (subir archivo o proporcionar URL válida).'); }

        const cases = await readCases();
        const newCase = {
            id: Date.now() + 1, // ID único simple (distinto de posts si se crean al mismo tiempo)
            title: data.title.trim(),
            category: data.category,
            excerpt: data.excerpt.trim(),
            full_content: data.full_content.trim(),
            image_url: finalImageUrl,
            author: data.author.trim(),
            publish_date: publishDate.toISOString(),
            pdf_url: pdfFilePath ? `/uploads/${pdfFilePath}` : null,
            last_updated_date: new Date().toISOString()
        };

        cases.push(newCase);
        await writeCases(cases);
        console.log(`Case ${newCase.id} created successfully by ${req.session.username}.`);
        res.status(201).json(newCase);

    } catch (e) {
        console.error(`Error ADD case by ${req.session.username}:`, e);
        if (pdfFilePath) await deleteFileIfExists(pdfFilePath);
        if (imgFilePath) await deleteFileIfExists(imgFilePath);
        res.status(400).json({ message: e.message || 'Error interno al crear el caso clínico.' });
    }
});

// PUT /api/admin/cases/:id (Editar Caso Clínico)
app.put('/api/admin/cases/:id', isAuthenticated, handleMulterUpload, async (req, res) => {
    const caseId = parseInt(req.params.id, 10);
    const files = req.files || {};
    const data = req.body;
    let newPdfFile = files.pdfFile?.[0]?.filename;
    let newImgFile = files.imageFile?.[0]?.filename;
    let oldPdfToDelete = null;
    let oldImgToDelete = null;
    const removeCurrentPdf = data.removeCurrentPdf === 'true';
    const removeCurrentImage = data.removeCurrentImage === 'true';

    try {
        console.log(`User ${req.session.username} UPDATE case ${caseId}. Body:`, data, "Files:", files, "RemovePDF:", removeCurrentPdf, "RemoveIMG:", removeCurrentImage);
        if (isNaN(caseId)) { throw new Error('ID de caso clínico inválido'); }
        if (!data.title || !data.excerpt || !data.category || !data.author || !data.full_content) {
            throw new Error('Faltan datos requeridos para el caso clínico (título, extracto, categoría, autor, contenido).');
        }

        const cases = await readCases();
        const caseIndex = cases.findIndex(c => c.id === caseId);
        if (caseIndex === -1) {
            res.status(404); throw new Error('Caso clínico no encontrado');
        }
        const originalCase = cases[caseIndex];

        // --- Lógica de Imagen (Idéntica a la de Artículos - Obligatoria) ---
         let finalImageUrl = originalCase.image_url;
         if (newImgFile) {
             finalImageUrl = `/uploads/${newImgFile}`;
             if (originalCase.image_url?.startsWith('/uploads/')) { oldImgToDelete = path.basename(originalCase.image_url); }
         } else if (removeCurrentImage) {
             finalImageUrl = null;
             if (originalCase.image_url?.startsWith('/uploads/')) { oldImgToDelete = path.basename(originalCase.image_url); }
             if (!data.image_url?.trim()) { throw new Error('Si eliminas la imagen actual, debes proporcionar una nueva URL externa.'); }
             // URL externa se gestiona después
         }
         if (!newImgFile && !removeCurrentImage && data.image_url !== originalCase.image_url) {
             if (data.image_url?.trim()) {
                 try {
                     const parsedUrl = new URL(data.image_url.trim());
                     if (!['http:', 'https:'].includes(parsedUrl.protocol)) throw new Error();
                     finalImageUrl = parsedUrl.toString();
                     if (originalCase.image_url?.startsWith('/uploads/')) { oldImgToDelete = path.basename(originalCase.image_url); }
                 } catch { throw new Error('La URL de la imagen externa proporcionada no es válida.'); }
             } else if (originalCase.image_url) { // URL se borró
                 finalImageUrl = null;
                 if (originalCase.image_url?.startsWith('/uploads/')) { oldImgToDelete = path.basename(originalCase.image_url); }
             }
         }
        // Si se marcó eliminar pero se dio URL externa
        if (removeCurrentImage && data.image_url?.trim() && !newImgFile) {
              try {
                  const parsedUrl = new URL(data.image_url.trim());
                  if (!['http:', 'https:'].includes(parsedUrl.protocol)) throw new Error();
                  finalImageUrl = parsedUrl.toString();
              } catch { throw new Error('La URL de la imagen externa proporcionada no es válida.'); }
        }
         // Validación final para casos (imagen obligatoria)
         if (!finalImageUrl) { throw new Error('El caso clínico debe tener una imagen.'); }
         console.log(`DEBUG CASE IMG: Final Image URL determined: ${finalImageUrl}`);
        // --- FIN Lógica Imagen ---

        // --- Lógica PDF (Idéntica a la de Artículos) ---
        let finalPdfUrl = originalCase.pdf_url;
        if (newPdfFile) {
            finalPdfUrl = `/uploads/${newPdfFile}`;
            if (originalCase.pdf_url?.startsWith('/uploads/')) { oldPdfToDelete = path.basename(originalCase.pdf_url); }
        } else if (removeCurrentPdf) {
            finalPdfUrl = null;
            if (originalCase.pdf_url?.startsWith('/uploads/')) { oldPdfToDelete = path.basename(originalCase.pdf_url); }
        }
         console.log(`DEBUG CASE PDF: Final PDF URL determined: ${finalPdfUrl}`);
        // --- FIN Lógica PDF ---

        const updatedCase = {
            ...originalCase,
            title: data.title.trim(),
            category: data.category,
            excerpt: data.excerpt.trim(),
            full_content: data.full_content.trim(),
            image_url: finalImageUrl,
            author: data.author.trim(),
            pdf_url: finalPdfUrl,
            last_updated_date: new Date().toISOString()
        };
        cases[caseIndex] = updatedCase;

        await writeCases(cases);

        if (oldImgToDelete && oldImgToDelete !== newImgFile) await deleteFileIfExists(oldImgToDelete);
        if (oldPdfToDelete && oldPdfToDelete !== newPdfFile) await deleteFileIfExists(oldPdfToDelete);

        console.log(`Case ${caseId} updated successfully by ${req.session.username}.`);
        res.status(200).json(updatedCase);

    } catch (error) {
        console.error(`Error UPDATE case ${caseId} by ${req.session.username}:`, error);
        if (newPdfFile) await deleteFileIfExists(newPdfFile);
        if (newImgFile) await deleteFileIfExists(newImgFile);
        const status = res.statusCode >= 400 ? res.statusCode : 400;
        res.status(status).json({ message: error.message || 'Error interno al actualizar el caso clínico.' });
    }
});

// DELETE /api/admin/cases/:id (Eliminar Caso Clínico)
app.delete('/api/admin/cases/:id', isAuthenticated, async (req, res) => {
    const caseId = parseInt(req.params.id, 10);
    try {
        if (isNaN(caseId)) { throw new Error('ID de caso clínico inválido'); }
        console.log(`User ${req.session.username} attempts DELETE case ${caseId}`);

        const cases = await readCases();
        const caseIndex = cases.findIndex(c => c.id === caseId);
        if (caseIndex === -1) {
            res.status(404); throw new Error('Caso clínico no encontrado para eliminar');
        }
        const caseToDelete = cases[caseIndex];

        cases.splice(caseIndex, 1);
        await writeCases(cases);

        if (caseToDelete.image_url?.startsWith('/uploads/')) await deleteFileIfExists(path.basename(caseToDelete.image_url));
        if (caseToDelete.pdf_url?.startsWith('/uploads/')) await deleteFileIfExists(path.basename(caseToDelete.pdf_url));

        console.log(`Case ${caseId} deleted successfully by ${req.session.username}.`);
        res.status(200).json({ message: 'Caso clínico eliminado correctamente' });
    } catch (e) {
        console.error(`Error DELETE case ${caseId} by ${req.session.username}:`, e);
        const status = res.statusCode >= 400 ? res.statusCode : 500;
        res.status(status).json({ message: e.message || 'Error interno al eliminar el caso clínico.' });
    }
});


// --- CRUD para Noticias (news.json) ---

// GET /api/admin/news (Obtener todas las noticias para el admin)
app.get('/api/admin/news', isAuthenticated, async (req, res) => {
    try {
        const newsItems = await readNews();
        // Ordenar por fecha de publicación descendente para mostrar en admin
        newsItems.sort((a, b) => new Date(b.publish_date) - new Date(a.publish_date));
        res.json(newsItems);
    } catch (e) {
        console.error(`GET /api/admin/news Error by ${req.session.username}:`, e);
        res.status(500).json({ message: e.message || 'Error al obtener noticias para admin' });
    }
});


// POST /api/admin/news (Añadir Noticia)
app.post('/api/admin/news', isAuthenticated, async (req, res) => { // No necesita handleMulterUpload
    const data = req.body;
    try {
        console.log(`User ${req.session.username} ADD news. Body:`, data);
        // Validación básica para noticias
        if (!data.title || !data.content) {
            throw new Error('Faltan datos requeridos (título, contenido) para la noticia.');
        }

        // Validar URL de imagen si se proporciona
        let imgUrl = data.image_url ? data.image_url.trim() : null;
        if (imgUrl) {
            try {
                const parsedUrl = new URL(imgUrl);
                if (!['http:', 'https:'].includes(parsedUrl.protocol)) throw new Error();
            } catch { throw new Error('URL de imagen inválida. Debe ser una URL completa http o https.'); }
        }

        // Validar enlace si se proporciona
        let linkUrl = data.link ? data.link.trim() : null;
        if (linkUrl && !linkUrl.startsWith('/') && !linkUrl.startsWith('http')) {
             try {
                 new URL(linkUrl); // Permitir URLs absolutas
             } catch {
                 throw new Error('El enlace debe ser una ruta relativa (empezando con /) o una URL completa (http/https).');
             }
        }


        const newsItems = await readNews();
        const newNewsItem = {
            id: Date.now() + 2, // ID único simple (distinto de posts/cases)
            title: data.title.trim(),
            content: data.content.trim(),
            image_url: imgUrl,
            link: linkUrl,
            publish_date: new Date().toISOString(), // Fecha de creación/publicación
            last_updated_date: new Date().toISOString()
        };
        newsItems.push(newNewsItem);
        await writeNews(newsItems);
        console.log(`News ${newNewsItem.id} created successfully by ${req.session.username}.`);
        res.status(201).json(newNewsItem);
    } catch (e) {
        console.error(`Error ADD news by ${req.session.username}:`, e.message);
        res.status(400).json({ message: e.message || 'Error interno al crear la noticia.' });
    }
});

// PUT /api/admin/news/:id (Editar Noticia)
app.put('/api/admin/news/:id', isAuthenticated, async (req, res) => { // No necesita handleMulterUpload
    const newsId = parseInt(req.params.id, 10);
    const data = req.body;
    try {
        console.log(`User ${req.session.username} UPDATE news ${newsId}. Body:`, data);
        if (isNaN(newsId)) { throw new Error('ID de noticia inválido'); }
        if (!data.title || !data.content) { throw new Error('Faltan datos requeridos (título, contenido) para la noticia'); }

        // Validar URL de imagen si se proporciona
        let imgUrl = data.image_url ? data.image_url.trim() : null;
        if (imgUrl) {
            try {
                 const parsedUrl = new URL(imgUrl);
                 if (!['http:', 'https:'].includes(parsedUrl.protocol)) throw new Error();
            } catch { throw new Error('URL de imagen inválida. Debe ser una URL completa http o https.'); }
        }

        // Validar enlace si se proporciona
        let linkUrl = data.link ? data.link.trim() : null;
         if (linkUrl && !linkUrl.startsWith('/') && !linkUrl.startsWith('http')) {
             try { new URL(linkUrl); } catch {
                 throw new Error('El enlace debe ser una ruta relativa (empezando con /) o una URL completa (http/https).');
             }
         }

        const newsItems = await readNews();
        const newsIdx = newsItems.findIndex(n => n.id === newsId);
        if (newsIdx === -1) {
            res.status(404); throw new Error('Noticia no encontrada');
        }

        const original = newsItems[newsIdx];
        const updated = {
            ...original, // Mantener id, publish_date original
            title: data.title.trim(),
            content: data.content.trim(),
            image_url: imgUrl,
            link: linkUrl,
            last_updated_date: new Date().toISOString() // Actualizar fecha de modificación
        };
        newsItems[newsIdx] = updated;
        await writeNews(newsItems);
        console.log(`News ${newsId} updated successfully by ${req.session.username}.`);
        res.status(200).json(updated);

    } catch (error) {
        console.error(`Error UPDATE news ${newsId} by ${req.session.username}:`, error.message);
        const status = res.statusCode >= 400 ? res.statusCode : 400;
        res.status(status).json({ message: error.message || 'Error interno al actualizar la noticia.' });
    }
});

// DELETE /api/admin/news/:id (Eliminar Noticia)
app.delete('/api/admin/news/:id', isAuthenticated, async (req, res) => {
    const newsId = parseInt(req.params.id, 10);
    try {
        if (isNaN(newsId)) { throw new Error('ID de noticia inválido'); }
        console.log(`User ${req.session.username} attempts DELETE news ${newsId}`);

        const newsItems = await readNews();
        const initialLength = newsItems.length;
        const filteredNews = newsItems.filter(n => n.id !== newsId);

        if (filteredNews.length === initialLength) {
            res.status(404); throw new Error('Noticia no encontrada para eliminar');
        }

        await writeNews(filteredNews);
        console.log(`News ${newsId} deleted successfully by ${req.session.username}.`);
        res.status(200).json({ message: 'Noticia eliminada correctamente' });
    } catch (e) {
        console.error(`Error DELETE news ${newsId} by ${req.session.username}:`, e.message);
        const status = res.statusCode >= 400 ? res.statusCode : 500;
        res.status(status).json({ message: e.message || 'Error interno al eliminar la noticia.' });
    }
});


// **** NUEVO CRUD PARA REVISIONES (revisiones.json) ****

// GET /api/admin/revisions (Obtener todas las revisiones para el admin)
app.get('/api/admin/revisions', isAuthenticated, async (req, res) => {
    try {
        const revisions = await readRevisions();
        revisions.sort((a, b) => new Date(b.publish_date) - new Date(a.publish_date));
        res.json(revisions);
    } catch (e) {
        console.error(`GET /api/admin/revisions Error by ${req.session.username}:`, e);
        res.status(500).json({ message: e.message || 'Error al obtener revisiones para admin' });
    }
});

// POST /api/admin/revisions (Añadir Revisión)
app.post('/api/admin/revisions', isAuthenticated, handleMulterUpload, async (req, res) => {
    const files = req.files || {};
    const data = req.body;
    let pdfFilePath = files.pdfFile?.[0]?.filename;
    let imgFilePath = files.imageFile?.[0]?.filename; // Imagen puede ser opcional para revisiones

    try {
        console.log(`User ${req.session.username} ADD revision. Body:`, data, "Files:", files);
        // Validación específica para revisiones
        if (!data.title || !data.excerpt || !data.category || !data.author || !data.full_content || !data.publish_date) {
            throw new Error('Faltan datos requeridos para la revisión (título, extracto, categoría, autor, contenido, fecha).');
        }

        // Validación Fecha Publicación
        const publishDate = new Date(data.publish_date + 'T00:00:00.000Z');
        const today = new Date(); today.setUTCHours(0, 0, 0, 0);
        if (isNaN(publishDate.getTime())) { throw new Error('Fecha de publicación inválida.'); }
        if (publishDate < today) { throw new Error('La fecha de publicación no puede ser anterior a hoy.'); }

        // Validación y determinación de URL de Imagen (puede ser null)
        let finalImageUrl = null;
        if (imgFilePath) {
            finalImageUrl = `/uploads/${imgFilePath}`;
        } else if (data.image_url && data.image_url.trim()) {
            try {
                const parsedUrl = new URL(data.image_url.trim());
                if (!['http:', 'https:'].includes(parsedUrl.protocol)) throw new Error();
                finalImageUrl = parsedUrl.toString();
            } catch { throw new Error('La URL de la imagen externa no es válida.'); }
        } // Si no hay ni archivo ni URL, finalImageUrl se queda en null (permitido)

        const revisions = await readRevisions();
        const newRevision = {
            id: Date.now() + 3, // ID único simple (diferente de otros tipos)
            title: data.title.trim(),
            category: data.category,
            excerpt: data.excerpt.trim(),
            full_content: data.full_content.trim(),
            image_url: finalImageUrl, // Puede ser null
            author: data.author.trim(),
            publish_date: publishDate.toISOString(),
            pdf_url: pdfFilePath ? `/uploads/${pdfFilePath}` : null,
            last_updated_date: new Date().toISOString()
        };

        revisions.push(newRevision);
        await writeRevisions(revisions);
        console.log(`Revision ${newRevision.id} created successfully by ${req.session.username}.`);
        res.status(201).json(newRevision);

    } catch (e) {
        console.error(`Error ADD revision by ${req.session.username}:`, e);
        if (pdfFilePath) await deleteFileIfExists(pdfFilePath);
        if (imgFilePath) await deleteFileIfExists(imgFilePath);
        res.status(400).json({ message: e.message || 'Error interno al crear la revisión.' });
    }
});

// PUT /api/admin/revisions/:id (Editar Revisión)
app.put('/api/admin/revisions/:id', isAuthenticated, handleMulterUpload, async (req, res) => {
    const revisionId = parseInt(req.params.id, 10);
    const files = req.files || {};
    const data = req.body;
    let newPdfFile = files.pdfFile?.[0]?.filename;
    let newImgFile = files.imageFile?.[0]?.filename;
    let oldPdfToDelete = null;
    let oldImgToDelete = null;
    const removeCurrentPdf = data.removeCurrentPdf === 'true';
    const removeCurrentImage = data.removeCurrentImage === 'true';

    try {
        console.log(`User ${req.session.username} UPDATE revision ${revisionId}. Body:`, data, "Files:", files, "RemovePDF:", removeCurrentPdf, "RemoveIMG:", removeCurrentImage);
        if (isNaN(revisionId)) { throw new Error('ID de revisión inválido'); }
        if (!data.title || !data.excerpt || !data.category || !data.author || !data.full_content) {
             throw new Error('Faltan datos requeridos para la revisión (título, extracto, categoría, autor, contenido).');
        }

        const revisions = await readRevisions();
        const revisionIndex = revisions.findIndex(r => r.id === revisionId);
        if (revisionIndex === -1) {
            res.status(404); throw new Error('Revisión no encontrada');
        }
        const originalRevision = revisions[revisionIndex];

        // --- Lógica de Imagen (Permite null) ---
        let finalImageUrl = originalRevision.image_url; // Empezar con la original
        if (newImgFile) { // 1. Archivo nuevo subido
            finalImageUrl = `/uploads/${newImgFile}`;
            if (originalRevision.image_url?.startsWith('/uploads/')) { oldImgToDelete = path.basename(originalRevision.image_url); }
             console.log(`DEBUG REV IMG: Using new uploaded image: ${finalImageUrl}`);
        } else if (removeCurrentImage) { // 2. Marcado para eliminar
             finalImageUrl = null; // Se permite explícitamente null
             if (originalRevision.image_url?.startsWith('/uploads/')) { oldImgToDelete = path.basename(originalRevision.image_url); }
             console.log(`DEBUG REV IMG: Image explicitly removed.`);
        } else if (data.image_url !== originalRevision.image_url) { // 3. URL externa cambió
             if (data.image_url?.trim()) { // Nueva URL externa
                 try {
                     const parsedUrl = new URL(data.image_url.trim());
                     if (!['http:', 'https:'].includes(parsedUrl.protocol)) throw new Error();
                     finalImageUrl = parsedUrl.toString();
                     console.log(`DEBUG REV IMG: Using new external URL: ${finalImageUrl}`);
                     if (originalRevision.image_url?.startsWith('/uploads/')) { oldImgToDelete = path.basename(originalRevision.image_url); }
                 } catch { throw new Error('La URL de la imagen externa proporcionada no es válida.'); }
             } else { // URL externa se borró (string vacío)
                 finalImageUrl = null;
                 console.log(`DEBUG REV IMG: External URL removed, setting to null.`);
                  if (originalRevision.image_url?.startsWith('/uploads/')) { oldImgToDelete = path.basename(originalRevision.image_url); }
             }
        }
        // Si no se tocó nada, finalImageUrl sigue siendo la original.
         console.log(`DEBUG REV IMG: Final Image URL determined: ${finalImageUrl}`);
        // --- FIN Lógica Imagen ---

        // --- Lógica PDF (Idéntica a Artículos/Casos) ---
        let finalPdfUrl = originalRevision.pdf_url;
        if (newPdfFile) {
            finalPdfUrl = `/uploads/${newPdfFile}`;
            if (originalRevision.pdf_url?.startsWith('/uploads/')) { oldPdfToDelete = path.basename(originalRevision.pdf_url); }
        } else if (removeCurrentPdf) {
            finalPdfUrl = null;
            if (originalRevision.pdf_url?.startsWith('/uploads/')) { oldPdfToDelete = path.basename(originalRevision.pdf_url); }
        }
         console.log(`DEBUG REV PDF: Final PDF URL determined: ${finalPdfUrl}`);
        // --- FIN Lógica PDF ---

        const updatedRevision = {
            ...originalRevision, // Mantener id, publish_date original
            title: data.title.trim(),
            category: data.category,
            excerpt: data.excerpt.trim(),
            full_content: data.full_content.trim(),
            image_url: finalImageUrl, // Puede ser null
            author: data.author.trim(),
            pdf_url: finalPdfUrl,
            last_updated_date: new Date().toISOString()
        };
        revisions[revisionIndex] = updatedRevision;

        await writeRevisions(revisions);

        if (oldImgToDelete && oldImgToDelete !== newImgFile) await deleteFileIfExists(oldImgToDelete);
        if (oldPdfToDelete && oldPdfToDelete !== newPdfFile) await deleteFileIfExists(oldPdfToDelete);

        console.log(`Revision ${revisionId} updated successfully by ${req.session.username}.`);
        res.status(200).json(updatedRevision);

    } catch (error) {
        console.error(`Error UPDATE revision ${revisionId} by ${req.session.username}:`, error);
        if (newPdfFile) await deleteFileIfExists(newPdfFile);
        if (newImgFile) await deleteFileIfExists(newImgFile);
        const status = res.statusCode >= 400 ? res.statusCode : 400;
        res.status(status).json({ message: error.message || 'Error interno al actualizar la revisión.' });
    }
});

// DELETE /api/admin/revisions/:id (Eliminar Revisión)
app.delete('/api/admin/revisions/:id', isAuthenticated, async (req, res) => {
    const revisionId = parseInt(req.params.id, 10);
    try {
        if (isNaN(revisionId)) { throw new Error('ID de revisión inválido'); }
        console.log(`User ${req.session.username} attempts DELETE revision ${revisionId}`);

        const revisions = await readRevisions();
        const revisionIndex = revisions.findIndex(r => r.id === revisionId);
        if (revisionIndex === -1) {
            res.status(404); throw new Error('Revisión no encontrada para eliminar');
        }
        const revisionToDelete = revisions[revisionIndex];

        revisions.splice(revisionIndex, 1);
        await writeRevisions(revisions);

        // Borrar archivos asociados si existen
        if (revisionToDelete.image_url?.startsWith('/uploads/')) await deleteFileIfExists(path.basename(revisionToDelete.image_url));
        if (revisionToDelete.pdf_url?.startsWith('/uploads/')) await deleteFileIfExists(path.basename(revisionToDelete.pdf_url));

        console.log(`Revision ${revisionId} deleted successfully by ${req.session.username}.`);
        res.status(200).json({ message: 'Revisión eliminada correctamente' });
    } catch (e) {
        console.error(`Error DELETE revision ${revisionId} by ${req.session.username}:`, e);
        const status = res.statusCode >= 400 ? res.statusCode : 500;
        res.status(status).json({ message: e.message || 'Error interno al eliminar la revisión.' });
    }
});
// *********************************************************


// --- Manejador de Errores Global ---
// Este middleware se ejecuta si ninguna ruta anterior manejó la request o si se llamó a next(err)
app.use((err, req, res, next) => {
    console.error("Unhandled Error Caught:", err.stack || err);
    const status = err.status || 500; // Usar status del error si existe, o 500 por defecto

    // Evitar mostrar detalles internos en producción
    const message = process.env.NODE_ENV === 'production'
        ? 'Error Interno del Servidor'
        : (err.message || 'Ocurrió un error en el servidor');

    // Asegurarse de enviar JSON para las rutas API
    if (req.originalUrl.startsWith('/api/')) {
        return res.status(status).json({ message: message });
    }

    // Para otras rutas (aunque aquí principalmente son API o archivos estáticos)
    // Podrías tener una página de error genérica
    res.status(status).send(`<h1>Error ${status}</h1><p>${message}</p>`);
});

// --- Iniciar Servidor ---
app.listen(PORT, () => {
    console.log(`\nServer running at http://localhost:${PORT}`);
    console.log(`- Public directory: ${PUBLIC_DIR}`);
    console.log(`- Uploads directory: ${UPLOADS_DIR}`);
    console.log(`- Environment: ${process.env.NODE_ENV || 'development'}`);

    // Comprobación de seguridad de admin.html
    fs.access(path.join(PUBLIC_DIR, 'admin.html'))
        .then(() => console.warn('\x1b[33m%s\x1b[0m', 'SECURITY WARNING: admin.html found in /public directory! It should be moved to /private and accessed via a protected route.'))
        .catch(() => { /* Archivo no encontrado en public, lo cual es bueno */ });
});
// --- END OF FILE server.js ---