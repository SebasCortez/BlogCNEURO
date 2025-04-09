document.addEventListener('DOMContentLoaded', () => {
    const postContentArea = document.getElementById('post-content-area');
    const loadingDiv = document.getElementById('loading');
    const errorDiv = document.getElementById('error-message');

    // Función para obtener parámetros de la URL
    function getQueryParam(param) {
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.get(param);
    }

    // Función para formatear fecha
    function formatDate(dateString) {
        if (!dateString) return '';
        try {
            const options = { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' };
            return new Date(dateString).toLocaleDateString('es-ES', options);
        } catch (e) { return ''; }
    }

    const postId = getQueryParam('id');

    if (!postId) {
        loadingDiv.style.display = 'none';
        errorDiv.textContent = 'Error: No se especificó un ID de publicación.';
        errorDiv.style.display = 'block';
        return;
    }

    // Fetch para obtener los datos del post específico
    fetch(`/api/posts/${postId}`)
        .then(response => {
            if (!response.ok) {
                 // Intentar leer el mensaje de error del servidor si está en JSON
                return response.json().then(err => {
                     throw new Error(err.message || `Error HTTP: ${response.status}`);
                 }).catch(() => {
                     // Si no hay JSON, lanzar error genérico
                      throw new Error(`Error HTTP: ${response.status}`);
                 });
            }
            return response.json();
        })
        .then(post => {
            loadingDiv.style.display = 'none'; // Ocultar "Cargando..."

            // Cambiar el título de la página
            document.title = `${post.title || 'Publicación'} - CNEURO`;

            // Generar el HTML del post
            postContentArea.innerHTML = `
                <article class="post-detail">
                    <header class="post-detail-header">
                        <h1>${post.title || 'Título no disponible'}</h1>
                        <div class="post-meta-detail">
                            <span class="post-category-detail">
                                <i class="fas fa-tag"></i> ${post.category || 'Sin categoría'}
                            </span>
                            <span class="post-date-detail">
                                <i class="far fa-calendar-alt"></i> Publicado el ${formatDate(post.publish_date)}
                            </span>
                            <span class="post-author-detail">
                                <i class="far fa-user"></i> Por ${post.author || 'Desconocido'}
                            </span>
                        </div>
                        ${post.image_url ? `<img src="${post.image_url}" alt="${post.title || ''}">` : ''}
                    </header>
                    <section class="post-full-content">
                        ${post.full_content || '<p>Contenido no disponible.</p>'}
                    </section>
                    ${post.pdf_url ? `
                        <section class="pdf-link">
                            <a href="${post.pdf_url}" target="_blank" download>
                                <i class="fas fa-file-pdf"></i> Descargar PDF adjunto
                            </a>
                        </section>
                    ` : ''}
                </article>
                <hr style="margin: 2rem 0;">
                <a href="/" class="btn"><i class="fas fa-arrow-left"></i> Volver al inicio</a>
            `;
        })
        .catch(error => {
            loadingDiv.style.display = 'none';
            errorDiv.textContent = `Error al cargar la publicación: ${error.message}`;
            errorDiv.style.display = 'block';
            console.error('Error:', error);
        });
});