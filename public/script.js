document.addEventListener('DOMContentLoaded', () => {
    const postsGrid = document.querySelector('.posts-grid');

    if (!postsGrid) {
        console.error("Elemento .posts-grid no encontrado.");
        return; // Salir si no existe el contenedor
    }

    // Función para formatear la fecha
    function formatDate(dateString) {
        if (!dateString) return 'Fecha no disponible';
        try {
            // Formato más corto para la tarjeta
            const options = { year: 'numeric', month: 'short', day: 'numeric' };
            return new Date(dateString).toLocaleDateString('es-ES', options);
        } catch (e) {
            console.error("Error formateando fecha:", dateString, e);
            return 'Fecha inválida';
        }
    }

    // Mostrar mensaje de carga inicial
    postsGrid.innerHTML = '<p>Cargando publicaciones...</p>';

    // Hacer la petición al backend para obtener los posts
    fetch('/api/posts')
        .then(response => {
            if (!response.ok) {
                 // Intentar obtener mensaje de error del servidor
                 return response.json().then(err => {
                    throw new Error(err.message || `Error HTTP: ${response.status}`);
                 }).catch(() => {
                     // Si no hay JSON, lanzar error genérico
                      throw new Error(`Error HTTP: ${response.status}`);
                 });
            }
            return response.json();
        })
        .then(posts => {
            postsGrid.innerHTML = ''; // Limpiar el mensaje de "Cargando..."

            if (!posts || posts.length === 0) {
                postsGrid.innerHTML = '<p>No hay publicaciones disponibles en este momento.</p>';
                return;
            }

            posts.forEach(post => {
                const postElement = document.createElement('article');
                postElement.classList.add('post-card');
                // Añadir animación si se desea (requiere CSS)
                // postElement.style.opacity = '0';
                // postElement.style.transform = 'translateY(20px)';

                postElement.innerHTML = `
                    <div class="post-image">
                        <a href="post.html?id=${post.id}"> <!-- Enlace en la imagen -->
                            <img src="${post.image_url || 'https://via.placeholder.com/300x200?text=Sin+Imagen'}" alt="${post.title || ''}">
                        </a>
                    </div>
                    <div class="post-content">
                        <span class="post-category">${post.category || 'Sin Categoría'}</span>
                        <h3 class="post-title">
                            <a href="post.html?id=${post.id}" style="color: inherit; text-decoration: none;"> <!-- Enlace en el título -->
                                ${post.title || 'Título no disponible'}
                            </a>
                        </h3>
                        <p class="post-excerpt">${post.excerpt || 'Extracto no disponible.'}</p>
                        <div class="post-meta">
                            <span class="post-date"><i class="far fa-calendar-alt"></i> ${formatDate(post.publish_date)}</span>
                            <span class="post-author"><i class="far fa-user"></i> ${post.author || 'Desconocido'}</span>
                        </div>
                        <a href="post.html?id=${post.id}" class="btn btn-read-more">Leer Más</a>
                    </div>
                `;
                postsGrid.appendChild(postElement);

                // Activar animación si se usa
                // setTimeout(() => {
                //    postElement.style.opacity = '1';
                //    postElement.style.transform = 'translateY(0)';
                // }, 50); // Delay pequeño
            });

        })
        .catch(error => {
            console.error('Error al cargar los posts:', error);
            postsGrid.innerHTML = `<p style="color: red;">Error al cargar las publicaciones: ${error.message}. Inténtalo más tarde.</p>`;
        });

}); // Fin del DOMContentLoaded