document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('addPostForm');
    const messageDiv = document.getElementById('message');

    if (!form) {
        console.error("Formulario #addPostForm no encontrado.");
        return;
    }
     if (!messageDiv) {
        console.error("Elemento #message no encontrado.");
        // Podríamos continuar sin messageDiv, pero avisamos.
    }


    form.addEventListener('submit', (event) => {
        event.preventDefault(); // Evitar que el formulario se envíe de forma tradicional
        if (messageDiv){
            messageDiv.textContent = 'Enviando...'; // Mensaje de carga
            messageDiv.className = ''; // Limpiar clases de estilo del mensaje
        }

        // Crear FormData a partir del formulario. Esto recoge automáticamente
        // todos los campos, incluyendo el archivo (si se seleccionó uno).
        const formData = new FormData(form);

        // Enviar los datos al backend (al endpoint POST /api/posts)
        fetch('/api/posts', {
            method: 'POST',
            // **NO** establecer la cabecera 'Content-Type'.
            // El navegador lo hará automáticamente con el 'boundary'
            // correcto cuando envías un objeto FormData.
            body: formData
        })
        .then(response => {
            // Intentar parsear la respuesta como JSON, sin importar si es OK o error
            return response.json().then(data => {
                // Añadir el status de la respuesta al objeto de datos para usarlo después
                return { status: response.status, ok: response.ok, body: data };
            });
        })
        .then(result => {
            if (result.ok) {
                // Éxito (ej. status 201 Created)
                if (messageDiv){
                     messageDiv.textContent = `Publicación "${result.body.title || 'Nueva'}" añadida con éxito!`;
                     messageDiv.className = 'success'; // Aplicar estilo de éxito
                }
                form.reset(); // Limpiar el formulario
                console.log("Post añadido:", result.body);
                 // Opcional: Redirigir o mostrar un enlace para ver el post
                 // setTimeout(() => { window.location.href = '/'; }, 2000);
            } else {
                // Error del servidor (ej. status 400 Bad Request, 500 Internal Server Error)
                 // Usar el mensaje del cuerpo de la respuesta si existe, o un mensaje genérico
                 throw new Error(result.body.message || `Error ${result.status} del servidor.`);
            }
        })
        .catch(error => {
            // Error (puede ser de red, de parseo JSON, o el lanzado desde el .then anterior)
            console.error('Error al añadir post:', error);
             if (messageDiv){
                messageDiv.textContent = `Error al añadir la publicación: ${error.message}`;
                messageDiv.className = 'error'; // Aplicar estilo de error
             }
        });
    });
});