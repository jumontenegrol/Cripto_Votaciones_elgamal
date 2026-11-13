# Eleccion ElGamal — demo academica

Prototipo local para visualizar cifrado ElGamal exponencial, papeletas validables, conteo homomorfico y auditoria publica. No usar para elecciones reales.

## Ejecutar

Requiere Node.js 18 o superior (incluye npm). Desde esta carpeta, abre una terminal de VS Code y ejecuta:

```powershell
npm start
```

Deja esa terminal abierta mientras usas la demo y visita la dirección que imprime el servidor (normalmente http://localhost:3000). Si el puerto está ocupado, intentará automáticamente el siguiente. También puedes iniciar el servidor haciendo doble clic en `iniciar-demo.bat`. No abras `public/index.html` directamente ni uses la extensión Live Server de VS Code: la aplicación necesita su propio servidor para habilitar los botones. No hace falta ejecutar `npm install`: no usamos paquetes externos. El estado vive en memoria y se reinicia al detener el servidor.

## Alcance de esta version

- Eleccion local con tres candidaturas de ejemplo y 100 identidades simuladas.
- El navegador cifra cada papeleta; el servidor valida las pruebas antes de aceptarla.
- El tablero publica criptogramas anonimos en una cadena de hashes.
- El cierre agrega los criptogramas y publica el descifrado del total con prueba verificable.
- La auditoria vuelve a verificar papeletas, cadena y prueba de descifrado.

El registro de votantes es una simulacion de una sola instancia. La clave privada se mantiene en memoria en el mismo servidor que cuenta los votos. La cadena de hashes no impide que un operador reescriba todo el tablero. Esto ilustra propiedades criptograficas; no es una arquitectura segura de votacion.
