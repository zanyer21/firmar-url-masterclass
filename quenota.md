# Construir las imágenes y levantar los contenedores

- docker-compose down - Detiene y elimina contenedores y redes
- Reconstruir y levantar sin detener todo: docker-compose up --build -d

## decodificar playload

echo "eyJ1aWQiOiJ1c3VhcmlvMTIzIiwiaXAiOiIxMjcuMC4wLjEiLCJleHBpcmVzIjoxNzY5MTE1ODEzfQ" | base64 --decode

## ejemplo de hora universal zanyer

new Date(1769113800 \* 1000).toLocaleString("es-NI")
