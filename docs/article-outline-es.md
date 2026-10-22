# Esquema del artículo en español

## Tesis

El valor de nuestra investigación no está en afirmar que descubrimos
PHP2Shell. Está en mostrar qué cambia realmente después del parche, qué señales
deja el intento de explotación y por qué ejecutar el primer repositorio que
aparece en GitHub puede introducir un segundo riesgo durante una emergencia.

## Título de trabajo

**PHP2Shell bajo el microscopio: qué cambió con el parche y qué encontramos al reproducirlo**

## Estructura

### 1. La emergencia estaba en el intérprete

Explicar los dos CVE, el alcance por SAPI y por qué actualizar WordPress,
Drupal o Joomla no sustituye la actualización de PHP. Dar crédito a los
descubridores y al equipo de PHP desde el comienzo.

### 2. Construimos una comparación, no una demostración teatral

Presentar las ocho builds, el límite idéntico, los cuerpos derivados de fuentes
primarias y la obligación de observar un marcador positivo. Contar brevemente
los tres errores del harness y por qué invalidamos las primeras corridas.

### 3. El parche dejó una frontera medible

Desarrollar el diferencial 8/8, la muerte de 8.3.35 y el acantilado 140k/260k.
Explicar que son observaciones de laboratorio y que un OOM no equivale a RCE.

### 4. Lo que la sesión dejó en disco

Presentar la truncación a cero bytes como hipótesis forense correlacionable, no
como IoC concluyente. Añadir el mapa por SAPI y los negativos honestos.

### 5. Sí logramos ejecución, pero por otra superficie

Explicar Chain A y Chain C con atribución. Declarar las condiciones no-default
de Chain A y que ambas cadenas funcionaron también en versiones parcheadas.
Cerrar la sección diciendo explícitamente que el grooming del motor sigue
pendiente.

### 6. Mientras investigábamos aparecieron 267 repositorios

Contar las tres poblaciones, los cinco análisis profundos, el target embebido y
la imitación de identidad. Incluir las limitaciones: no auditamos la cola larga
y no confirmamos malware en la muestra.

### 7. Qué hacer ahora

Parchear PHP, reiniciar workers, aplicar mitigaciones temporales, revisar logs y
preservar evidencia. Explicar qué correlaciones buscar y por qué no basta con
una firma literal de una PoC pública.

### Cierre

Una emergencia técnica también es una emergencia de información. La respuesta
útil combina parcheo, experimentos comparables, atribución y la disciplina de
decir exactamente qué se logró y qué todavía no.

## Nota metodológica opcional

El laboratorio pasó de una VM apagada a RCE remoto reproducido en alrededor de
24 horas. Este dato acompaña la metodología; no debe reemplazar los resultados
ni presentarse como una carrera.

