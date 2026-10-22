# PHP2Shell bajo el microscopio: qué cambió con el parche y qué encontramos al reproducirlo

> Borrador editorial privado. Los conteos de GitHub corresponden a una captura
> del 21 de octubre de 2026 y deben conservar su fecha al publicarse.

El 21 de octubre de 2026, PHP publicó cuatro versiones de emergencia para
corregir CVE-2026-109618 y CVE-2026-109619. Ambas vulnerabilidades afectan al
intérprete y permiten construir rutas de ejecución remota antes de que la
aplicación procese la petición. Un WordPress, Drupal o Joomla actualizado sigue
expuesto si corre sobre una versión vulnerable de PHP.

El alcance explica la urgencia. El problema atraviesa PHP-FPM, Apache
`mod_php`, `php-cgi`, FrankenPHP y LiteSpeed, aunque cada SAPI maneja de forma
distinta el inicio, el cierre y la reutilización de un worker. PHP publicó
8.2.35, 8.3.36, 8.4.27 y 8.5.12 como versiones corregidas. Las ramas anteriores
sin soporte requieren migración o los backports mínimos publicados por el
proyecto.

Durante las primeras 24 horas montamos un laboratorio para observar el cambio
entre versiones vulnerables y parcheadas. La meta era conseguir evidencia
comparable: mismo cuerpo HTTP, mismo límite de memoria, misma aplicación y una
pareja de builds por rama. El resultado más útil fue una frontera medible en el
parseo multipart, acompañada de diferencias por SAPI y de artefactos que pueden
ayudar durante una investigación defensiva.

## Dos fallos unidos por el ciclo de vida del request

CVE-2026-109618 nace en la forma histórica con que PHP maneja ciertos fallos de
memoria. Un `longjmp()` puede abandonar una operación cuando partes del request
todavía no están completamente inicializadas. Si el SAPI continúa con el
shutdown, el motor puede consultar memoria inválida o parcialmente construida.

El atacante tampoco necesita enviar un cuerpo enorme. El advisory describe
formas de amplificar el consumo dentro del parser: headers ilimitados dentro de
una parte multipart, controles de archivo vacíos y nombres anidados que obligan
a construir estructuras mucho mayores que su representación en la red.

CVE-2026-109619 usa una segunda propiedad del runtime: los workers se reutilizan
entre peticiones. Ciertos globales relacionados con errores, sesiones y
deserialización pueden conservar referencias a memoria perteneciente al
request anterior. Una petición productora deja el estado incompleto; una
petición posterior, atendida por el mismo worker, lo consume demasiado pronto.

El cambio que corrigió ambas vulnerabilidades fue amplio: 389 archivos y más
de doscientos tests relacionados con OOM. El motor incorporó estados explícitos
para diferir errores hasta puntos seguros de la VM, una salida dura para el
límite extremo y más resets de globales durante el cierre. El tamaño del parche
también explica por qué una prueba aislada contra una sola aplicación resulta
insuficiente para entender el comportamiento.

## Una matriz de ocho versiones

Probamos las parejas 8.2.34/8.2.35, 8.3.35/8.3.36, 8.4.26/8.4.27 y
8.5.11/8.5.12. Todas usaron `memory_limit=8M` y `post_max_size=64M`. El límite
pequeño permitió observar la amplificación interna sin depender de grandes
volúmenes de tráfico.

La base relevante de configuración fue idéntica entre builds:

```ini
memory_limit = 8M
post_max_size = 64M
upload_max_filesize = 32M
max_input_vars = 1000000

session.upload_progress.enabled = 1
session.upload_progress.cleanup = 1
session.use_cookies = 1
session.serialize_handler = php
```

El cuerpo principal contenía una sola parte de archivo y 220.000 headers de
parte. Las cuatro versiones vulnerables terminaron con un fatal por agotamiento
de memoria. Las cuatro versiones corregidas completaron el parseo y ejecutaron
el script. Repetimos la matriz dos veces después de validar el harness.

La forma del request era deliberadamente simple. El volumen estaba dentro de
los headers de una única parte multipart:

```http
POST /worker.php HTTP/1.1
Content-Type: multipart/form-data; boundary=adversario-lab

--adversario-lab
Content-Disposition: form-data; name="file"; filename="probe.txt"
X-F0: hhhhhhhhhhhh
X-F1: hhhhhhhhhhhh
...
X-F219999: hhhhhhhhhhhh

x
--adversario-lab--
```

La respuesta HTTP y el código de salida no bastaron como prueba. Nuestro primer
cliente FastCGI tenía dos errores de framing y una fixture de PowerShell
expandía variables que debían quedar literales. En las primeras corridas, un
404 con un estado aparentemente correcto podía parecer una ejecución válida.
Desde ese punto exigimos un marcador emitido por la aplicación después del
parseo. Las corridas anteriores quedaron invalidadas.

El endpoint de control no hacía trabajo adicional. Solo confirmaba que PHP
había terminado de construir las variables de entrada y alcanzado la
aplicación:

```php
<?php
register_shutdown_function(static function (): void {
    echo "[shutdown-reached]\n";
});

printf(
    "[app] version=%s sapi=%s files=%d\n",
    PHP_VERSION,
    PHP_SAPI,
    count($_FILES)
);
```

En el harness, un resultado solo entraba a la matriz si contenía el marcador
correspondiente. Un status o un `appStatus=0` aislado quedaban clasificados como
indeterminados:

```python
reached_app = b"[app]" in response_body
reached_shutdown = b"[shutdown-reached]" in response_body

if not reached_app and not fatal_oom:
    verdict = "INDETERMINATE"
elif reached_app:
    verdict = "PARSE_COMPLETE"
else:
    verdict = "FATAL_OOM"
```

La lección es aplicable a cualquier trabajo de exploit development: una señal
del transporte demuestra que el servidor respondió; solamente un marcador
positivo demuestra que se alcanzó el punto que el experimento pretende medir.

## El acantilado 140k/260k

El resultado más distintivo apareció en Apache `mod_php` sobre Windows. Hicimos
un sweep de seis tamaños, con tres repeticiones por tamaño, sobre PHP 8.4.26 y
8.4.27. La versión vulnerable agotó los 8 MiB desde 140.000 headers. La versión
corregida procesó 260.000 bajo el mismo límite.

El resumen del sweep tenía esta forma:

```text
headers    PHP 8.4.26             PHP 8.4.27
-------    --------------------   --------------------
140000     FATAL_OOM  (3/3)       PARSE_COMPLETE (3/3)
180000     FATAL_OOM  (3/3)       PARSE_COMPLETE (3/3)
220000     FATAL_OOM  (3/3)       PARSE_COMPLETE (3/3)
260000     FATAL_OOM  (3/3)       PARSE_COMPLETE (3/3)
```

Esta diferencia no convierte un fatal OOM en ejecución de código. Sí muestra un
cambio observable en la contabilidad o representación del parseo después del
parche. El punto intermedio permite construir una verificación diferencial de
una petición para versiones y configuraciones equivalentes.

Esa verificación induce deliberadamente presión de memoria. Debe ejecutarse en
un laboratorio o bajo autorización expresa, observando la salud y capacidad de
los workers. Describirla como un scanner inocuo ocultaría su efecto real sobre
el servicio.

## El mismo cuerpo no produce el mismo resultado en cada SAPI

En FastCGI persistente, un cuerpo con 200.000 variables mató al worker de PHP
8.3.35 durante la transmisión en tres de tres intentos. PHP 8.3.36 sobrevivió
las tres corridas equivalentes. Las otras ramas no replicaron esa muerte con la
misma forma, coherente con la sensibilidad a la versión, el allocator y el
layout del proceso descrita en los advisories.

El CGI one-shot permitió observar el diferencial, pero no conservar estado
entre requests. El FastCGI de Windows no reprodujo el consumidor stale ni la
cookie de sesión anormalmente grande descrita en investigaciones públicas.
Sobre `mod_php` de Windows ejecutamos 240 variantes con PageHeap y no obtuvimos
un crash atribuible al CVE. En Linux confirmamos el diferencial del parser y la
firma temprana del consumidor de sesión, sin alcanzar corrupción controlada.

Estos negativos importan. Delimitan qué formas terminan en un OOM limpio, qué
SAPI elimina el worker y dónde conviene buscar el estado persistente. También
evitan transformar cualquier caída de PHP en una supuesta prueba de RCE.

## El consumidor stale finalmente cayó en PHP-FPM

Las primeras pruebas de la cadena entre requests terminaban limpias porque el
productor fallaba demasiado pronto. Con una sesión de 30 MiB y un límite de 32
MiB, PHP no alcanzaba a deserializar: agotaba memoria al reservar el buffer del
archivo. Con la primera calibración de 5 MiB/8 MiB, el fallo ocurría al reservar
la tabla inicial. En ambos casos quedaba poco estado útil para el consumidor.

Al mover el experimento a PHP-FPM 8.2 y usar `memory_limit=32M`, las sesiones de
14, 16 y 18 MiB agotaron memoria durante el walk de `unserialize`. El primer
request de upload progress atendido después por el mismo worker produjo
SIGSEGV en PHP 8.2.34:

```text
PHP 8.2.34 FPM, sesión productora de 14 MiB
  producer: FATAL_OOM, tried to allocate 4096 bytes
  consumer #1: respuesta vacía
  php-fpm: child exited on signal 11 (SIGSEGV)

PHP 8.2.35 FPM, mismo diseño de 14 y 16 MiB
  producer: OOM durante el walk
  consumers: [APP, APP, APP, APP, APP, APP]
  segfaults: 0
```

Los casos vulnerables de 14–18 MiB alcanzaron el mismo offset de instrucción en
las corridas observadas. Las direcciones de fallo variaron con el tamaño; una
repetición del caso de 14 MiB reprodujo ambas direcciones. El log de FPM dejó la
secuencia completa: fatal dentro del productor, warning al decodificar la sesión
del consumidor y salida del child por señal 11.

Este resultado reproduce un crash diferencial del motor consistente con
CVE-2026-109619. Todavía falta capturar el backtrace bajo debugger, identificar
la estructura exacta y demostrar un overwrite controlado. Un SIGSEGV
determinista ofrece un oráculo para continuar el análisis; no equivale a control
del instruction pointer ni a una shell.

## Una pista forense en los archivos de sesión

Al calibrar el productor de sesión, un archivo de aproximadamente 5 MiB hizo
que el agotamiento ocurriera dentro de `php_var_unserialize`. Con tamaños
mayores, el fallo sucedía antes, al reservar el buffer para leer el archivo.
Tres líneas de configuración o unos pocos megabytes podían separar un OOM
estéril de la ruta que deja activo el estado del deserializador.

Después del fatal interno observamos que el archivo de sesión quedaba truncado
a cero bytes. Ese artefacto puede servir como hipótesis de hunting cuando
coincide temporalmente con errores de memoria, actividad de upload progress y
peticiones multipart anómalas. Por sí solo tiene demasiadas causas operativas
posibles para tratarlo como indicador concluyente.

## Ejecución de comandos y límites del claim

También reproducimos dos cadenas públicas dependientes de la aplicación. La
cadena de mismatch entre handlers de serialización ejecutó `whoami` durante el
arranque del request en cuatro builds de Windows. Chain A produjo ejecución
remota mediante HTTP en nuestro laboratorio Linux usando datos persistidos por
upload progress y un endpoint con inclusión local de archivos.

Chain A necesitó un LFI, conocer el directorio de sesiones,
`session.upload_progress.cleanup=Off` y `session.use_only_cookies=0`. Los dos
valores de configuración no son los defaults de PHP. La cadena funcionó tanto
en PHP 8.4.26 como en 8.4.27.

La ejecución es real, pero pertenece a una superficie de sesión y aplicación
documentada públicamente por Qi Deng e ikow. Nuestro laboratorio todavía no ha
demostrado control del instruction pointer ni ejecución final mediante heap
grooming. Ahora sí reprodujimos el crash del consumidor stale en el motor con
un control parcheado limpio. El crash diferencial, las cadenas dependientes de
la aplicación y un RCE del motor siguen siendo resultados distintos.

## La segunda emergencia apareció en GitHub

Mientras avanzaba la investigación, una búsqueda de `php2shell` devolvía 267
repositorios. Las búsquedas por cada CVE devolvían 232 y 217 resultados. La
mayoría había sido actualizada durante las horas posteriores al anuncio.

Encontramos tres grupos: investigación sustantiva con referencias cruzadas,
copias de un commit publicadas desde cuentas recientes y repositorios que
usaban el término para ganar visibilidad. Una copia conservaba incluso la
instrucción para clonar el upstream original. Otro proyecto reutilizaba un CVE
de 2024 sin relación con PHP2Shell y usaba un handle parecido al del
investigador que reportó la vulnerabilidad.

Uno de los PoC auditados contenía una URL predeterminada que aparentaba apuntar
a un host real. Ejecutarlo sin argumentos habría enviado tráfico de explotación
a ese destino. También identificamos strings útiles para hunting, como el
User-Agent `php2shell-109618`, el boundary `B7kQpoc618` y el marcador
`JACKALPOC`.

La muestra tiene límites claros. Auditamos profundamente cinco repositorios y
revisamos cerca de diez README adicionales. No confirmamos malware, descargas,
telemetría ni exfiltración en esos archivos. Aproximadamente 250 resultados de
cola larga quedaron fuera de la auditoría. La ausencia de malware en cinco
repositorios no certifica el resto de la oleada.

## Qué deberían hacer los equipos ahora

La prioridad es identificar y actualizar el runtime PHP. Revisar solamente la
versión del CMS deja fuera el componente vulnerable. Después de cambiar
mitigaciones de sesión hay que reiniciar todos los workers.

Los controles temporales publicados por PHP incluyen límites en el proxy,
desactivar upload progress para la segunda cadena y eliminar configuraciones
por request que emitan diagnósticos antes de la inicialización. Esas medidas
reducen superficie mientras se instala la versión corregida.

Para hunting, conviene correlacionar varias capas: peticiones multipart con
cantidades anómalas de headers o campos, fatals de memoria durante el parseo,
caídas o churn de workers, cookies PHPSESSID inusuales y archivos de sesión
vacíos creados en la misma ventana. Los literales de PoC públicos son pistas
temporales y fáciles de modificar.

Una búsqueda inicial puede expresar esa correlación sin convertir cada evento
aislado en una alerta crítica. El siguiente pseudocódigo muestra la lógica, no
una consulta específica de proveedor:

```sql
SELECT host, time_bucket('1 minute', timestamp) AS window
FROM security_events
WHERE event IN (
  'multipart_header_anomaly',
  'php_memory_limit_exhausted',
  'php_worker_crash',
  'zero_byte_session_created'
)
GROUP BY host, window
HAVING COUNT(DISTINCT event) >= 2;
```

Finalmente, un PoC recién publicado merece el mismo tratamiento que cualquier
binario desconocido: revisión estática, eliminación de destinos embebidos,
entorno desechable y ausencia de credenciales reutilizables. Cuando existe un
advisory y tests del parche, reconstruir el caso desde esas fuentes suele dar
mejor evidencia que ejecutar código ajeno y confiar en su salida.

## La investigación continúa

Esta primera entrega cierra con un diferencial reproducible del parche, un
crash del consumidor FPM exclusivo de la versión vulnerable, un mapa por SAPI,
una hipótesis forense y una auditoría acotada de la oleada pública. Es material
suficiente para que otros equipos comparen sus entornos, mejoren el hunting y
eviten confundir un fatal o una cadena de aplicación con explotación completa
del motor.

El siguiente paso será identificar bajo debugger la estructura exacta que
consume el estado stale y validar las reglas defensivas contra tráfico del
laboratorio. Publicaremos una segunda entrega si esa evidencia permite avanzar
el análisis. Hasta entonces, el resultado queda descrito por lo que demuestra:
un crash diferencial del motor, reproducible y separado de cualquier claim de
RCE controlado.

PHP2Shell expuso una falla profunda en el ciclo de vida del intérprete. La
respuesta útil combina actualización, mediciones comparables, preservación de
evidencia y atribución precisa. También exige declarar el límite del
experimento: pudimos medir el efecto del parche y reproducir cadenas remotas
dependientes de la aplicación. También reprodujimos un crash diferencial del
motor en la cadena FPM; la corrupción controlada y la ejecución final mediante
esa ruta siguen fuera de nuestros resultados.
