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

El cuerpo principal contenía una sola parte de archivo y 220.000 headers de
parte. Las cuatro versiones vulnerables terminaron con un fatal por agotamiento
de memoria. Las cuatro versiones corregidas completaron el parseo y ejecutaron
el script. Repetimos la matriz dos veces después de validar el harness.

La respuesta HTTP y el código de salida no bastaron como prueba. Nuestro primer
cliente FastCGI tenía dos errores de framing y una fixture de PowerShell
expandía variables que debían quedar literales. En las primeras corridas, un
404 con un estado aparentemente correcto podía parecer una ejecución válida.
Desde ese punto exigimos un marcador emitido por la aplicación después del
parseo. Las corridas anteriores quedaron invalidadas.

La lección es aplicable a cualquier trabajo de exploit development: una señal
del transporte demuestra que el servidor respondió; solamente un marcador
positivo demuestra que se alcanzó el punto que el experimento pretende medir.

## El acantilado 140k/260k

El resultado más distintivo apareció en Apache `mod_php` sobre Windows. Hicimos
un sweep de seis tamaños, con tres repeticiones por tamaño, sobre PHP 8.4.26 y
8.4.27. La versión vulnerable agotó los 8 MiB desde 140.000 headers. La versión
corregida procesó 260.000 bajo el mismo límite.

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
demostrado control del instruction pointer ni ejecución final mediante el heap
grooming de CVE-2026-109618/109619. El diferencial del parche, las cadenas de
aplicación y el RCE del motor son resultados distintos y deben permanecer
separados.

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

Finalmente, un PoC recién publicado merece el mismo tratamiento que cualquier
binario desconocido: revisión estática, eliminación de destinos embebidos,
entorno desechable y ausencia de credenciales reutilizables. Cuando existe un
advisory y tests del parche, reconstruir el caso desde esas fuentes suele dar
mejor evidencia que ejecutar código ajeno y confiar en su salida.

PHP2Shell expuso una falla profunda en el ciclo de vida del intérprete. La
respuesta útil combina actualización, mediciones comparables, preservación de
evidencia y atribución precisa. También exige declarar el límite del
experimento: pudimos medir el efecto del parche y reproducir cadenas remotas
dependientes de la aplicación; la ejecución completa mediante la corrupción de
memoria del motor sigue fuera de nuestros resultados.
