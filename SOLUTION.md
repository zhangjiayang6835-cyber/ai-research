\# Solución para el Bounty #963 - Host Header Injection



\## Vulnerabilidad

El enlace de reseteo de contraseña se generaba usando el header `Host` de la petición, lo que permitía a un atacante manipular el dominio y redirigir a los usuarios a un sitio malicioso.



\## Solución

Se implementó una función `get\_reset\_link()` que:



1\. Usa un dominio confiable definido en una variable de entorno.

2\. Valida el header `Host` contra una lista blanca de dominios permitidos.

3\. Genera URLs absolutas con el dominio correcto.



\## Archivos modificados

\- `fix\_host\_header\_injection.py`: Contiene la nueva lógica segura.



\## Pruebas

\- Verificado que el enlace se genera con el dominio correcto.

\- Probado que el header `Host` malicioso no afecta la generación del enlace.



Closes #963

