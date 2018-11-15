# AnyTrace
AnyTrace es una colección de herramientas usada para detectar el área de servicio de diferentes servidores pertenecientes a una nube anycast.

El codigo más reciente lo puede encontrar en https://github.com/niclabs/AnyTrace

## Dependencias para compilación
AnyTrace se encuentra programado en *Rust*, por lo que para compilarlo es necesario instalar su compilador. Las instrucciones para esto lo pueden encontrar en https://www.rust-lang.org/en-US/install.html

Rust genera ejecutables independientes, por lo que no es necesario instalar este en otra maquina más que la utilizada para compilar.

## Compilar
Para Compilar AnyTrace, en la carpeta del repositorio debe ejecutar.
```
cargo build --release
```

Esto compilara las dependencias incluidas y generara el binario *target/release/anytrace*. Este binario puede traspasarse a otros computadores que utilicen la misma arquitectura.

## Permisos
Dado que este programa escucha de manera directa los paquetes ICMP, este requiere permisos de administrador, o CAP_NET_RAW en linux para ejecutarse en modo usuario. Para agregar los permisos, en cada servidor en el cual se quiera ejecutar se deben agregar los permisos de la siguiente forma:
```
sudo setcap CAP_NET_RAW+ep target/release/anytrace
```

## Ejecución
AnyTrace funciona en estructura Maestro/Seguidor, donde el servidor maestro realiza el envío de los paquetes iniciales, y los seguidores escuchan y procesan las respuestas. Los Seguidores deben ejecutarse antes del Maestro dado que este comienza el envío de forma inmediata. Todos los servidores a medir deben ejecutarse en modo seguidor, con excepción del nodo maestro, el cual actúa como maestro y seguidor a la vez.

Es posible indicar (opcionalmente) el tiempo que deben ejecutarse los seguidores, donde como base, la ejecución completa de las pruebas toma 1.800 segundos a una velocidad de 20.000 paquetes por segundo (9.7MBit/s) en unicast, y debe agregarse el tiempo requerido para instalarse en otros nodos (Utilizar un tiempo mayor no afecta a las pruebas).

Los parámetros de este programa son los siguientes:

| Parametro | Descripción                                                                                                                                           |
|-----------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| ip        | IP Anycast local a medir (fuente de los paquetes)                                                                                                     |
| pps       | Paquetes por segundo a enviar (64 bytes o menos por paquete)                                                                                          |
| method    | Método a medir (ICMP o UDP)                                                                                                                           |
| duration  | [Seguidor] (Opcional) Tiempo aproximado de las pruebas (a una velocidad de 20.000pps (9.7MBit/s) toma un tiempo de 20 minutos sin contar tiempo de configuracion) |
| hitlist   | [Maestro] Archivo con direcciones IP a medir                                                                                                          |
| master    | [Maestro] Indica si debe ejecutarse como maestro                                                                                                      |


Un seguidor debe ejecutarse de la siguiente manera:

```
./target/release/anytrace\
    --ip 190.124.27.10\
    --pps 20000\
    --method ICMP\
    --duration 2400\
    > resultICMP.csv
```

El servidor maestro debe ejecutarse de la siguiente manera:

```
./target/release/anytrace\
    --ip 190.124.27.10\
    --pps 20000\
    --hitlist hitlistICMP.txt\
    --method ICMP\
    --master\
    > resultICMP.csv
```

Estos comandos generaran el archivo resultICMP.csv con los resultados de las mediciones, capturado desde la salida estandar.

## Resultados

Los resultados son expuestos por la salida estándar del programa, y pueden almacenarse localmente en los nodos. Cada uno de estos archivos poseen información sobre el área de servicio que ellos poseen de manera independiente.

# Estructura de repositorio
El código se separa en dos fuentes principales, *src/ping* y *src/anytrace*.

*src/ping* corresponde al código que se encarga de generar, enviar y recibir los paquetes ICMP a través de un socket unix, utilizando colas sobre la información.

*src/anytrace* se encarga del procesamiento de los datos recibidos, enviando paquetes según la información capturada y generando los resultados.

# Como ejecutar el experimento

Para realizar las mediciones, se debe copiar el binario *anytrace* en todos los nodos a medir, seleccionando uno con acceso a internet global como maestro, en el cual se debe incluir las listas *hitlistICMP.txt* y *hitlistUDP.txt*

En cada nodo seguidor se debe ejecutar *anytrace* como seguidor, y luego de tener todos los nodos en ejecución, se realiza la ejecución del nodo maestro.

La dirección IP indicada debe ser local y pertenecer a la nube anycast, no siendo necesario utilizar una dirección en producción.

Para facilitar la ejecución, se incluyen los archivos *master.sh* y *follower.sh* con los argumentos necesarios, los cuales calculan el tiempo de ejecución según la cantidad de paquetes por segundo y una ventana de 20 minutos para configurar todos los nodos.

```
# ./master.sh IP pps method
./master.sh 190.124.27.10 20000 ICMP
```

```
# ./follower.sh IP pps method
./follower.sh 190.124.27.10 20000 ICMP
```

Las mediciones deben realizarse para ICMP y UDP. Para realizar las pruebas por UDP, se deben ejecutar los mismos scripts cambiando las llamadas de ICMP a UDP de la siguiente manera.

```
# ./master.sh IP pps method
./master.sh 190.124.27.10 20000 UDP
```

```
# ./follower.sh IP pps method
./follower.sh 190.124.27.10 20000 UDP
```

Los resultados serán guardados en los archivos resultUDP.csv y resultICMP.csv en cada nodo, los cuales deben ser recolectados. Es posible comprimirlos con el comando.

```
gzip resultUDP.csv resultICMP.csv
```
