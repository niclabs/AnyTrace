# AnyTrace
AnyTrace es una colección de herramientas usada para detectar el área de servicio de diferentes servidores pertenecientes a una nube anycast.

El código más reciente se puede encontrar en https://github.com/niclabs/AnyTrace

## Dependencias para compilación
AnyTrace se encuentra programado en *Rust*, por lo que para compilarlo es necesario instalar su compilador. Las instrucciones para esto lo pueden encontrar en https://www.rust-lang.org/en-US/install.html

Rust genera ejecutables independientes, por lo que no es necesario instalar este en otra máquina más que la utilizada para compilar.

## Compilar
Para Compilar AnyTrace, en la carpeta del repositorio debe ejecutar.
```
cargo build --release
```

Esto compilará las dependencias incluidas y generará el binario *target/release/anytrace*. Este binario puede traspasarse a otros computadores que utilicen la misma arquitectura, sin requerir la instalación de las dependencias en otros nodos.

## Permisos
Dado que este programa escucha de manera directa los paquetes ICMP, este requiere permisos de administrador, o CAP_NET_RAW en linux para ejecutarse en modo usuario. En cada servidor en el cual se quiera ejecutar se deben agregar los permisos de la siguiente forma:
```
sudo setcap CAP_NET_RAW+ep target/release/anytrace
```

## Ejecución
AnyTrace se debe ejecutar en cada servidor de manera independiente. La ejecución completa en un nodo toma aproximadamente 20 minutos a una velocidad de 20.000 paquetes por segundo (9,7MBit/s) utilizando unicast, y se espera que su ejecución sea mucho más rápida en nodos anycast.

Los parámetros de este programa son los siguientes:

| Parametro | Descripción                                           |
|-----------|-------------------------------------------------------|
| ip        | IP Anycast local a medir (fuente de los paquetes)     |
| pps       | Paquetes por segundo a enviar (64 bytes por paquete)  |
| method    | Método a medir (ICMP o UDP)                           |
| hitlist   | Archivo con direcciones IP a medir                    |
| master    | Indica que se debe ejecutar como maestro              |

Cada nodo debe ejecutarse de la siguiente manera, cambiando la dirección IP (x.x.x.x) a una local **en la red anycast**, no siendo necesario utilizar una dirección en producción:

```
./target/release/anytrace\
    --ip x.x.x.x\
    --pps 20000\
    --hitlist hitlistICMP.txt\
    --method ICMP\
    --master\
    > resultICMP.csv
```

Estos comandos generaran el archivo resultICMP.csv con los resultados de las mediciones, capturado desde la salida estándar. Esto debe repetirse para el método UDP de la siguiente manera.

```
./target/release/anytrace\
    --ip x.x.x.x\
    --pps 20000\
    --hitlist hitlistUDP.txt\
    --method UDP\
    --master\
    > resultUDP.csv
```

## Resultados
Los comandos indicados anteriormente almacenan los resultados de manera local en cada nodo en los archivos *resultICMP.csv* y *resultUDP.csv*, generados a partir de la salida estándar del programa.

Antes de recolectarlos, es posible comprimirlos utilizando el siguiente comando.

```
tar -czvf result.tar.gz resultUDP.csv resultICMP.csv
```

## Estructura de repositorio
El código se separa en dos fuentes principales, *ping/src* y *src/anytrace*.

*ping/src* corresponde al código que se encarga de generar, enviar y recibir los paquetes ICMP a través de un socket unix, utilizando colas sobre la información.

*src/anytrace* se encarga del procesamiento de los datos recibidos, enviando paquetes según la información capturada y generando los resultados.
