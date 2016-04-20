### Dependencias
`sudo pip install scapy`
`sudo apt-get install python-pygraphviz`
`sudo pip install networkx`

### Capturar paquetes
Para hacer una captura de paquetes, ejecutar: `sudo ./capture.py <interface> <segundos>`.
El archivo se guarda como "captura.pcap"

### Procesar capturas
Para procesar una captura, ejecutar: `./process.py <archivo> <experimento>`.
Donde `<experimento>` puede ser:
* "exp-proto": Corre el experimento de protocolos distinguidos
* "exp-nodos": Corre el experimento de nodos distinguidos

### Graficar nodos
Para generar una imagen con la topología de una red, ejecutar: `./graficar.py <archivo>`.
