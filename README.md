<p align="center">
  <img src='https://mili.one/pics/arashik.png' width="60%" height="60%"/>
</p>

----------
DNS over KCP Experimental and Proof of Concept

## Quickstart

##### Server
```
docker run -d -p 20053:20053 -p 20053:20053/udp ghcr.io/mili-tan/arashidns.ks 8.8.8.8:53 -l 0.0.0.0:20053 -p passw0rd
```
##### Client
```
docker run -d -p 127.0.0.1:53:53 -p 127.0.0.1:53:53/udp ghcr.io/mili-tan/arashidns.k <serverip>:20053 -l 0.0.0.0:53 -p passw0rd
```

## License

Copyright (c) 2024 Milkey Tan. Code released under the [Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/). 

<sup>ArashiDNS™ is a trademark of Milkey Tan.</sup>
