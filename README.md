# WS-Attacker
[![release](https://img.shields.io/badge/Release-v1.8-blue.svg)](https://github.com/RUB-NDS/WS-Attacker/releases)
![licence](https://img.shields.io/badge/License-GPLv2-brightgreen.svg)[
![travis](https://travis-ci.org/RUB-NDS/WS-Attacker.svg?branch=master)](https://travis-ci.org/RUB-NDS/WS-Attacker)

WS-Attacker is a modular framework for web services penetration testing. It is developed by the Chair of Network and Data Security, Ruhr University Bochum (https://nds.rub.de/) and the Hackmanit GmbH (https://hackmanit.de/).

The basic idea behind WS-Attacker is to provide a functionality to load WSDL files and send SOAP messages to the Web Service endpoints (which is executed using the underlying SoapUI framework). This functionality can be extended using various plugins and libraries to build specific Web Services attacks. You can find more information on the WS-Attacker architecture and its extensibility in our paper: Penetration Testing Tool for Web Services Security (https://www.nds.rub.de/research/publications/ws-attacker-paper/)

In the current version, WS-Attacker supports the following attacks:
- SOAPAction spoofing: see https://www.ws-attacks.org/index.php/SOAPAction_Spoofing
- WS-Addressing spoofing: see https://www.ws-attacks.org/index.php/WS-Addressing_spoofing
- XML Signature Wrapping: see https://nds.rub.de/media/nds/arbeiten/2012/07/24/ws-attacker-ma.pdf
- XML-based DoS attacks: see https://www.nds.rub.de/research/publications/ICWS_DoS
- New Adaptive and Intelligent Denial-of-Service Attacks (AdIDoS)
- XML Encryption attacks: see this blogpost (https://web-in-security.blogspot.de/2015/05/how-to-attack-xml-encryption-in-ibm.html) for a general overview on the attacks and on further references to the scientific papers

## Obtaining Runnable File
The first option to obtain a WS-Attacker jar file is from the sourceforge website: https://sourceforge.net/projects/ws-attacker/files/

The second option is to build it directly from the Github sources. For this purpose, you need:
- Java 7 or 8
- maven
- git

You procede as follows. You first need to clone WS-Attacker sources (you can of course also download a ZIP file):

```bash
$ git clone https://github.com/RUB-NDS/WS-Attacker.git 
```

Then you go to the WS-Attacker directory and use maven to build and package the files:

```bash
$ cd WS-Attacker
$ mvn clean package -DskipTests
```

Afterwards, you are able to go to the runnable directory and execute WS-Attacker:

```bash
$ cd runnable
$ java -jar WS-Attacker-1.9-SNAPSHOT.jar
```


## WS-Attacker Usage

You can find the latest documentation on XML Signature Wrapping and DoS attacks here:
https://sourceforge.net/projects/ws-attacker/files/WS-Attacker%201.3/Documentation-v1.3.pdf/download

The documentation on XML Encryption attacks is currently under development, but you can find a lot of information on the XML Encryption plugin and on starting XML Encryption attacks here:
https://web-in-security.blogspot.de/2015/05/how-to-attack-xml-encryption-in-ibm.html

If you want to practice the attacks and you do not have any Web Service, we encourage you to use the Apache Rampart framework. This framework provides several Web Services examples and is vulnerable to the most of the provided attacks, including XML Signature Wrapping and the attacks on XML Encryption. 

See this blog post on how to use WS-Attacker to attack Apache Rampart Web Services with XML Signatures: https://web-in-security.blogspot.de/2015/04/introduction-to-ws-attacker-xml.html 
Similar concepts apply to the attacks with XML Encryption.

*Happy Web Service hacking*
