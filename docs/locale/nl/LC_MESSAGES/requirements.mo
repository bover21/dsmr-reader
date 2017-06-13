��          �   %   �      p  |   q  �   �  G   �  a   �     7     I  %   Y  "     R   �     �       C        ]  
   f  4   q     �  w   �     #     1  S   8     �  �   �  `   �  *   �  b     r   �  �   �  K  w	  �   �
  �   N  K   �  o   G     �     �  %   �  &   �  ]   &     �     �  9   �     �     �  D   �     >  �   F     �     �  ]   �  	   >    H  _   T  .   �  w   �  �   [  �   �        
             	                                                                                                      **Alternative #1**: You can also run it on any server near your smart meter, as long as it satisfies the other requirements. **Alternative #2**: The application supports receiving P1 telegrams using an API, so you can also run it on a server outside your home. (:doc:`API DOCS<api>`) **Basic Linux knowledge for deployment, debugging and troubleshooting** **Minimal 1 GB of disk space on RaspberryPi (card)** (for application installation & virtualenv). **PostgreSQL 9+** **Python 3.4+** **RaspberryPi 2 / 3 or Linux server** **Raspbian OS or Debian based OS** **Smart Meter** with support for **at least DSMR 4.x+** and a **P1 telegram port** **Smart meter P1 data cable** Cable Can be purchased online and they cost around 15 tot 20 Euro's each. Database Disk space It just really helps if you know what you are doing. Misc More disk space is required for storing all reader data captured (optional). I generally advise to use a 8+ GB SD card. OS / hardware Python Recommended and tested with, but any OS satisfying the requirements should do fine. Requirements Support for ``MySQL`` has been **deprecated** since ``DSMR-reader v1.6`` and will be discontinued completely in a later release. Please use a PostgreSQL database instead. Users already running MySQL will be supported in migrating at a later moment. Support for ``Python 3.3`` has been **discontinued** since ``DSMR-reader v1.5`` (due to Django). Tested so far with Landis+Gyr E350, Kaifa. The RaspberryPi 1 tends to be **too slow** for this project, as it requires multi core processing. The readings will take about 90+ percent of the disk space. Retention is on it's way for a future release in 2017. You can however run just the datalogger client on an old RaspberryPi, :doc:`see for the API for a howto and example scripts<api>`. Project-Id-Version: DSMR Reader 1.x
Report-Msgid-Bugs-To: 
POT-Creation-Date: 2017-06-13 21:36+0200
PO-Revision-Date: 2017-06-13 21:40+0200
Last-Translator: 
Language-Team: 
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit
Generated-By: Babel 2.3.4
Language: nl
X-Generator: Poedit 1.8.7.1
 **Alternatief #1**: Je kunt dit natuurlijk ook draaien op een server vlakbij je slimme meter, zolang de vereisten maar ondersteund worden. **Alternatief #2**: De applicatie ondersteunt het ontvangen van P1 telegrammen via een API, dus je kunt dit ook op een server buiten je huis draaien. (:doc:`API DOCS<api>`) **Basiskennis Linux voor het uitrollen en mogelijk debuggen van problemen** **Minimaal 1 GB schijfruimte vereist op RaspberryPi (SD-kaart)** (ten behoeve van de applicatie en VirtualEnv). **PostgreSQL 9+** **Python 3.4+** **RaspberryPi 2 / 3 of Linux server** **Raspbian OS of Debian-gebaseerd OS** **Slimme meter** met ondersteuning voor **ten minste DSMR 4.x+** en een **P1 telegram poort** **Slimme meter P1 data kabel** Kabel Je kunt deze online bestellen voor ongeveer 15 a 20 Euro. Database Schijfruimte Het scheelt eenmaal een hoop wanneer je weet waar je mee bezig bent. Overige Meer schijfruimte is nodig voor het opslaan van alle metingen (optioneel). Over het algemeen adviseer ik minimaal een 8 GB SD-kaart. OS / hardware Python Aanbevolen en mee getest, al zou elk OS die dezelfde vereisten ondersteunt prima moeten zijn. Vereisten Gebruik van ``MySQL`` wordt **afgeraden** sinds ``DSMR-reader v1.6`` en ondersteuning hiervoor verdwijnt helemaal in een toekomstige versie. Gebruik daarom PostgreSQL. Gebruikers die dit project al op MySQL draaien krijgen in de toekomst ondersteuning om te migreren. Ondersteuning voor ``Python 3.3`` is **vervallen** sinds ``DSMR-reader v1.5`` (vanwege Django). Tot nu toe getest met: Landis+Gyr E350, Kaifa. De RaspberryPi 1 lijkt **te traag** voor het draaien van dit project, gezien meerdere processoren vrijwel vereist zijn. De metingen nemen zo'n 90+ procent van alle schijfruimte in beslag. Er komt echter een optie voor retentie in een toekomstige release in 2017. Je kunt echter wel alleen een datalogger client draaien op een oude RaspberryPi, :doc:`zie de API -documentatie voor meer informatie en voorbeeldscripts<api>`. 