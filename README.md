# Ephemeral2 - HackMyVM (Medium)

![Ephemeral2.png](Ephemeral2.png)

## Übersicht

*   **VM:** Ephemeral2
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Ephemeral2)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 7. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/Ephemeral2_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, die virtuelle Maschine "Ephemeral2" auf der Plattform HackMyVM zu kompromittieren und sowohl die User- als auch die Root-Flag zu erlangen. Der Lösungsweg umfasste die Enumeration von SMB-Diensten, einen Brute-Force-Angriff auf einen gefundenen SMB-Benutzer, die Ausnutzung einer unsicheren Samba-"Magic Script"-Konfiguration für den initialen Zugriff, eine Rechteausweitung auf einen anderen Benutzer durch das Schreiben in ein systemweites Login-Skript-Verzeichnis (`/etc/profile.d`) und schließlich die Erlangung von Root-Rechten durch die Ausnutzung einer unsicheren `sudo`-Regel, die das Ausführen eines Python-Skripts erlaubte, mit dem beliebige Dateien gelesen werden konnten.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `enum4linux`
*   `msfconsole (smb_login)`
*   `mount.cifs`
*   `vi`
*   `nc (netcat)`
*   `chmod`
*   `mv`
*   `cp`
*   `python3`
*   `wget`
*   `python3 -m http.server`
*   `cat`
*   `ls`
*   `sudo`
*   `john`
*   Standard Linux-Befehle (`ls`, `cat`, `find`, etc.)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Ephemeral2" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   IP-Findung mittels `arp-scan` (192.168.2.123).
    *   Umfassender Portscan mit `nmap` identifizierte offene Ports: 22 (SSH), 80 (HTTP - Apache Standardseite), 139 (SMB), 445 (SMB - Samba smbd 4.6.2). NetBIOS-Name: `EPHEMERAL`.

2.  **SMB Enumeration & Brute Force:**
    *   `enum4linux` wurde verwendet, um den SMB-Benutzer `randy` und den Share `SYSADMIN` zu identifizieren.
    *   Ein Brute-Force-Angriff mit `msfconsole (smb_login)` und der `rockyou.txt`-Wortliste auf den Benutzer `randy` war erfolgreich und lieferte das Passwort `pogiako`.

3.  **Initial Access (SMB Magic Script RCE):**
    *   Der `SYSADMIN`-Share wurde mit den Credentials von `randy` gemountet. Die Samba-Konfiguration enthielt die Option `magic script = smbscript.elf`.
    *   Ein Bash-Reverse-Shell-Skript wurde erstellt, ausführbar gemacht und als `smbscript.elf` in den Share hochgeladen.
    *   Durch erneuten Zugriff auf den Share wurde das Magic Script ausgelöst, was zu einer Shell als Benutzer `randy` führte.

4.  **Privilege Escalation (von `randy` zu `ralph`):**
    *   Es wurde festgestellt, dass das Verzeichnis `/etc/profile.d` für den Benutzer `randy` beschreibbar war.
    *   Ein weiteres Reverse-Shell-Skript wurde erstellt und als `shell.sh` in `/etc/profile.d/` platziert und ausführbar gemacht.
    *   Beim nächsten Login eines anderen Benutzers (`ralph`) wurde dieses Skript ausgeführt und eine Shell als `ralph` erlangt. Die User-Flag wurde im Home-Verzeichnis von `ralph` gefunden.

5.  **Privilege Escalation (von `ralph` zu root):**
    *   Die `sudo -l`-Ausgabe für `ralph` zeigte, dass das Skript `/usr/bin/python3 /home/ralph/getfile.py` als `root` ohne Passwort (`NOPASSWD`) ausgeführt werden durfte.
    *   Das Python-Skript `getfile.py` erlaubte das Auslesen einer beliebigen Datei und deren Versand an eine angegebene IP-Adresse.
    *   Zuerst wurde `/etc/shadow` ausgelesen und ein Versuch unternommen, den Root-Hash mit `john` zu knacken (erfolglos in kurzer Zeit).
    *   Anschließend wurde das Skript genutzt, um den privaten SSH-Schlüssel von Root (`/root/.ssh/id_rsa`) zu extrahieren.
    *   Schließlich wurde das Skript direkt verwendet, um die Root-Flag (`/root/root.txt`) auszulesen.

## Wichtige Schwachstellen und Konzepte

*   **Samba "magic script" RCE:** Die `magic script`-Option in der Samba-Konfiguration erlaubt die Ausführung eines serverseitigen Skripts, wenn ein Client versucht, eine Datei mit einem bestimmten Namen im Share zu öffnen. Dies wurde für Remote Code Execution ausgenutzt.
*   **Unsichere Dateiberechtigungen (`/etc/profile.d`):** Das Verzeichnis `/etc/profile.d` enthielt Skripte, die bei jedem Benutzerlogin ausgeführt werden. Da `randy` Schreibrechte auf dieses Verzeichnis hatte, konnte er ein bösartiges Skript platzieren, das beim nächsten Login eines anderen Benutzers (hier `ralph`) ausgeführt wurde.
*   **Unsichere `sudo`-Konfiguration (NOPASSWD + Dateilese-Skript):** Dem Benutzer `ralph` wurde erlaubt, ein Python-Skript (`getfile.py`) als `root` ohne Passwort auszuführen. Dieses Skript hatte die Fähigkeit, beliebige Dateien vom System zu lesen und an einen externen Host zu senden, was den Zugriff auf sensible Dateien wie `/etc/shadow`, `/root/.ssh/id_rsa` und `/root/root.txt` ermöglichte.
*   **SMB Enumeration & Brute-Force:** Systematische Aufzählung von SMB-Benutzern und Shares, gefolgt von einem erfolgreichen Wörterbuchangriff auf gefundene Benutzerkonten.

## Flags

*   **User Flag (`/home/ralph/user.txt`):** `0041e0826ce1e1d6da9e9371a8bb3bde`
*   **Root Flag (`/root/root.txt`):** `16c760c8c08bf9dd3363355ab77ef8da`

## Tags

`HackMyVM`, `Ephemeral2`, `Medium`, `SMB`, `MagicScript`, `Samba`, `RCE`, `ProfileD`, `SudoExploitation`, `ArbitraryFileRead`, `Linux`, `Privilege Escalation`
