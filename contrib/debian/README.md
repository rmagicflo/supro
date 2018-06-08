
Debian
====================
This directory contains files used to package suprod/supro-qt
for Debian-based Linux systems. If you compile suprod/supro-qt yourself, there are some useful files here.

## supro: URI support ##


supro-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install supro-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your suproqt binary to `/usr/bin`
and the `../../share/pixmaps/supro128.png` to `/usr/share/pixmaps`

supro-qt.protocol (KDE)

