to package app into a dmg, in top folder of appFirewall project use:

source dmgbuild_venv/bin/activate
pip3 install dmgbuild
dmgbuild -s dmgbuild_settings.py "appFirewall" appFirewall.dmg
mv appFirewall.dmg latest\ release/