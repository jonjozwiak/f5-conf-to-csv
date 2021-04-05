# f5-conf-to-csv
This is used to read a bigip.conf from an F5 LTM and write CSV files of its configuration. 

This script was tested on Mac and requires Python 3.9+

## Usage 

``` 
chmod 755 f5-conf-to-csv.py
./f5-conf-to-csv.py
```

These CSV files could then be imported into Excel or another spreadsheet for review

## Known Issues

Import of the iRules does not work correctly in Excel... 

