## Description
This is a BOF file/project for Havoc C2 framework, the purpose is to port a known techinque for UAC bypass, escalate to Local Administrator in Windows using COM
- Ideas and source codes are from: https://github.com/tijme/conferences/tree/master/2024-09%20OrangeCon

Then place `.o` file in the same directory as your Havoc script.

*Note: this project is still under development so sorry in advanced for my crappy code :(, it was created as a POC and does not have off-sec features* 

## Usage

To build:
```
make UACBypass
```

To run:
```
uac-lua-bypass com_exec "cmd.exe" "<args>" 
```


## Ideas for future development
- Dump LSAS using Dup Handle and `MiniWriteDump`
- Implement PPL bypass techniques to dump LSASS with `RunAsPPL=1`
- Implement evasive features and test on EDR 

## Test in Windows VM with Havoc integration
