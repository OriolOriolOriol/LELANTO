# LELANTO

## Introduction
Lelanto (in greece: Λήλαντος) was one of the Teen Titans . Probable god of the air, movement not discernible to the eye, and ability of the hunter to stalk the prey.

## Target
Analyzes possible vulnerabilities within an Active Directory (AD). You must run LELANTO in a computer in the domain of the AD

## Dependencies

```
python3 -m pip install colorama
python3 -m pip install tabulate

On config.py you must change IP of the server
```
Besides you can run a server on Linux where there are PowerView,PowerUp and Mimikatz file. 

## How to run?

```
python3 Lelanto.py
```

## Notes
Use RunFinger.py to verify if SMB Signing is enabled or not if you use Responder to intercept LLMNR or NBT-NS request.
```
python3 RunFinger.py -i <IP of the target>
```
