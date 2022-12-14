# Evidence_BOF

Cobalt Strike Beacon Object File (BOF) that leverages Native APIs to get evidence for a machine in the Locked Shields exercise. The evidence consisted of three parts: 
Current time
Computername and domain name
Current user and integrity
Contents of a specific file

## Compile

```
git clone https://github.com/carlnykvist/Evidence_BOF
cd Evidence_BOF
make
```

## Usage

Modify the date/time and the filenames in the cna file. Load the provided aggressor script and run the command:

```
evidence
```

![](/images/runningBof.png)

You can also run it by right clicking on a beacon and choosing "Gather evidence".

### Credits / References
##### Cobalt Strike - Beacon Object Files
+ https://www.cobaltstrike.com/help-beacon-object-files
##### BOF Code References
###### trustedsec/CS-Situational-Awareness-BOF
+ https://github.com/trustedsec/CS-Situational-Awareness-BOF
