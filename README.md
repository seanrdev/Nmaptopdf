## Usage

```bash
python3 main.py -pdfname sample-name -p22 127.0.0.1
```
Will scan port 22 on localhost and return a pdf file with results.

Ports can be entered just as any typical nmap scan except the all port arg as such: "-p-"

Examples
```bash
python3 main.py -pdfname sample-name -p22,80,443 127.0.0.1
```

```bash
python3 main.py -pdfname sample-name -p22-8080 127.0.0.1
```
