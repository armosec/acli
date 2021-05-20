# acli

Build:
```
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o actl .
```

Run:
```
chmod +x actl
./actl --inputFile /home/david/temp/externa-nginx.yaml
```