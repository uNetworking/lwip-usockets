# lwip-usockets

### Listening

Disable Linux TCP processing on port 4000 like so:

`sudo iptables -A INPUT -p tcp --destination-port 4000 -j DROP`
