### Pingsweep via Windows CLI 
- Scan local /24 networks (credits [0xB455](http://ha.cker.info/author/skr))

`for /L %i in <1,1,255) do@ping -w -n 123.123.123.%i | find "Reply" `
