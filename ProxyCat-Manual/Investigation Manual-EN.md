[Back to README](../README-EN.md)

Q: Abnormal proxy addresses appear and the proxy cannot be used

![Abnormal proxy address built from the API error line](./Investigation%20Manual.assets/1.png)

A: Check whether the API endpoint returns proxies in a correct format: it must return one proxy address per line (the supported form is `protocol://user:password@host:port`; with the protocol omitted, `http` is assumed, and only http / https / socks5 are supported; lines with an invalid format are skipped). If the endpoint returns an error message instead (for example, `error000x-13` as the first line), it is treated as a configuration error and never assembled into a proxy address for use — troubleshoot on the endpoint side (whether the local machine's IP needs to be whitelisted there, for example).

Q: Why is my IP still unchanged after running ProxyCat?

A: ProxyCat is not a system-wide proxy: you need to point your proxy settings at the local listening port (1080 by default, shared by HTTP and SOCKS5) and make sure the proxy server is usable — then troubleshoot your own network step by step.

Q: Why do port scans and similar tasks fail to go through the proxy?

A: The listening port accepts both HTTP and SOCKS5 and forwards only connections in which the client speaks one of those two proxy protocols; tasks such as port scanning send raw packets directly and never perform a proxy handshake, so they cannot be forwarded by this tool.

Q: Why can't I find the problem I hit in this troubleshooting manual?

A: This manual grows as problems come up — entries are added when they are encountered. You can contact the author (send ¥50 with your question; if no solution to the problem can be found via Baidu or GPT, it is refunded in full).

Q: An error message such as `- ERROR - XXXXXXXXXXX` appears

A: Copy the error text and search it on Baidu.
