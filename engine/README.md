# legacyray-engine

The optional protocol engine is [shoes](https://github.com/cfal/shoes) at
rev `f485914`, built for armv7 iOS and shipped as `/usr/lib/legacyray-engine`
(`make package LR_ENGINE=<path to the binary>`). Without it the daemon runs
its built-in core.

`patches/` holds what LegacyRay needs on top of that rev. Apply them in
order before building:

    git -C shoes checkout f485914
    git -C shoes am ../engine/patches/*.patch

- `0001` adds a Hysteria2 client (TCP; salamander obfuscation; pinned or
  verified certificates). The daemon hands hysteria2 profiles to the engine
  when it is installed.
- `0002` adds Xray's newer XHTTP request shaping: packet-up data in headers
  or cookies, the upload method, where the session id, the sequence number
  and the padding go. Servers behind fronts that refuse request bodies
  answer anything else with 413 or 400.
- `0003` puts the headers Xray adds to every XHTTP request on ours: a
  desktop Chrome fetch (User-Agent, Sec-CH-UA, Sec-Fetch-*, Accept and the
  rest) unless the profile names its own user agent. Without them the
  requests carried no user agent at all.
