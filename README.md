# Ring-IP-Whitelisting

Ring middleware that allows you to protect routes with an IP whitelist.

## Install

Add the following dependency to your `project.clj`

```
[net.danielcompton/ring-ip-whitelisting "0.1.0"]
```

## Usage

To IP whitelist routes, wrap them with `wrap-ip-whitelisting`.


```clj
(ns my.cool-ns
  (:require [ring.middleware.ip-whitelisting :as ip]))

(def app
  (-> handler
      (ip/wrap-ip-whitelisting {:cidrs ["8.8.4.4" "210.50.2.0/30" "::1/128"})))
```

`wrap-ip-whitelisting` takes a map of configuration options

* cidrs: a whitelist of CIDR strings or IP addresses. IP addresses are treated as a CIDR for a single address (e.g. a /32 for an IPv4 address). If the list is inside an atom then the whitelist will be updated when the atom changes.
* ip-fn: function to extract the IP address. Defaults to `:remote-addr`.
* error-response: Response to return if request is not authorised
* allow-access?: An additional function that can be provided if IP whitelisting fails but more checking is needed before denying access. Takes a request argument, returns true if the request should be allowed, else false."

CIDRs shouldn't be too large. The current implementation generates every IP address in the range. This is fine for a smallish number of IP addresses in the whitelist, and keeps the implementation simple and fast. The tradeoff is memory space. Don't use this to whitelist the whole world unless you want to run out of memory very shortly afterwards.

#### :cidrs as an atom

(def ip-whitelist (atom {"8.8.4.4"})
(ip/wrap-ip-...

(swap!

#### :ip-fn

look at X-Forwarded-For headers

#### error-response

You may want to return either a customised 403 error page that matches your sites theme, or a 404 so you don't reveal that the user wasn't authorised to access a protected route. Either way, you can pass an error-response function to override the default.

#### allow-access?

Say you want to allow access from within your internal network to anyone, but outside users must be authenticated.

(ip-whitelisting)
check auth headers


## Security of IP whitelisting

While IP whitelisting increases the difficulty for an attacker, if an attacker controls a router between you and the server they can compromise you. If they can get onto the network of one of the whitelisted ranges then it is also game over. Treat IP whitelisting as an additional layer of security, not your only one.

Include links to sec.stackexchange

## Protect some of your routes with IP whitelisting

Show how you can protect just some of your routes before they are combined

Show a filterer to apply after the routes are combined - does this route match me?


## License

Copyright © 2016 Daniel Compton

This project is released under the [MIT License](http://opensource.org/licenses/MIT)
