# Ring-IP-Whitelist

Ring middleware that allows you to protect routes with an IP whitelist.

## Install

Add the following dependency to your `project.clj`

```
[net.danielcompton/ring-ip-whitelist "0.1.0"]
```

## Usage

To IP whitelist routes, wrap them with `wrap-ip-whitelist`. `wrap-ip-whitelist` support IPv4 and IPv6 IP addresses.

```clj
(ns my.cool-ns
  (:require [ring.middleware.ip-whitelist :as ip]))

(def app
  (-> handler
      (ip/wrap-ip-whitelist {:cidrs ["8.8.4.4" "210.50.2.0/30" "::1/128"})))
```

`wrap-ip-whitelist` takes a map of configuration options. Only `:cidrs` is required.

* `:cidrs`: a whitelist of CIDR strings or IP addresses. IP addresses are treated as a CIDR for a single address (e.g. a /32 for an IPv4 address). If the list is inside an atom then the whitelist will be updated when the atom changes.
* `:ip-fn`: function to extract the IP address. Defaults to `:remote-addr`.
* `:error-response`: Response to return if request is not authorised. Defaults to a 403 Not Authorized response.
* `:allow-access?`: An additional function that can be called if IP whitelisting fails but more checking is needed before denying access. The function takes a request argument, returns truthy if the request should be allowed, otherwise it will be denied."

CIDR ranges shouldn't be too large. The current implementation generates every IP address in the CIDR range. This is fine for a smallish number of IP addresses in the whitelist, and keeps the implementation simple and fast. The tradeoff is memory space. Don't use this to whitelist the whole world unless you want to run out of memory very shortly afterwards.

#### Passing `:cidrs` as an atom

```clj
(def ip-whitelist (atom {"8.8.4.4"})
(-> routes
    (ip/wrap-ip-whitelist {:cidrs ip-whitelist}))

(swap! ip-whitelist conj "100.121.5.33/30")
```

#### `:ip-fn`

In almost all cases you should use something like [ring.middleware.proxy-headers/wrap-forwarded-remote-addr](https://ring-clojure.github.io/ring-headers/ring.middleware.proxy-headers.html) to translate proxy headers into `:remote-addr` for you. If for some reason you do need to look at other headers to find the 'real' IP address of a client then you can do it here. The function you write will take a ring request and return an IP address string.

#### `:error-response`

If people fail your IP whitelist, you may want to return a customised 403 error page that matches your sites theme, or a 404 so you don't reveal that the user wasn't authorised to access a protected route. You can do this by passing an `:error-response` function to override the default.

```clj
(-> routes
    (ip/wrap-ip-whitelist {:cidrs ["127.0.0.1"]
                           :error-response (constantly
                                             {:status 404
                                              :headers {"Content-Type" "text/html"}
                                              :body "<h1>Not found</h1>"}}))
```

#### `:allow-access?`

Use `:allow-access?` if you need to do additional checking before denying someone access. For example you may want to allow access from within your internal network to anyone, but outside users have to be authenticated.

```clj
(-> routes
    (ip/wrap-ip-whitelist {:cidrs ["10.0.0.0/28"]
                           :allow-access (fn [req] (check-cookies-to-see-if-authorised req))}))
```


## Security of IP whitelisting

While IP whitelisting increases the difficulty for an attacker, if an attacker controls a router between a whitelisted IP and the server they can bypass your IP whitelisting. Also, if they can get onto the network of one of the whitelisted ranges then it is also game over. Treat IP whitelisting as an additional layer of security, not your only one. Some useful links to read more on IP whitelisting:

* [How secure is IP address filtering?](http://stackoverflow.com/questions/437146/how-secure-is-ip-address-filtering)
* [Is IP whitelist sufficient to protect a server?](http://security.stackexchange.com/questions/51587/is-ip-whitelist-sufficient-to-protect-a-server)
* [The ugly truth about IP whitelisting](https://community.akamai.com/community/cloud-security/blog/2014/11/06/the-ugly-truth-behind-the-practice-of-ip-whitelisting)
* [What security risks does IP spoofing bring?](http://security.stackexchange.com/questions/1009/what-security-risks-does-ip-spoofing-bring)


## Protect some of your routes with IP whitelisting

TODO: Show how you can protect just some of your routes before they are combined.
TODO: Where to put this in your stack of middleware.

## License

Copyright © 2016 Daniel Compton

This project is released under the [MIT License](http://opensource.org/licenses/MIT)
