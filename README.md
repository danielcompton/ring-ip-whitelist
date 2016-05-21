# Ring-IP-Whitelisting

Ring middleware that allows you to protect routes with an IP whitelist.

## Install

Add the following dependency to your `project.clj`

```
[net.danielcompton/ring-ip-whitelisting "0.1.0"]
```

## Usage


```clj
(ns my.cool-ns
  (:require [ring.middleware.ip-whitelisting :as ip]))

(def app
  (-> handler
      (ip/wrap-ip-whitelisting {:cidrs ["8.8.4.4" "210.50.2.0/30"})))
```

Show examples and explanations of all the parameters


Talk about memory tradeoff, don't try and put in a /1 unless you want an OOM.
Talk about safety of IP whitelisting

Show how you can protect just some of your routes


## License

Copyright © 2016 Daniel Compton

This project is released under the [MIT License](http://opensource.org/licenses/MIT)
