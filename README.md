# ring-ip-whitelisting

A Clojure library designed to ... well, that part is up to you.

## Usage

(wrap-ip-whitelisting routes {:whitelist <atom-or-set> :error-fn ?? :auth-fn (fn [request result]) :ip-fn <>}

Talk about memory tradeoff, don't try and put in a /1 unless you want an OOM.

## License

Copyright © 2016 Daniel Compton

This project is released under the [MIT License](http://opensource.org/licenses/MIT)
