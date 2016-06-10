(defproject net.danielcompton/ring-ip-whitelist "0.2.0"
  :description "Ring IP whitelisting middleware"
  :url "http://github.com/danielcompton/ring-ip-whitelist"
  :license {:name "MIT License"
            :url "https://opensource.org/licenses/MIT"}
  :global-vars {*warn-on-reflection* true}
  :dependencies [[org.clojure/clojure "1.8.0"]]
  :deploy-repositories [["releases" :clojars]
                        ["snapshots" :clojars]]
  :profiles {:dev {:dependencies [[criterium "0.4.4"]
                                  [ring/ring-mock "0.3.0"]]}})
