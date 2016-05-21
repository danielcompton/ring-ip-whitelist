(defproject net.danielcompton/ring-ip-whitelisting "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :global-vars {*warn-on-reflection* true}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [commons-net/commons-net "3.5"]]
  :profiles {:dev {:dependencies [[criterium "0.4.4"]
                                  [ring/ring-mock "0.3.0"]]}})
