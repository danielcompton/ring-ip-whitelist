(ns ring.middleware.ip-whitelist-test
  (:require [clojure.test :refer :all]
            [ring.middleware.ip-whitelist :as ip]
            [criterium.core :as bench]
            [ring.mock.request :as mock]))

;; Utils

(defn success? [req]
  (= 200 (:status req)))

;; Test internals

(deftest cidr-range-test
  (are [start end cidr] (= [start end] (ip/cidr-range cidr))
    1 1 "0.0.0.1/32"
    0 63 "0.0.0.1/26"
    0 63 "0.0.0.1/26"
    0 63 "0.0.0.62/26"
    2130706432 2130706433 "127.0.0.1/31"
    256 256 "0.0.1.0/32"
    1 1 "::1/128"
    0 0 "::0/128"
    0 79228162514264337593543950335 "::1/32"
    256 256 "::ffff:0.0.1.0/128"
    ))

(deftest normalise-cidr-test
  (are [expected given] (= expected (ip/normalise-cidr given))
    "::1/128" "::1"
    "127.0.0.1/32" "127.0.0.1"
    "210.11.25.12/24" "210.11.25.12/24"
    "2001:0db8:85a3:0000:0000:8a2e:0370:7334/120" "2001:0db8:85a3:0000:0000:8a2e:0370:7334/120"))

(def whitelist ["201.202.161.33" "62.99.73.200/30" "177.10.156.0/21" "32.62.57.106/25"
                "::ffff:0.0.1.0/128" "2001:0db8:85a3:0000:0000:8a2e:0370:7334/120" "::2/127"])

(deftest in-whitelist-test
  (let [cidrs whitelist
        ip-set (ip/build-ip-set cidrs)]
    (are [in? ip] (= in? (ip/ip-in-ip-set? ip-set ip))
      true "201.202.161.33"
      false "201.202.161.34"
      true "62.99.73.200"
      true "62.99.73.202"
      true "62.99.73.203"
      false "62.99.73.204"
      true "177.10.156.0"
      true "177.10.159.255"
      false "177.10.160.0"
      false "0.0.0.0"
      false "255.255.255.255"
      false "::0"
      false "::1"
      true "::2"
      true "::3"
      true "0.0.1.0"
      true "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
      true "2001:0db8:85a3:0000:0000:8a2e:0370:7385"
      )))


;; Test middleware

(def response {:status 200, :headers {} :body "Hi!"})

(deftest ip-whitelisting-test
  (let [handler (ip/wrap-ip-whitelist
                  (constantly response)
                  {:cidrs whitelist})]
    (are [success ip] (= (-> (mock/request :get "/")
                             (assoc :remote-addr ip)
                             (handler)
                             (success?))
                         success)
      true "201.202.161.33"
      false "201.202.161.34"
      true "62.99.73.200"
      true "62.99.73.202"
      true "62.99.73.203"
      false "62.99.73.204"
      true "177.10.156.0"
      true "177.10.159.255"
      false "177.10.160.0"
      false "0.0.0.0"
      false "255.255.255.255"
      false "::0"
      false "::1"
      true "::2"
      true "::3"
      true "0.0.1.0"
      true "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
      true "2001:0db8:85a3:0000:0000:8a2e:0370:7385"
      )
    (is (= "<h1>Not authorized</h1>"
           (-> (mock/request :get "/")
               (assoc :remote-addr "0.0.0.0")
               (handler)
               :body)))))

(deftest ip-fn-test
  (let [handler (ip/wrap-ip-whitelist
                  (constantly response)
                  {:cidrs whitelist
                   :ip-fn :x-forwarded-for})]
    (are [success req] (= (-> req
                              (handler)
                              (success?))
                          success)
      true (assoc (mock/request :get "/")
             :x-forwarded-for "201.202.161.33")
      true (assoc (mock/request :get "/")
             :x-forwarded-for "201.202.161.33"
             :remote-addr "1.1.1.1")
      false (assoc (mock/request :get "/")
              :x-forwarded-for "2.2.2.2"
              :remote-addr "201.202.161.33")
      false (assoc (mock/request :get "/")
              :remote-addr "201.202.161.33"))))

(deftest error-response-test
  (let [handler (ip/wrap-ip-whitelist
                  (constantly response)
                  {:cidrs          whitelist
                   :error-response (constantly {:status 404 :headers {} :body "Not found"})})]
    (is (= 404 (-> (mock/request :post "/secret")
                   (assoc :remote-addr "8.8.4.4")
                   (handler)
                   :status)))
    (is (= 200 (-> (mock/request :post "/secret")
                   (assoc :remote-addr "177.10.156.0")
                   (handler)
                   :status)))))

(deftest allow-access?-test
  (let [handler (ip/wrap-ip-whitelist
                  (constantly response)
                  {:cidrs         whitelist
                   :allow-access? (fn [request]
                                    (= (:query-string request) "password=knockknock"))})]
    (is (= 200 (-> (mock/request :get "/admin?password=knockknock")
                   (assoc :remote-addr "8.8.4.4")
                   (handler)
                   :status)))
    (is (= 403 (-> (mock/request :get "/admin")
                   (assoc :remote-addr "8.8.4.4")
                   (handler)
                   :status)))))

(deftest cidr-validation
  (is (thrown? AssertionError
               (ip/wrap-ip-whitelist
                 (constantly response)
                 {})))
  (is (thrown? AssertionError
               (ip/wrap-ip-whitelist
                 (constantly response)
                 {:cidrs "100.200.100.200"}))))

(deftest updating-cidr-atom-test
  (let [cidr-list (atom [])
        handler (ip/wrap-ip-whitelist
                  (constantly response)
                  {:cidrs         cidr-list})]
    (is (= 403 (-> (mock/request :get "/admin")
                   (assoc :remote-addr "8.8.4.4")
                   (handler)
                   :status)))
    (swap! cidr-list conj "8.8.4.4")
    (is (= 200 (-> (mock/request :get "/admin")
                   (assoc :remote-addr "8.8.4.4")
                   (handler)
                   :status)))
    (reset! cidr-list [])
    (is (= 403 (-> (mock/request :get "/admin")
                   (assoc :remote-addr "8.8.4.4")
                   (handler)
                   :status)))))

;; Benchmarks

;(defn benchmark []
;  (let [cidrs ["201.202.161.33" "62.99.73.200/30" "177.10.156.0/21" "32.62.57.106/25"]
;        ip-set (ip/build-ip-set cidrs)]
;    (bench/bench (ip/ip-in-ip-set? ip-set "177.10.160.0"))))
;;; 53 ns
;
;;; This is an alternate implementation where we loop over each subnet and check if the IP is in it.
;;; Roughly 20x slower. Trades off smaller space for slower execution.
;;; Not needed at the moment, may be useful in the future.
;
;(defn build-ip-subnet-set [cidrs]
;  (into #{} (map ip/cidr->subnet-util) cidrs))
;
;(defn in-subnet-whitelist [subnet-set ^String ip]
;  (reduce (fn [in-whitelist? ^SubnetUtils subnet]
;            (if (.isInRange (.getInfo subnet) ip)
;              (reduced true)
;              false))
;          false
;          subnet-set))
;
;(defn benchmark-2 []
;  (let [cidrs ["201.202.161.33" "62.99.73.200/30" "177.10.156.0/21" "32.62.57.106/25"]
;        ip-set (build-ip-subnet-set cidrs)]
;    (bench/bench (in-subnet-whitelist ip-set "177.10.160.0"))))
;;; 1100 ns
