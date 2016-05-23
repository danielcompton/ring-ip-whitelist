(ns ring.middleware.ip-whitelisting
  (:refer-clojure :exclude [biginteger])
  (:require [clojure.string :as str])
  (:import [clojure.lang IAtom]
           [java.net InetAddress]
           [java.nio ByteBuffer]))

(defn ^BigInteger inet->value
  [^InetAddress inet-address]
  (let [buffer (ByteBuffer/wrap (.getAddress inet-address))]
    (BigInteger. 1 (.array buffer))))

(defn ip-value
  "Returns the value of an IP (v4 or v6) address string"
  [ip-address]
  (inet->value (InetAddress/getByName ip-address)))

(defn normalise-cidr [^String cidr-or-ip]
  (let [])
  (if (str/index-of cidr-or-ip "/") ;; If there is no slash in the cidr, treat it as a /32.
    cidr-or-ip
    (->> (.. (InetAddress/getByName cidr-or-ip) getAddress)
         count ;; count number of bytes in address
         (* 8) ;; * 8 to get address size
         (str cidr-or-ip "/")))) ;; append address size to IP address to only match the single IP address

(defn cidr-range
  "Takes a cidr string and returns the start and end IP value in the range."
  [^String cidr]
  ;; Logic partially based on https://github.com/edazdarevic/CIDRUtils/blob/master/CIDRUtils.java
  (let [index (.indexOf cidr "/")
        _ (assert (pos? index) "CIDR must include /<n>")
        [address network] (str/split cidr #"/" 2)
        inet-address (InetAddress/getByName address)
        prefix-length (Integer/parseInt network)
        address-length (count (.getAddress inet-address)) ;; 4 (IPv4) or 16 (IPv6)
        address-mask (.. (BigInteger. 1 (byte-array address-length (repeat address-length -1))) ;; Fill array with all bits set to 1
                         not
                         (shiftRight prefix-length))
        ip-val (inet->value inet-address)
        start-val (.and ip-val address-mask)
        end-val (.add start-val (.not address-mask))]
    [start-val end-val]))

(defn build-ip-set
  "Returns a set which contains every IP address that is in the range of one of the CIDRs.

  * cidrs: a sequence of cidr strings or IP addresses."
  [cidrs]
  (into #{}
        (comp (map normalise-cidr)
              (map cidr-range)
              (mapcat (fn [[start end]]
                        (range start (inc end)))))
        cidrs))

(defn ip-in-ip-set? [ip-set ip]
  (contains? ip-set (ip-value ip)))

(defn- access-denied [body]
  {:status  403
   :headers {"Content-Type" "text/html"}
   :body    body})

(defn wrap-ip-whitelisting
  "Middleware that secures routes by IP whitelist. Checks the IP address of every request
  and denies access if requester is not in the whitelist.

  IP whitelisting can provide additional security, but can be spoofed or otherwise defeated.
  It shouldn't be the only line of defense for sensitive resources.

  * cidrs: a whitelist of CIDR strings or IP addresses. IP addresses are treated as a CIDR for
    the single address (e.g. a /32 for an IPv4 address). If the list is inside an atom
    then the whitelist will be updated when the atom changes.
  * ip-fn: function to extract the IP address.
  * error-response: Response to return if request is not authorised
  * allow-access?: An additional function that can be provided if IP whitelisting fails but
    more checking is needed before denying access. Takes a request argument, returns true if
    the request should be allowed, else false."
  [handler {:keys [cidrs ip-fn error-response allow-access?]
            :as   options
            :or   {ip-fn          :remote-addr
                   error-response #(access-denied "<h1>Not authorized</h1>")
                   allow-access?  (constantly false)}}]
  (let [cidrs-atom? (instance? IAtom cidrs)
        dereffed-cidrs (if cidrs-atom? @cidrs cidrs)
        _ (assert (sequential? dereffed-cidrs) "cidrs must be a sequential collection")
        _ (assert (every? string? dereffed-cidrs) "every element in cidrs must be a string")
        ip-whitelist (atom (build-ip-set dereffed-cidrs))]
    (when cidrs-atom?
      (add-watch cidrs :watcher (fn [_ _ _ new-state]
                                  (reset! ip-whitelist (build-ip-set new-state)))))
    (fn [request]
      (if (or (ip-in-ip-set? @ip-whitelist (ip-fn request))
              (allow-access? request))
        (handler request)
        (error-response)))))
