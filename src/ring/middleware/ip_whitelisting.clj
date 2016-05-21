(ns ring.middleware.ip-whitelisting
  (:import [org.apache.commons.net.util SubnetUtils]
           [clojure.lang IAtom]))

;; TODO: IPv6 support? Could use http://docs.spring.io/spring-security/site/docs/3.1.x/apidocs/org/springframework/security/web/util/IpAddressMatcher.html
;; https://issues.apache.org/jira/browse/NET-405

(defn ^SubnetUtils cidr->subnet-util
  "Build a SubnetUtil from a cidr string. If there is no /<n> on the string
   then it is treated as a /32 (matches one IP address)."
  [^String cidr]
  (let [cidr (if (neg? (.indexOf cidr (int \/))) ;; If there is no slash in the cidr, treat it as a /32.
               (str cidr "/32")
               cidr)]
    (doto
      (SubnetUtils. cidr)
      (.setInclusiveHostCount true))))

(defn build-ip-set
  "Returns a set which contains every IP address that is in the range of one of the CIDRs.

  * cidrs: a sequence of cidr strings."
  [cidrs]
  (persistent!
    (reduce (fn [ip-set cidr]
              (reduce conj! ip-set (.. (cidr->subnet-util cidr) getInfo getAllAddresses)))
            (transient #{})
            cidrs)))

(defn ip-in-ip-set? [ip-set ip]
  (contains? ip-set ip))

(defn- access-denied [body]
  {:status  403
   :headers {"Content-Type" "text/html"}
   :body    body})

(defn wrap-ip-whitelisting
  "Middleware that secures routes by IP whitelist. Checks the IP address of every request
  and denies access if requester is not in the whitelist.

  IP whitelisting can provide additional security, but can be spoofed or otherwise defeated.
  It shouldn't be the only line of defense for sensitive resources.

  * cidrs: a whitelist of CIDR strings or IP addresses. If the list is inside an atom
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
