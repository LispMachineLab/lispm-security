;;; lispm-security-osv.el --- Looking packages up in OSV  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Ryan.K

;; This file is not part of GNU Emacs.

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU Affero General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Affero General Public License for more details.

;; You should have received a copy of the GNU Affero General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; OSV (https://osv.dev) is the open database of vulnerabilities of open
;; source packages.  It gathers GitHub's advisories, PyPI's, Go's and
;; RustSec's, and OpenSSF's malicious packages, which are most of npm's
;; entries in it: a package known to steal is listed there as one, under
;; an id that starts with MAL-.
;;
;; The packages MCP servers run, those npx and uvx start them as and what
;; they bring along, at the versions installed, are looked up all at
;; once (POST /v1/querybatch), and the details of each vulnerability
;; found, which OSV answers by id (GET /v1/vulns/ID), are fetched once
;; and again only when OSV changed them.  What OSV answered is kept in
;; osv.eld (`lispm-security-directory'), so that scans, which never use
;; the network, report it.
;;
;; Looking up tells osv.dev the names and versions of the packages, so it
;; happens only when the user asks for it, l in Security's window, and,
;; as `lispm-security-look-up' says, after they agreed.  OSV's data is
;; under the licenses of its sources, CC-BY-4.0 for most; each finding
;; links to its entry on osv.dev.

;;; Code:

(require 'seq)
(require 'subr-x)
(require 'url)
(require 'url-http)
(require 'lispm-security)

(defvar url-http-end-of-headers)
(defvar url-http-response-status)

(defcustom lispm-security-look-up 'ask
  "Whether Security may look packages up in OSV, telling osv.dev their names.
`ask' asks each time the user looks up; t looks up without asking; nil
never looks up."
  :group 'lispm-security
  :type '(choice (const :tag "Ask each time" ask) (const :tag "Without asking" t)
                 (const :tag "Never" nil)))

(defcustom lispm-security-osv-url "https://api.osv.dev"
  "Where OSV's API answers."
  :group 'lispm-security
  :type 'string)

(defcustom lispm-security-osv-stale-days 7
  "Days after which a look-up is old enough for a scan to say so."
  :group 'lispm-security
  :type 'integer)

(defvar lispm-security-osv-request-function #'lispm-security-osv--request
  "Function making a request of OSV: (METHOD PATH BODY CALLBACK).
BODY is the JSON to send, as alists, or nil; CALLBACK is called with
the JSON answered, as alists and vectors, and nil, or with nil and a
string saying what failed.")

(defvar lispm-security--osv nil
  "What OSV answered, once read: a plist, see `lispm-security-osv'.")

(defun lispm-security-osv ()
  "What OSV answered last: a plist of :at, when; :packages, ((PURL . IDS) ...),
the ids of the vulnerabilities of each package looked up; and :vulns,
\((ID . DETAILS) ...)."
  (or lispm-security--osv
      (setq lispm-security--osv (or (lispm-security-read-data (lispm-security-file "osv.eld"))
                                    (list :at nil :packages nil :vulns nil)))))

(defun lispm-security-osv--save (data)
  "Keep DATA as what OSV answered."
  (setq lispm-security--osv data)
  (lispm-security-write-data (lispm-security-file "osv.eld") data))

;;;; Requests

(defun lispm-security-osv--request (method path body callback)
  "Make the request METHOD PATH of OSV, with the JSON BODY; see
`lispm-security-osv-request-function' for CALLBACK."
  (let ((url-request-method method)
        (url-request-extra-headers (and body '(("Content-Type" . "application/json"))))
        (url-request-data (and body (encode-coding-string (json-serialize body) 'utf-8))))
    (condition-case err
        (url-retrieve
         (concat lispm-security-osv-url path)
         (lambda (status)
           (let ((buffer (current-buffer)))
             (unwind-protect
                 (if-let* ((problem (plist-get status :error)))
                     (funcall callback nil (format "%s" (cdr-safe problem)))
                   (condition-case err
                       (progn
                         (goto-char (or url-http-end-of-headers (point-min)))
                         (if (and (numberp url-http-response-status) (>= url-http-response-status 400))
                             (funcall callback nil (format "OSV answered %d" url-http-response-status))
                           (funcall callback (json-parse-buffer :object-type 'alist :array-type 'array
                                                                :null-object nil :false-object :false)
                                    nil)))
                     (error (funcall callback nil (error-message-string err)))))
               (kill-buffer buffer))))
         nil t t)
      (error (funcall callback nil (error-message-string err))))))

(defun lispm-security-osv--call (method path body callback)
  "Make the request METHOD PATH with BODY of OSV, CALLBACK as for
`lispm-security-osv-request-function'."
  (funcall lispm-security-osv-request-function method path body callback))

;;;; Looking up

(defun lispm-security-osv-packages (&optional items)
  "The packages of ITEMS, by default the last scan's, to look up: those
whose version is known, once each.  A list of packages, see
`lispm-security-package'."
  (seq-uniq
   (seq-filter (lambda (package)
                 (and (plist-get package :version)
                      (member (plist-get package :ecosystem) '("npm" "PyPI"))))
               (mapcan (lambda (item) (copy-sequence (plist-get (plist-get item :runs) :packages)))
                       (or items lispm-security-items)))
   (lambda (a b) (equal (plist-get a :purl) (plist-get b :purl)))))

(defun lispm-security-look-up-allowed-p ()
  "Non-nil if the user let Security look up without asking."
  (eq lispm-security-look-up t))

(defun lispm-security-look-up (&optional done)
  "Look the packages MCP servers run up in OSV, then scan again.
Their names and versions go to osv.dev, after the user agreed, as
`lispm-security-look-up' says.  DONE, if non-nil, is called with a
message saying what came of it and nil, or nil and why nothing did."
  (interactive)
  (let* ((done (or done (lambda (text &optional problem) (message "Security: %s" (or text problem)))))
         (_ (unless lispm-security-items (lispm-security-scan)))
         (packages (lispm-security-osv-packages)))
    (cond
     ((null lispm-security-look-up)
      (funcall done nil "looking up is turned off: see `lispm-security-look-up'"))
     ((null packages)
      (funcall done nil "no package to look up: no server runs one at a version known"))
     ((and (eq lispm-security-look-up 'ask)
           (not (y-or-n-p (format "Look %d packages up in OSV?  Their names and versions go to osv.dev. "
                                  (length packages)))))
      (funcall done nil "not looked up"))
     (t
      (lispm-security-osv--query
       packages
       (lambda (problem)
         (if problem
             (funcall done nil (format "OSV could not be reached: %s" problem))
           (lispm-security-scan)
           (let ((found (seq-filter (lambda (finding) (eq (plist-get finding :rule) 'vulnerable))
                                    lispm-security-findings)))
             (funcall done (format "%d packages looked up in OSV: %s" (length packages)
                                   (if found
                                       (format "%d known vulnerabilities or malicious packages" (length found))
                                     "none known vulnerable"))
                      nil)))))))))

(defun lispm-security-osv--query (packages done)
  "Look PACKAGES up in OSV, keep what it answers, then call DONE with nil,
or with a string saying what failed."
  (lispm-security-osv--call
   "POST" "/v1/querybatch"
   `((queries . ,(vconcat (mapcar (lambda (package) `((package . ((purl . ,(plist-get package :purl))))))
                                  packages))))
   (lambda (json problem)
     (if problem
         (funcall done problem)
       (let* ((results (append (alist-get 'results json) nil))
              (found (seq-mapn (lambda (package result)
                                 (cons (plist-get package :purl)
                                       (mapcar (lambda (vuln) (cons (alist-get 'id vuln) (alist-get 'modified vuln)))
                                               (append (alist-get 'vulns result) nil))))
                               packages results))
              (known (plist-get (lispm-security-osv) :vulns))
              (wanted (seq-uniq
                       (seq-keep (pcase-lambda (`(,id . ,modified))
                                   (let ((old (cdr (assoc id known))))
                                     (and (not (equal (plist-get old :modified) modified)) id)))
                                 (apply #'append (mapcar #'cdr found))))))
         (lispm-security-osv--details
          wanted known
          (lambda (vulns problem)
            (if problem
                (funcall done problem)
              (let ((data (lispm-security-osv)))
                (lispm-security-osv--save
                 (list :at (current-time)
                       :packages (append (mapcar (lambda (entry) (cons (car entry) (mapcar #'car (cdr entry))))
                                                 found)
                                         (seq-remove (lambda (entry) (assoc (car entry) found))
                                                     (plist-get data :packages)))
                       :vulns vulns))
                (funcall done nil))))))))))

(defun lispm-security-osv--details (ids known done)
  "Fetch the details of the vulnerabilities IDS, one after the other.
KNOWN are those fetched before; DONE gets them all, ((ID . DETAILS) ...),
and nil, or nil and what failed."
  (if (null ids)
      (funcall done known nil)
    (lispm-security-osv--call
     "GET" (concat "/v1/vulns/" (url-hexify-string (car ids))) nil
     (lambda (json problem)
       (if problem
           (funcall done nil problem)
         (lispm-security-osv--details
          (cdr ids)
          (cons (cons (car ids) (lispm-security-osv--summary json))
                (seq-remove (lambda (entry) (equal (car entry) (car ids))) known))
          done))))))

(defun lispm-security-osv--summary (vuln)
  "What a finding needs of VULN, as OSV describes one."
  (list :modified (alist-get 'modified vuln)
        :summary (or (alist-get 'summary vuln)
                     (car (split-string (or (alist-get 'details vuln) "") "\n")))
        :aliases (append (alist-get 'aliases vuln) nil)
        :severity (alist-get 'severity (alist-get 'database_specific vuln))
        :cvss (seq-some (lambda (entry) (alist-get 'score entry)) (alist-get 'severity vuln))
        :fixed (seq-uniq
                (seq-keep (lambda (event) (alist-get 'fixed event))
                          (mapcan (lambda (affected)
                                    (mapcan (lambda (range) (append (alist-get 'events range) nil))
                                            (append (alist-get 'ranges affected) nil)))
                                  (append (alist-get 'affected vuln) nil))))))

;;;; Findings

(defun lispm-security-osv-severity (id details)
  "The severity of a finding of the vulnerability ID, of DETAILS."
  (if (string-prefix-p "MAL-" id)
      'critical
    (pcase (upcase (or (plist-get details :severity) ""))
      ("CRITICAL" 'critical) ("HIGH" 'high) ((or "MODERATE" "MEDIUM") 'medium) ("LOW" 'low)
      (_ 'medium))))

(defun lispm-security-osv-check (items)
  "Findings of what OSV answered last, for the packages of ITEMS."
  (let* ((data (lispm-security-osv))
         (looked-up (plist-get data :packages))
         (vulns (plist-get data :vulns))
         (packages (lispm-security-osv-packages items))
         findings)
    (dolist (item items)
      (dolist (package (plist-get (plist-get item :runs) :packages))
        (dolist (id (cdr (assoc (plist-get package :purl) looked-up)))
          (let* ((details (cdr (assoc id vulns)))
                 (malicious (string-prefix-p "MAL-" id))
                 (name (format "%s@%s" (plist-get package :name) (plist-get package :version))))
            (push (lispm-security-finding
                   'vulnerable (lispm-security-osv-severity id details) item
                   (if malicious
                       (format "Runs %s, a malicious package" name)
                     (format "Runs %s: %s" name (or (plist-get details :summary) id)))
                   :file (plist-get item :file)
                   :evidence (string-join (cons id (plist-get details :aliases)) ", ")
                   :osv id
                   :detail (concat
                            (if (plist-get package :direct)
                                (format "The server is started as %s.  " (plist-get package :name))
                              (format "%s comes with the server, which depends on it.  " (plist-get package :name)))
                            (if malicious
                                "OSV lists this version as malicious: it was published to do harm.  Stop \
the server, remove it from npx's or uv's cache, and change the secrets it could reach."
                              (concat (or (plist-get details :summary) "")
                                      (if-let* ((fixed (plist-get details :fixed)))
                                          (format "  Fixed in %s." (string-join fixed ", "))
                                        "  No fixed version is known.")))
                            (format "  https://osv.dev/vulnerability/%s" id)))
                  findings)))))
    (cond ((and packages (null (plist-get data :at)))
           (push (lispm-security-finding
                  'not-looked-up 'info "security"
                  (format "%d packages servers run are not looked up in OSV" (length packages))
                  :detail "Look them up (l) to learn of known vulnerabilities and malicious packages.  \
Their names and versions go to osv.dev.")
                 findings))
          ((and packages
                (> (/ (float-time (time-subtract nil (plist-get data :at))) 86400)
                   lispm-security-osv-stale-days))
           (push (lispm-security-finding
                  'looked-up-long-ago 'info "security"
                  (format "Packages last looked up in OSV %s" (format-time-string "%Y-%m-%d" (plist-get data :at)))
                  :detail "OSV learns of vulnerabilities every day; look up again (l).")
                 findings))
          ((seq-some (lambda (package) (not (assoc (plist-get package :purl) looked-up))) packages)
           (push (lispm-security-finding
                  'not-looked-up 'info "security"
                  (format "%d packages are not looked up in OSV since they were installed"
                          (seq-count (lambda (package) (not (assoc (plist-get package :purl) looked-up)))
                                     packages))
                  :detail "Look them up (l).")
                 findings)))
    findings))

(add-hook 'lispm-security-check-functions #'lispm-security-osv-check t)

(provide 'lispm-security-osv)
;;; lispm-security-osv.el ends here
