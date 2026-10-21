;;; lispm-security-pins.el --- Pinning the tools of MCP servers  -*- lexical-binding: t; -*-

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

;; A model learns what an MCP server's tools do from what the server
;; says of them, their names, descriptions and input schemas, which the
;; server may change at any time: from one start to the next, as a
;; package updates itself, or at once, the day it turns.  The user
;; approved a server as it described itself then.
;;
;; So the tools of a server are pinned when the user trusts them: each
;; one's name, description and schema, by its hash, kept with the text
;; itself (`lispm-security-state', :pins).  A scan compares the tools
;; every running server lists with its pins, and reports a server not
;; pinned yet, and of one pinned, each tool added, removed or changed,
;; with what changed.  Trusting the server again pins it as it now is.
;;
;; The servers are those mcp.el runs, which LispM's are, and those of
;; mcp-hub; a scan starts none.  The text of every tool's description is
;; checked by the text rules as well (lispm-security-rules.el): tool
;; poisoning hides its instructions there.

;;; Code:

(require 'seq)
(require 'subr-x)
(require 'lispm-security)
(require 'lispm-security-rules)

(defvar mcp-server-connections)
(defvar lispm-mcp-servers)
(declare-function mcp--tools "mcp" (connection))
(declare-function jsonrpc-running-p "jsonrpc" (connection))
(declare-function lispm-mcp-refresh "lispm-mcp" (&optional server))

(defun lispm-security-pins--plain (value)
  "VALUE, as mcp.el decodes JSON, in one written form: object keys sorted.
So that a schema hashes alike whatever order a server lists its keys in."
  (cond ((and (consp value) (keywordp (car value)))
         (let ((pairs (seq-partition value 2)))
           (mapcan (lambda (pair) (list (car pair) (lispm-security-pins--plain (cadr pair))))
                   (sort pairs (lambda (a b) (string< (symbol-name (car a)) (symbol-name (car b))))))))
        ((vectorp value) (vconcat (mapcar #'lispm-security-pins--plain value)))
        ((consp value) (mapcar #'lispm-security-pins--plain value))
        (t value)))

(defun lispm-security-pins-tool (tool)
  "What of TOOL, as a server lists it, is pinned.
\(NAME :hash HASH :description DESCRIPTION :schema SCHEMA), SCHEMA printed."
  (let* ((name (format "%s" (plist-get tool :name)))
         (description (or (plist-get tool :description) ""))
         (schema (lispm-security-pins--plain (plist-get tool :inputSchema))))
    (list name
          :hash (secure-hash 'sha256 (encode-coding-string
                                      (prin1-to-string (list name description schema)) 'utf-8))
          :description description
          :schema (prin1-to-string schema))))

(defun lispm-security-pins--listed (connection)
  "The tools CONNECTION's server listed last, as `lispm-security-pins-tool'
makes them, sorted by name; nil if it does not run or listed none."
  (when-let* (((ignore-errors (jsonrpc-running-p connection)))
              (tools (ignore-errors (mcp--tools connection))))
    (sort (mapcar #'lispm-security-pins-tool (append tools nil))
          (lambda (a b) (string< (car a) (car b))))))

(defun lispm-security-pins-running ()
  "The MCP servers running, with their tools: ((NAME . TOOLS) ...).
TOOLS as `lispm-security-pins-tool' makes them, from the tools the
server listed last; a server that listed none yet is left out."
  (when (and (boundp 'mcp-server-connections) (hash-table-p mcp-server-connections)
             (fboundp 'mcp--tools))
    (let (servers)
      (maphash (lambda (name connection)
                 (when-let* ((tools (lispm-security-pins--listed connection)))
                   (push (cons (format "%s" name) tools) servers)))
               mcp-server-connections)
      (sort servers (lambda (a b) (string< (car a) (car b)))))))

(defun lispm-security-pins-listed (server)
  "The tools the running MCP SERVER listed last, or nil if it does not run
or listed none; as `lispm-security-pins-running' gives them."
  (when (and (boundp 'mcp-server-connections) (hash-table-p mcp-server-connections)
             (fboundp 'mcp--tools))
    (when-let* ((connection (gethash server mcp-server-connections)))
      (lispm-security-pins--listed connection))))

(defun lispm-security-pins--item (server)
  "The :id of the item of the running SERVER."
  (if (and (boundp 'lispm-mcp-servers) (assoc server lispm-mcp-servers))
      (format "LispM/server/%s" server)
    (format "Emacs/server/%s" server)))

(defun lispm-security-pins-hash (tools)
  "The hash of a server's TOOLS, pinned together."
  (secure-hash 'sha256 (mapconcat (lambda (tool) (concat (car tool) "=" (plist-get (cdr tool) :hash)))
                                  tools "\n")))

(defun lispm-security-pin (server)
  "The pin of SERVER, as the user trusted it last, or nil."
  (cdr (assoc server (lispm-security-state :pins))))

(defun lispm-security-trust (server)
  "Trust the tools the running MCP SERVER lists now: pin them as they are.
A scan then reports any change, and agents' calls of them no longer
ask, unless they change (see lispm-security-guard.el); LispM registers
them again, those it kept back included.  Only the user does: no
agent's tool calls this."
  (interactive
   (list (completing-read "Trust the tools of the MCP server: "
                          (mapcar #'car (lispm-security-pins-running)) nil t)))
  (let ((tools (cdr (assoc server (lispm-security-pins-running)))))
    (unless tools
      (user-error "The MCP server %s is not running, or lists no tools" server))
    (lispm-security-state-put
     :pins (cons (cons server (list :hash (lispm-security-pins-hash tools) :at (current-time) :tools tools))
                 (seq-remove (lambda (pin) (equal (car pin) server)) (lispm-security-state :pins))))
    (when (fboundp 'lispm-mcp-refresh)
      (lispm-mcp-refresh server))
    (message "Security: the %d tools of %s are pinned" (length tools) server)))

(defun lispm-security--short (text)
  "TEXT, made short to be shown in a finding."
  (lispm-security-evidence (or text "")))

(defun lispm-security-pins-changes (pinned tools)
  "How TOOLS differ from PINNED: ((WHAT NAME OLD NEW) ...), WHAT being
`added', `removed' or `changed'."
  (let (changes)
    (dolist (tool tools)
      (let ((old (cdr (assoc (car tool) pinned))))
        (cond ((null old) (push (list 'added (car tool) nil (cdr tool)) changes))
              ((not (equal (plist-get old :hash) (plist-get (cdr tool) :hash)))
               (push (list 'changed (car tool) old (cdr tool)) changes)))))
    (dolist (old pinned)
      (unless (assoc (car old) tools)
        (push (list 'removed (car old) (cdr old) nil) changes)))
    (nreverse changes)))

(defun lispm-security-pins-check (_items)
  "Findings of the tools of the running MCP servers, against their pins."
  (let (findings)
    (pcase-dolist (`(,server . ,tools) (lispm-security-pins-running))
      (let ((item (lispm-security-pins--item server))
            (pin (lispm-security-pin server)))
        (cond
         ((null pin)
          (push (lispm-security-finding
                 'unpinned-tools 'low item
                 (format "Its %d tools are not pinned" (length tools))
                 :server server
                 :evidence (mapconcat #'car tools ", ")
                 :detail "Read what its tools say they do; once you trust them, trust the server (t) \
to pin them.  Security then reports any change to them; until then, each call agents make of \
them asks.")
                findings))
         ((not (equal (plist-get pin :hash) (lispm-security-pins-hash tools)))
          (pcase-dolist (`(,what ,name ,old ,new) (lispm-security-pins-changes (plist-get pin :tools) tools))
            (push (lispm-security-finding
                   (intern (format "tool-%s" what)) (if (eq what 'removed) 'low 'high) item
                   (pcase what
                     ('added (format "Lists a tool %s it did not when trusted" name))
                     ('removed (format "No longer lists its tool %s" name))
                     ('changed (format "Changed its tool %s since trusted" name)))
                   :server server
                   :evidence (pcase what
                               ('added (lispm-security--short (plist-get new :description)))
                               ('removed (lispm-security--short (plist-get old :description)))
                               ('changed
                                (if (equal (plist-get old :description) (plist-get new :description))
                                    "its input schema changed"
                                  (lispm-security--short (plist-get new :description)))))
                   :was (and old (plist-get old :description))
                   :now (and new (plist-get new :description))
                   :detail (concat
                            (format "The tools of %s are not those you trusted %s.  " server
                                    (format-time-string "on %Y-%m-%d" (plist-get pin :at)))
                            (pcase what
                              ('removed "A tool gone does no harm, but says the server is another now.")
                              (_ "A model takes a tool's description as what the tool does, so a \
description that changed changes what agents do with it: the shape of a rug pull.  Read what it says \
now; trust the server again (t) if it is right."))))
                  findings))))
        ;; What the tools' descriptions say, whether pinned or not.
        (dolist (tool tools)
          (setq findings
                (append findings
                        (mapcar (lambda (finding) (plist-put finding :server server))
                                (lispm-security-text-findings
                                 item (plist-get (cdr tool) :description) nil nil
                                 (format "tool %s" (car tool)))))))))
    findings))

(add-hook 'lispm-security-check-functions #'lispm-security-pins-check t)

(provide 'lispm-security-pins)
;;; lispm-security-pins.el ends here
